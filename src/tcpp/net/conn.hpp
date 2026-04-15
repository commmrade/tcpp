//
// Created by klewy on 3/18/26.
//

#ifndef TCPP_TCP_CONN_HPP
#define TCPP_TCP_CONN_HPP


#include "../../netparser/netparser.hpp"
#include <arpa/inet.h>
#include "../tun.hpp"
#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <netdb.h>
#include <sys/types.h>
#include <span>
#include "common.hpp"
#include "../clock.hpp"
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>

using Buffer = std::vector<std::byte>;

constexpr static inline std::uint32_t SENDER_DEF_MSS = 536;
constexpr static inline std::uint32_t RECEIVER_DEF_MSS = 1440;

struct SendSequence
{
    std::uint32_t una;// send unack'ed
    std::uint32_t nxt;// send next
    std::uint32_t wnd;// send window size. It is recommended to use 32 bit int for WND
    std::uint16_t up;// urgent pointer
    std::uint32_t wl1;// segment sequence number used for last window update
    std::uint32_t wl2;// segment acknowledgment number used for last window update
    std::uint32_t iss;// initial sequence number
};

struct ReceiveSequence
{
    std::uint32_t nxt;// next to receive, which is +1 byte. so this equals to the next seqn that is expected
    std::uint32_t wnd;// receiver window size. It is recommended to use 32 bit int for WND
    std::uint16_t up;// urgent pointer
    std::uint32_t irs;// initial receiver seq n
};

struct RttMeasurement
{
    constexpr static std::uint32_t DEFAULT_RTO_MS = 1000;
    constexpr static std::uint32_t MAX_RTO_MS = 60'000;
    constexpr static std::uint32_t SWS_OVERRIDE_MS = 100;// 0.1...1.0

    std::optional<std::int64_t> send_at_;// Time at which oldest UNACKed segment was sent.
    std::uint32_t send_seq_at_;// Seq n at which send_at_ segmetn was sent

    std::uint32_t rtt_ms{};
    std::uint32_t srtt{};// Smothed round-trip time
    std::uint32_t rttvar{};// round-trip time variation
    std::uint32_t rto_ms{ DEFAULT_RTO_MS };// Default RTO is 1 (1000ms) second, as per RFC 6298

    void reset()
    {
        rttvar = 0;
        srtt = 0;
    }

    void start(const std::int64_t now_ms, const std::uint32_t seq_n)
    {
        if (!send_at_.has_value()) {
            send_seq_at_ = seq_n;
            send_at_ = now_ms;
            std::println("Send at: {}", send_at_.value());
        }
    }

    void stop_measure() { send_at_.reset(); }

    void measure(const std::int64_t cur_time, const std::uint32_t ack_n)
    {
        if (send_at_.has_value() && wrapping_gt(ack_n, send_seq_at_)) {
            const std::int64_t res = cur_time - send_at_.value();// cur. rtt

            static constexpr std::uint32_t GRAN_MS = 1;
            if (rtt_ms == 0) {
                // First measurement
                srtt = static_cast<std::uint32_t>(res);
                rttvar = static_cast<std::uint32_t>(res / 2);
            } else {
                // Following measurements
                static constexpr double ALPHA = 1.0 / 8.0;
                static constexpr double BETA = 1.0 / 4.0;
                rttvar = static_cast<std::uint32_t>(
                    (1.0 - BETA) * static_cast<double>(rttvar) + BETA * std::abs(
                        static_cast<double>(srtt) - static_cast<double>(res)));
                srtt = static_cast<std::uint32_t>(
                    (1.0 - ALPHA) * static_cast<double>(srtt) + ALPHA * static_cast<double>(
                        res));
            }
            rto_ms = srtt + std::max(GRAN_MS, 4 * rttvar);
            // Whenever RTO is computed, if it is less than 1 second,
            // then the RTO SHOULD be rounded up to 1 second
            rto_ms = std::max(rto_ms, RttMeasurement::DEFAULT_RTO_MS);

            rtt_ms = static_cast<std::uint32_t>(res);

            send_at_.reset();
            std::println("RTT IS {}, SRTT IS {}, RTTVAR IS {}, RTO IS {}",
                rtt_ms,
                srtt,
                rttvar,
                rto_ms);
        }
    }
};

struct Timer
{
    virtual ~Timer() = default;

    std::optional<std::int64_t> timer_start{};
    std::uint32_t timer_start_seq_at{};
    std::uint32_t timer_data_length{};// Payload length
    std::int64_t timer_expire_at{ -1 };
    std::optional<std::uint32_t> rto_ms_;

    [[nodiscard]] bool is_armed() const { return timer_start.has_value(); }

    void start(const std::uint32_t seq_n,
     const std::uint32_t data_len,
     const std::uint32_t rto_ms,
     const std::int64_t cur_time)
    {
        if (!timer_start.has_value()) {
            timer_start.emplace(cur_time);// Start timer
            timer_expire_at = cur_time + static_cast<std::int64_t>(rto_ms);// It expires at RTO
            timer_start_seq_at = seq_n;
            timer_data_length = data_len;
            rto_ms_.emplace(rto_ms);
            std::println("Start Timer with {} ms rto", rto_ms);
        }
    }

    void stop()
    {
        timer_start.reset();
    }

    virtual void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) = 0;
};

struct RetransTimer : public Timer
{
    bool update(const std::uint32_t send_nxt, const std::uint32_t ack_n, const std::int64_t cur_time_ms, const RttMeasurement& rtt_measurement)
    {
        if (timer_start.has_value()) {
            if (ack_n >= send_nxt && is_armed()) {
                std::println("All outstanding data ACKED. Disable timer");
                // (5.2) When all outstanding data has been acknowledged, turn off the retransmission timer.
                stop();
            } else if (wrapping_gt(ack_n, timer_start_seq_at) &&
                       is_armed()) {
                // Window was moved, restart timer
                // (5.3) When an ACK is received that acknowledges new data, restart the retransmission timer so that it will expire
                // after RTO seconds (for the current value of RTO).
                std::println("Window moved. Restart the timer");

                // Restart
                stop();
                start(ack_n, timer_data_length, rtt_measurement.rto_ms, cur_time_ms);
            } else {
               // timer is neither updated nor disabled
               if (cur_time_ms >= timer_expire_at) {
                   // handle_timer_retransmit();
                   return true; // should retransmit
               }
            }
        }
        return false;
    }

    void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) override
    {
        // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        rto_ms_ = rto_ms_.value() * 2;

        // These values are likely bogus after several backoffs (3)
        constexpr std::uint32_t BACKOFF_THRESHOLD = 10000;
        rto_ms_ = std::min(rto_ms_.value(), RttMeasurement::MAX_RTO_MS);

        //  (5.6) Start the retransmission timer, such that it expires after RTO
        //  seconds
        stop();
        start(send_una, timer_data_length, rto_ms_.value(), cur_time);
    }
};

struct ZwpTimer : public Timer
{
    bool update(const std::int64_t cur_time_ms)
    {
        if (timer_start.has_value()) {
            // timer is neither updated nor disabled
            if (cur_time_ms >= timer_expire_at) {
                // handle_timer_retransmit();
                return true; // should retransmit
            }
        }
        return false;
    }

    void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time)
    {
        // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        rto_ms_ = rto_ms_.value() * 2;

        // These values are likely bogus after several backoffs (3)
        constexpr std::uint32_t BACKOFF_THRESHOLD = 10000;
        rto_ms_ = std::min(rto_ms_.value(), RttMeasurement::MAX_RTO_MS);

        //  (5.6) Start the retransmission timer, such that it expires after RTO
        //  seconds
        stop();
        start(send_una, timer_data_length, rto_ms_.value(), cur_time);
    }
};

struct SwsTimer : public Timer
{
    bool update(const std::int64_t cur_time_ms)
    {
        if (timer_start.has_value()) {
            // timer is neither updated nor disabled
            if (cur_time_ms >= timer_expire_at) {
                // handle_timer_retransmit();
                return true; // should retransmit
            }
        }
        return false;
    }

    void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time)
    {
        // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        rto_ms_ = rto_ms_.value() * 2;

        // These values are likely bogus after several backoffs (3)
        constexpr std::uint32_t BACKOFF_THRESHOLD = 10000;
        rto_ms_ = std::min(rto_ms_.value(), RttMeasurement::MAX_RTO_MS);

        //  (5.6) Start the retransmission timer, such that it expires after RTO
        //  seconds
        stop();
        // Sws timer does not exp. backoff
    }
};

class Tcp;
class TcpConnectionTest;

class TcpConnection
{
public:
    TcpConnection(IOInterface &tun, std::unique_ptr<ClockInterface> clock)
        : tun_(tun), clock_(std::move(clock)) {}

    // Helpers
    [[nodiscard]] std::condition_variable &get_connect_var() { return conn_var_; }
    [[nodiscard]] std::condition_variable &get_recv_var() { return recv_var_; }
    [[nodiscard]] std::condition_variable &get_send_var() { return send_var_; }
    [[nodiscard]] bool is_recv_empty() const { return recv_buf_.empty(); }
    [[nodiscard]] bool is_finished() const { return is_finished_; }
    [[nodiscard]] TcpState get_state() const { return state_; }

    // "Userspace" kinda functions -------------------------------------
    void shutdown(ShutdownType sht);
    void close();
    [[nodiscard]] ssize_t read(void *buf, const std::size_t buf_size);
    [[nodiscard]] ssize_t write(const void *buf, const std::size_t buf_size);

    [[nodiscard]] std::size_t send_buf_free_space() const
    {
        return std::numeric_limits<std::uint16_t>::max() - send_buf_.size();
    }

    // Check timers, all sorts of events and issue SENDs
    // TODO: Piggybacked ACKs should be here
    // Method is used for SENDs and TIMEOUTs and all other kinds of events except SEGMENT ARRIVES
    void on_tick();

    void on_packet(const netparser::TcpHeaderView &tcph,
        std::span<const std::byte> payload);
private:
    void append_send_data(const std::span<const std::byte> data);
    void append_recv_data(const std::span<const std::byte> data);
    void erase_send_data(const std::size_t bytes_n);
    void erase_recv_data(const std::size_t bytes_n);

    [[nodiscard]] bool validate_seq_n(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload) const;

    // lile false if it should return
    bool handle_rst(const netparser::TcpHeaderView &tcph);
    bool handle_syn(const netparser::TcpHeaderView &tcph);
    bool handle_ack(const netparser::TcpHeaderView &tcph);
    bool handle_seg_text(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);
    bool handle_fin();

    void update_recv_window();
    void update_send_window();

    bool handle_segment_syn_sent(const netparser::TcpHeaderView &tcph);
    bool handle_segment_other(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);



    bool handle_send();
    bool handle_close();



    /// @param seqn_from first sequence number to send
    /// @param max_size how many bytes of payload it is allowed to send at most.
    ssize_t send(const std::uint32_t seqn_from, [[maybe_unused]] const std::size_t max_size);

    // Conn. establishment functions
    void accept(const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph);
    void connect(const std::uint32_t saddr,
        const std::uint16_t sport,
        const std::uint32_t daddr,
        const std::uint16_t dport);

    void retransmit(Timer& timer);
    void update_timers();

    void set_send_wnd(const std::uint32_t wnd);
    [[nodiscard]] std::uint32_t get_recv_wnd() const { return right_wnd_edge_ - recv_.nxt; }
    void set_recv_wnd(const std::uint32_t wnd, const std::uint32_t nxt);

    friend class Tcp;
    friend class TcpConnectionTest;

    IOInterface &tun_;

    std::condition_variable recv_var_;// Notified when something is received
    std::condition_variable conn_var_;// Notified when 3 way handshake is done (both active and passive)
    std::condition_variable send_var_;// Notified when there is free space in send_buffer

    // Not tcp protocol things
    // So I don't need to recreate ip header or tcp header each write
    netparser::IpHeader iph_;
    netparser::TcpHeader tcph_;

    // Tcp protocol stuff
    SendSequence send_{};
    std::uint32_t send_wnd_max_{};
    Buffer send_buf_;

    ReceiveSequence recv_{};
    std::uint32_t right_wnd_edge_{};
    Buffer recv_buf_;// First element is SND.UNA, last is SND.UNA + SND.WND


    TcpState state_{};
    // My MSS (what this host can send)
    std::uint16_t send_mss_{ SENDER_DEF_MSS };
    // Their MSS (what that host can send
    std::uint16_t recv_mss_{ RECEIVER_DEF_MSS };
    // Buffers and stuff
    bool should_send_fin_{ false };// TODO: Get rid of this. This should be sent after all data in buffers is sent
    bool is_finished_{ false };

    // Timer things (all in MS) ----
    RttMeasurement rtt_measurement_;

    // Retransmit. things (IN MS) -----
    RetransTimer r_timer_{};
    ZwpTimer z_timer_{};
    SwsTimer s_timer_{};

    std::unique_ptr<ClockInterface> clock_;
    // retransmissions -----
};


#endif //TCPP_TCP_CONN_HPP
