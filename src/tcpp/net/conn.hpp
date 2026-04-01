//
// Created by klewy on 3/18/26.
//

#ifndef TCPP_TCP_CONN_HPP
#define TCPP_TCP_CONN_HPP


#include "../../netparser/netparser.hpp"
#include <arpa/inet.h>
#include "../tun.hpp"
#include "spdlog/common.h"
#include "../util.hpp"
#include <unordered_map>
#include <array>
#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <netdb.h>
#include <sys/types.h>
#include <span>
#include <unordered_set>
#include "common.hpp"
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>
#include <random>

using Buffer = std::vector<std::byte>;

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
    std::optional<std::int64_t> send_at_; // Time at which oldest UNACKed segment was sent.
    std::uint32_t send_seq_at_; // Seq n at which send_at_ segmetn was sent

    std::uint32_t rtt_ms{};
    std::uint32_t srtt{}; // Smothed round-trip time
    std::uint32_t rttvar{}; // round-trip time variation
    std::uint32_t rto_ms{1000}; // Default RTO is 1 (1000ms) second, as per RFC 6298
};

struct Timer
{
    enum class TimerState : std::uint8_t
    {
        RETRANSMISSION,
        ZWP,
        SWS_OVERRIDE
    };
    std::optional<std::int64_t> timer_start{};
    std::uint32_t timer_start_seq_at{};
    std::uint32_t timer_data_length{};
    std::int64_t timer_expire_at{-1};

    TimerState state{TimerState::RETRANSMISSION};

    bool is_armed(const TimerState tstate) const
    {
        return timer_start.has_value() && state == tstate;
    }
};

class Tcp;

class TcpConnection
{
public:
    TcpConnection() = default;
    // Helpers
    std::condition_variable &get_connect_var() { return conn_var_; }
    std::condition_variable &get_recv_var() { return recv_var_; }
    std::condition_variable &get_send_var() { return send_var_; }
    bool is_recv_empty() const { return recv_buf_.empty(); }
    bool is_finished() const { return is_finished_; }
    TcpState get_state() const { return state_; }

    // "Userspace" kinda functions -------------------------------------
    void shutdown(ShutdownType sht);
    void close();
    ssize_t read(void *buf, const std::size_t buf_size);
    ssize_t write(const void *buf, const std::size_t buf_size);

    std::size_t send_buf_free_space() const { return std::numeric_limits<std::uint16_t>::max() - send_buf_.size(); }
private:
    void append_send_data(const std::span<const std::byte> data);
    void append_recv_data(const std::span<const std::byte> data);
    void erase_send_data(const std::size_t bytes_n);
    void erase_recv_data(const std::size_t bytes_n);

    [[nodiscard]] bool validate_seq_n(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload) const;

    // lile false if it should return
    bool handle_rst(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);
    bool handle_syn(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);
    bool handle_ack(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);
    bool handle_urg(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload) { return true; }
    bool handle_seg_text(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);
    bool handle_fin(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);

    void update_recv_window();
    void update_send_window(Tun& tun, const std::uint32_t old_wnd_size);

    bool handle_segment_syn_sent(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);
    bool handle_segment_other(Tun& tun, const netparser::TcpHeaderView& tcph, std::span<const std::byte> payload);
    void on_packet(Tun &tun,
        const netparser::IpHeaderView &iph,
        const netparser::TcpHeaderView &tcph,
        std::span<const std::byte> payload);


    bool handle_send(Tun &tun);
    bool handle_close(Tun &tun);

    // Check timers, all sorts of events and issue SENDs
    // TODO: Piggybacked ACKs should be here
    // Method is used for SENDs and TIMEOUTs and all other kinds of events except SEGMENT ARRIVES
    void on_tick(Tun &tun);

    /// @param seqn_from first sequence number to send
    /// @param max_size how many bytes of payload it is allowed to send at most.
    ssize_t send(Tun &tun, const std::uint32_t seqn_from, [[maybe_unused]] const std::size_t max_size);

    // Conn. establishment functions
    void accept(Tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph);
    void connect(Tun &tun,
        const std::uint32_t saddr,
        const std::uint16_t sport,
        const std::uint32_t daddr,
        const std::uint16_t dport);

    void start_measure_rtt(const std::uint32_t seq_n);
    void stop_measure_rtt();
    void measure_rtt(const std::uint32_t ack_n);
    void reset_rtt();

    void start_timer(const std::uint32_t seq_n, const std::uint32_t data_len, const std::uint32_t rto_ms, const Timer::TimerState start_state);
    void stop_timer();
    void handle_timer_retransmit(Tun& tun);

    void update_timer(Tun& tun, const std::uint32_t ack_n);

    void set_send_wnd(const std::uint32_t wnd);

    friend class Tcp;
    std::condition_variable recv_var_;// Notified when something is received
    std::condition_variable conn_var_;// Notified when 3 way handshake is done (both active and passive)
    std::condition_variable send_var_; // Notified when there is free space in send_buffer

    // Not tcp protocol things
    // So I don't need to recreate ip header or tcp header each write
    netparser::IpHeader iph_;
    netparser::TcpHeader tcph_;

    // Tcp protocol stuff
    SendSequence send_;
    std::uint32_t send_wnd_max_;
    Buffer send_buf_;
    ReceiveSequence recv_;
    Buffer recv_buf_;// First element is SND.UNA, last is SND.UNA + SND.WND
    TcpState state_;
    // My MSS (what this host can send)
    std::uint16_t send_mss_{ 536 };
    // Their MSS (what that host can send
    std::uint16_t recv_mss_{ 1440 };
    // Buffers and stuff
    bool should_send_fin_{ false };// TODO: Get rid of this. This should be sent after all data in buffers is sent
    bool is_finished_{ false };

    // Timer things (all in MS) ----
    RttMeasurement rtt_measurement_;

    // Retransmit. things (IN MS) -----
    Timer timer_;
    bool retransmit_fin_test_{false};
    bool retransmit_syn_test_{false};
    // retransmissions -----

    // Zeor window timer
    // bool is_zwp{false};
    // bool is_sws_override{false};
};


#endif //TCPP_TCP_CONN_HPP
