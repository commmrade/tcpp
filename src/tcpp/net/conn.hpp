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
#include "cong_control.hpp"
#include "output.hpp"
#include "../clock.hpp"
#include <netinet/in.h>
#include "../timer.hpp"
#include <sys/ioctl.h>
#include <net/if.h>
#include "sequence.hpp"
#include <poll.h>

using Buffer = std::vector<std::byte>;

constexpr static inline std::uint32_t SENDER_DEF_MSS = 536;
constexpr static inline std::uint32_t RECEIVER_DEF_MSS = 1440;


class Tcp;
class TcpConnectionTest;

enum class ConnectionOption : std::uint8_t
{
    NODELAY,
    QUICKACK,
};

struct Config
{
    bool is_nodelay{ false };
    bool is_quickack{ false };
};

static inline constexpr bool is_timestamp = true;

class TcpConnection
{
public:
    TcpConnection(std::unique_ptr<OutputInterface> output, std::unique_ptr<ClockInterface> clock)
        : output_(std::move(output)), clock_(std::move(clock)) {}

    // Helpers
    [[nodiscard]] std::condition_variable &get_connect_var() { return conn_var_; }
    [[nodiscard]] std::condition_variable &get_recv_var() { return recv_var_; }
    [[nodiscard]] std::condition_variable &get_send_var() { return send_var_; }
    [[nodiscard]] bool is_recv_empty() const { return recv_buf_.empty(); }
    [[nodiscard]] bool is_finished() const { return recv_buf_.empty() ? false : recv_buf_.back().fin(); }
    [[nodiscard]] TcpState get_state() const { return state_; }
    [[nodiscard]] std::size_t send_buf_free_space() const { return send_buf_.available_space(); }

    // "Userspace" kinda functions -------------------------------------
    void shutdown(ShutdownType sht);
    void close();
    [[nodiscard]] ssize_t read(void *buf, const std::size_t buf_size);
    [[nodiscard]] ssize_t write(std::span<const std::byte> buf);

    template<typename Value> void set_option(const ConnectionOption cfg, const Value &val)
    {
        switch (cfg) {
        case ConnectionOption::NODELAY: {
            config_.is_nodelay = val;
            break;
        }
        case ConnectionOption::QUICKACK: {
            config_.is_quickack = val;
            break;
        }
        default:
            throw std::runtime_error("TcpCon: Config option not implemented");
        }
    }

    // Check timers, all sorts of events and issue SENDs
    // Method is used for SENDs and TIMEOUTs and all other kinds of events except SEGMENT ARRIVES
    void on_tick();
    void on_packet(const netparser::TcpHeaderView &tcph,
        std::span<const std::byte> payload);

private:
    // Helpers
    void add_fin_segment();
    void update_ts(const netparser::TcpHeaderView &tcph);
    bool is_sync() const;
    void fast_recovery(const netparser::TcpHeaderView &tcph, const std::size_t pl_size);
    // void append_recv_data(const std::span<const std::byte> data);
    // void erase_recv_data(const std::size_t bytes_n);

    // lile false if it should return
    bool on_rst(const netparser::TcpHeaderView &tcph);
    bool on_syn(const netparser::TcpHeaderView &tcph);
    bool on_ack(const netparser::TcpHeaderView &tcph);
    bool on_data(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);
    bool on_fin();

    bool segment_arrived_syn_sent(const netparser::TcpHeaderView &tcph);
    bool segment_arrived_other(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);

    bool handle_send();
    // bool handle_close();

    void update_recv_window();
    void update_send_window();

    /// @param seqn_from first sequence number to send
    /// @param max_size how many bytes of payload it is allowed to send at most.
    // FIXME: Why pass seqn_from??, i should pass number of segments to be sent i guess
    // ssize_t send(const std::uint32_t seqn_from, [[maybe_unused]] const std::size_t max_size);

    // Used for sending data segments
    ssize_t send_data(const std::size_t max_size_pl,
        const std::size_t segments_limit = std::numeric_limits<std::size_t>::max());
    ssize_t send_pure(TcpSegment &seg);
    ssize_t send_retransmit(TcpSegment &retrans_seg, const std::size_t max_size_pl);

    // Conn. establishment functions
    void open_passive(const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph);
    void open_active(const std::uint32_t saddr,
        const std::uint16_t sport,
        const std::uint32_t daddr,
        const std::uint16_t dport);

    std::uint32_t retransmit(Timer &timer);
    void update_timers();

    friend class Tcp;
    friend class TcpConnectionTest;

    std::unique_ptr<OutputInterface> output_;

    std::condition_variable recv_var_;// Notified when something is received
    std::condition_variable conn_var_;// Notified when 3 way handshake is done (both active and passive)
    std::condition_variable send_var_;// Notified when there is free space in send_buffer

    // Not tcp protocol things
    // So I don't need to recreate ip header or tcp header each write
    // NOTE: These are inside SegmentOutput now
    // netparser::IpHeader iph_;
    // netparser::TcpHeader tcph_;

    // Tcp protocol stuff
    SendSequence send_{};
    std::uint32_t send_wnd_max_{};
    TcpSenderBuffer send_buf_;
    // Buffer send_buf_;

    ReceiveSequence recv_{};
    std::uint32_t right_wnd_edge_{};
    // TODO: replace recv buf with TcpBuffer
    // Buffer recv_buf_;
    TcpReceiverBuffer recv_buf_;


    TcpState state_{};

    // My MSS (what this host can send)
    std::uint16_t send_mss_{ SENDER_DEF_MSS };
    // Their MSS (what that host can send
    std::uint16_t recv_mss_{ RECEIVER_DEF_MSS };
    // Buffers and stuff

    // Timer things (all in MS) ----
    RttMeasurement rtt_measurement_;

    // Retransmit. things (IN MS) -----
    RetransTimer r_timer_{};
    ZwpTimer z_timer_{};
    SwsTimer s_timer_{};
    ExpireTimer time_wait_timer_{};

    // Del. Ack
    ExpireTimer ack_timer_{};
    int fs_segs_cnt_{ 0 };

    std::unique_ptr<ClockInterface> clock_;
    // retransmissions -----

    Config config_;

    bool is_tsopt{ false };

    // Cong. control
    CongestionControl cong_;
};


#endif //TCPP_TCP_CONN_HPP