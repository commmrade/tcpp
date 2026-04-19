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
#include "../timer.hpp"
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
    [[nodiscard]] ssize_t write(std::span<const std::byte> buf);

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

    bool segment_arrived_syn_sent(const netparser::TcpHeaderView &tcph);
    bool segment_arrived_other(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload);



    bool handle_send();
    bool handle_close();



    /// @param seqn_from first sequence number to send
    /// @param max_size how many bytes of payload it is allowed to send at most.
    ssize_t send(const std::uint32_t seqn_from, [[maybe_unused]] const std::size_t max_size);

    // Conn. establishment functions
    void open_passive(const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph);
    void open_active(const std::uint32_t saddr,
        const std::uint16_t sport,
        const std::uint32_t daddr,
        const std::uint16_t dport);

    void retransmit(Timer& timer);
    void update_timers();

    void set_send_wnd(const std::uint32_t wnd);
    [[nodiscard]] std::uint32_t get_recv_wnd() const { return right_wnd_edge_ - recv_.nxt; }
    void set_recv_wnd(const std::uint32_t wnd, const std::uint32_t nxt);

    void init_headers(const std::uint32_t src_addr, const std::uint32_t dst_addr,
            const std::uint16_t src_port, const std::uint16_t dst_port,
            const std::uint32_t iss) {
        iph_.version(4);
        iph_.ihl(5);
        iph_.dont_fragment(true);
        iph_.more_fragments(false);
        iph_.ttl(64);
        iph_.protocol(IPPROTO_TCP);
        iph_.source_addr(src_addr);
        iph_.dest_addr(dst_addr);

        tcph_.source_port(src_port);
        tcph_.dest_port(dst_port);
    }

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
