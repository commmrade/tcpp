//
// Created by klewy on 3/11/26.
//

#ifndef TCPP_TCP_HPP
#define TCPP_TCP_HPP

#include "../netparser/netparser.hpp"
#include <arpa/inet.h>
#include "tun.hpp"
#include "spdlog/common.h"
#include "util.hpp"
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
#include <bits/this_thread_sleep.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>
#include <random>


enum class TcpState// NOLINT
{
    // Passive open
    CLOSED,
    LISTEN,
    SYN_RCVD,
    ESTAB,

    // Passive close
    CLOSE_WAIT,
    LAST_ACK,

    // Active open
    SYN_SENT,

    // Active close
    FIN_WAIT_1,
    FIN_WAIT_2,

    CLOSING,
    TIME_WAIT,
};

struct Quad
{
    std::uint32_t src_addr;
    std::uint16_t src_port;

    std::uint32_t dst_addr;
    std::uint16_t dst_port;

    bool operator==(const Quad &quad) const
    {
        return src_addr == quad.src_addr && src_port == quad.src_port && dst_addr == quad.dst_addr && dst_port == quad.
               dst_port;
    }
};

template<> struct std::hash<Quad>
{
    std::size_t operator()(const Quad &quad) const noexcept
    {
        std::size_t hash;
        hash_combine(hash, quad.src_addr);
        hash_combine(hash, quad.src_port);
        hash_combine(hash, quad.dst_addr);
        hash_combine(hash, quad.dst_port);
        return hash;
    };
};

struct SendSequence
{
    std::uint32_t una;// send unack'ed
    std::uint32_t nxt;// send next
    std::uint16_t wnd;// send window size
    std::uint16_t up;// urgent pointer
    std::uint32_t wl1;// segment sequence number used for last window update
    std::uint32_t wl2;// segment acknowledgment number used for last window update
    std::uint32_t iss;// initial sequence number
};

struct ReceiveSequence
{
    std::uint32_t nxt;// next to receive, which is +1 byte. so this equals to the next seqn that is expected
    std::uint16_t wnd;// receiver window size
    std::uint16_t up;// urgent pointer
    std::uint32_t irs;// initial receiver seq n
};

struct TcpConnection
{
    // TODO: clean up user sutff
    TcpConnection() = default;
    std::condition_variable recv_var_;// Notified when something is received
    std::condition_variable conn_var_;

    // Not tcp protocol things
    // So I don't need to recreate ip header or tcp header each write
    netparser::IpHeader iph_;
    netparser::TcpHeader tcph_;

    // Tcp protocol stuff
    SendSequence send_;
    ReceiveSequence recv_;
    TcpState state_;
    bool is_finished{ false };

    [[nodiscard]] bool validate_seq_n(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload) const
    {
        if (payload.size() == 0 && recv_.wnd == 0 && tcph.seqn() == recv_.nxt) { return true; } else if (
            payload.size() == 0 && recv_.wnd > 0 &&
            is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd)) { return true; } else if (
            payload.size() > 0 && recv_.wnd == 0) { return false; } else if (
            payload.size() > 0 && recv_.wnd > 0 && (
                is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd) || is_between_wrapped(
                    recv_.nxt - 1,
                    tcph.seqn() + payload.size() - 1,
                    recv_.nxt + recv_.wnd))) { return true; }
        return false;
    }

    // lile false if it should return
    bool handle_rst(tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
    {
        // from 3.10.7.4. Other States later TODO

        if (!is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd)) {
            // Outside the window
            return false;// Just drop the segment
        } else if (tcph.seqn() != recv_.nxt) {
            // Inside window
            tcph_.ack(true);
            write(tun, send_.nxt, 0);// Challenge ACK
            return false;
        }

        // If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT),
        // then TCP endpoints MUST reset the connection in the manner prescribed below according to the connection state
        switch (state_) {
        case TcpState::SYN_RCVD: {
            // TODO: how to handle?
            // If the connection was initiated with a passive OPEN,
            // then return this connection to the LISTEN state and return.
            // Otherwise, handle per the directions for synchronized states below.
            break;
        }
        case TcpState::ESTAB:
        case TcpState::FIN_WAIT_1:
        case TcpState::FIN_WAIT_2:
        case TcpState::CLOSE_WAIT:
            // TODO: any outstanding RECEIVEs and SEND should receive "reset" responses. All segment queues should be flushed. Users should also receive an unsolicited general "connection reset" signal
            state_ = TcpState::CLOSED;
            break;
        case TcpState::CLOSING:
        case TcpState::LAST_ACK:
        case TcpState::TIME_WAIT:
            state_ = TcpState::CLOSED;
            break;
        default:
            break;
        }
        return true;
    }

    bool handle_syn(tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
    {
        switch (state_) {
        case TcpState::SYN_SENT: {
            assert(payload.empty()); // No support for payload here

            bool is_ack_acceptable = false;
            if (tcph.ack()) {
                std::println("{} {}. {} {}", tcph.ackn() - 1, send_.iss, tcph.ackn(), send_.nxt);
                if (wrapping_lt(tcph.ackn() - 1, send_.iss) || tcph.ackn() > send_.nxt) {
                    tcph_.syn(false); // it was probably true because of connect()
                    tcph_.rst(true);
                    std::println("SENDING RST");
                    write(tun, tcph.ackn(), 0);
                    return false; // return from processing
                }
                if (is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
                    // ACK is acceptable
                    is_ack_acceptable = true;
                }
            }
            if (tcph.rst()) {
                // TODO: IDC about it right now
                // implementation that supports the mitigation described in RFC 5961 SHOULD first check that
                // the sequence number exactly matches RCV.NXT prior to executing the action in the next paragraph

               //If the ACK was acceptable, then signal to the user
               // "error: connection reset", drop the segment, enter CLOSED state, delete TCB, and return.
               // Otherwise (no ACK), drop the segment and return
            }

            assert((is_ack_acceptable || !tcph.ack()) && !tcph.rst()); // This step should be reached only if the ACK is ok, or there is no ACK, and the segment did not contain a RST.
            if (tcph.syn()) {
                recv_.nxt = tcph.seqn() + 1;
                recv_.irs = tcph.seqn();
                if (tcph.ack()) {
                    send_.una = tcph.ackn();
                }

                if (send_.una > send_.iss /* SYN has been ACKed */) {
                    state_ = TcpState::ESTAB;

                    tcph_.ack(true);
                    write(tun, send_.nxt, 0);

                    // 3 way handshake is done at this point
                    conn_var_.notify_all();
                } else {
                    // TODO: how to handle this in terms of *conn_var_*?
                    state_ = TcpState::SYN_RCVD; // Sim. open things

                    tcph_.ack(true);
                    tcph_.syn(true);
                    write(tun, send_.iss, 0);
                }

                send_.wnd = tcph.window();
                send_.wl1 = tcph.seqn();
                send_.wl2 = tcph.ackn();
            }

            if (!tcph.syn() && !tcph.rst()) {
                return false; // return from processing
            }
            break;
        }
        default: break;
        }
        // TODO: Challenge ACK in synchronized states <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        return true;
    }


    bool handle_ack(tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
    {
        switch (state_) {
        case TcpState::SYN_RCVD: {
            if (!is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
                std::println("ACK IS NOT VALID");
                tcph_.rst(true);
                write(tun, tcph.ackn(), 0);
            }

            state_ = TcpState::ESTAB;
            send_.wnd = tcph.window();
            send_.wl1 = tcph.seqn();
            send_.wl2 = tcph.ackn();

            // TODO: for now, lets do an active close right after switching to estab
            // THIS IS the only place in state machine where passive/active close interwine
            // Note: Uncomment for active close
            // tcph_.ack(true);
            // tcph_.fin(true);
            // write(tun, send_.nxt, 0);
            // state_ = TcpState::FIN_WAIT_1;
            // TODO: Don't forget to send all the data before sending a FIN
            break;
        }
        case TcpState::ESTAB: { break; }
        case TcpState::LAST_ACK: {
            // The only thing that can arrive in this state is an acknowledgment of our FIN
            state_ = TcpState::CLOSED;
            break;
        }
        case TcpState::FIN_WAIT_1: {
            // Probably got an ACK of our FIN. TODO: Make sure
            state_ = TcpState::FIN_WAIT_2;
            break;
        }
        default:
            break;// TODO
        }
        return true;
    }

    bool handle_urg(tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload) { return true; }

    bool handle_seg_text(tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
    {
        return true;
    }

    bool handle_fin(tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
    {
        is_finished = true;
        recv_var_.notify_all();// Notify socekts about a read, now they should check is_finished

        recv_.nxt += 1;// Advance over FIN bit
        // TODO: SEND FINACK AND SHIT
        std::println("Connection is closing");

        // TODO: Send all buffered segments
        tcph_.ack(true);
        write(tun, send_.nxt, 0);

        switch (state_) {
        case TcpState::ESTAB: {
            state_ = TcpState::CLOSE_WAIT;
            // But since I already sent a FIN and an ACK I may switch to LAST_ACK (**???**)
            // TODO: At first, i should send all data, then switch to LAST_ACK, but since no buffers yet do this.

            tcph_.fin(true);
            tcph_.ack(true);
            write(tun, send_.nxt, 0);

            state_ = TcpState::LAST_ACK;// TODO: Wait for ACK of FIN properly
            break;
        }
        case TcpState::FIN_WAIT_2: {
            // WE got a FIN from the other side, now switch to time_wait
            state_ = TcpState::TIME_WAIT;
            // TODO: start wait timer and then close
            // But for now, just close at once
            state_ = TcpState::CLOSED;
            break;
        }
        default:
            break;// TODO
        }
        return true;
    }

    void on_packet(tun &tun,
        const netparser::IpHeaderView &iph,
        const netparser::TcpHeaderView &tcph,
        std::span<const std::byte> payload)
    {
        // TODO: FIND WHERE IT SENDS RST

        std::println("on packet: {} {}", tcph.syn(), tcph.ack());
        // First, check sequence number
        if (!validate_seq_n(tcph, payload) && recv_.wnd != 0) {
            // wnd != 0 because: If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs
            // If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return):
            if (tcph.rst()) { return; }

            tcph_.ack(true);
            write(tun, send_.nxt, 0);
            return;
        }

        // False signals, that a handler wants to return (usually in drop-and-return situations)
        if (tcph.rst()) { if (!handle_rst(tun, tcph, payload)) { return; } }

        // Fourth
        if (tcph.syn()) { if (!handle_syn(tun, tcph, payload)) { return; } }// NOLINT

        // Fifth, check the ACK field
        if (!tcph.ack()) { return; }
        if (!handle_ack(tun, tcph, payload)) { return; }

        // TODO: Check URG bit
        if (tcph.urg()) { if (!handle_urg(tun, tcph, payload)) { return; } }// NOLINT

        // TODO: Process segment text
        if (!payload.empty()) { if (!handle_seg_text(tun, tcph, payload)) { return; } }// NOLINT

        // TODO: Check FIN bit
        if (tcph.fin()) { if (!handle_fin(tun, tcph, payload)) { return; } }// NOLINT
    }

    /// @param seqn_from first sequence number to send
    /// @param max_size how many bytes of payload it is allowed to send at most.
    ssize_t write(tun &tun, const std::uint32_t seqn_from, const std::size_t max_size)
    {
        std::println("DOING A WRITE");
        tcph_.seqn(seqn_from);
        tcph_.ackn(recv_.nxt);
        tcph_.calculate_checksum(iph_, {});

        std::vector<std::byte> buf{};
        buf.resize(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE);
        const auto ip_data = iph_.serialize();
        const auto tcp_data = tcph_.serialize();
        std::size_t offset = 0;
        std::memcpy(buf.data() + offset, ip_data.data(), ip_data.size());// NOLINT
        offset += ip_data.size();
        std::memcpy(buf.data() + offset, tcp_data.data(), tcp_data.size());// NOLINT
        offset += tcp_data.size();

        const auto written = tun.write(buf.data(), offset);
        if (written < 0) {
            throw std::runtime_error(std::format("Write failed: {}", std::strerror(errno)));// NOLINT
        }

        const std::size_t payload_bytes_sent = 0;// mock variable
        send_.nxt += payload_bytes_sent + (tcph_.fin() ? 1 : 0) + (tcph_.syn() ? 1 : 0);

        tcph_.syn(false);
        tcph_.ack(false);
        tcph_.fin(false);
        tcph_.rst(false);

        return written;
    }

    void accept(tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
    {
        iph_.version(iph.version());
        iph_.ihl(iph.ihl());
        iph_.total_len(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE);
        // It is just that, since IP and TCP do not support options for now.
        iph_.id(1212);
        iph_.dont_fragment(iph.dont_fragment());
        iph_.more_fragments(iph.more_fragments());
        iph_.frag_offset(iph.frag_offset());
        iph_.ttl(iph.ttl());
        iph_.protocol(iph.protocol());
        iph_.source_addr(iph.dest_addr());
        iph_.dest_addr(iph.source_addr());
        iph_.calculate_checksum();

        tcph_.source_port(tcph.dest_port());
        tcph_.dest_port(tcph.source_port());
        tcph_.data_off(5);// SIZE OF HEADER (INCLUDING OPTIONS)


        // 3.10.7.2. LISTEN STATE
        // First, check for a RST: (TODO: Make RST work)
        if (tcph.rst()) {
            // RST should be ignored at this point, since connection doesn't even exist yet. So this RST is a creepy one :/
            return;
        }

        // Second, check for an ACK:
        if (tcph.ack()) {
            // ACK shouldn't be set in initial SYN segment

            tcph_.rst(true);
            write(tun, tcph.ackn(), 0);
            return;
        }

        // Third, check for a SYN
        if (tcph.syn()) {
            recv_.nxt = tcph.seqn() + 1;
            recv_.irs = tcph.seqn();

            recv_.wnd = tcph.window();// I think this is correct? TODO: MAKE SURE
            send_.wnd = 4380;

            // SEt ISS
            // TODO: use a better mechanism, just 10 for now
            send_.iss = 10;

            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            tcph_.window(send_.wnd);
            tcph_.syn(true);
            tcph_.ack(true);
            write(tun, send_.iss, 0);

            send_.una = send_.iss;
            send_.nxt = send_.iss + 1;// 1 goes for SYN, since it uses up a SEQ number
            state_ = TcpState::SYN_RCVD;
        }
    }

    void connect(tun &tun, const std::uint32_t saddr, const std::uint16_t sport, const std::uint32_t daddr, const std::uint16_t dport)
    {
        // 1. construct ip and tcp headers
        // 2. send a create connection in **connections**.
        // 3. something esle i guess?

        std::random_device rnd;
        std::mt19937 gen(rnd());
        std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(), std::numeric_limits<std::uint32_t>::max() - 1U);

        send_.iss = dis(gen);
        send_.una = send_.iss;
        send_.nxt = send_.iss; // it is incremented in write()
        send_.wnd = 4380;

        iph_.version(4);
        iph_.ihl(5);// 5 * 4 = 20 bytes (no options)
        iph_.type_of_service(0);
        iph_.total_len(40);// 20 (IP) + 20 (TCP) — update once you know payload size
        iph_.id(0);
        iph_.dont_fragment(true);
        iph_.more_fragments(false);
        iph_.frag_offset(0);
        iph_.ttl(64);
        iph_.protocol(IPPROTO_TCP);// 6
        iph_.source_addr(saddr);// already in network byte order from inet_pton
        iph_.dest_addr(daddr);// assumed network byte order
        iph_.calculate_checksum();

        tcph_.source_port(sport);// ephemeral port, pick randomly or track in connections
        tcph_.dest_port(dport);// destination port, you'll need to pass this into connect()
        tcph_.seqn(send_.iss);
        tcph_.ackn(0);// 0 on SYN
        tcph_.data_off(5);// 5 * 4 = 20 bytes, no options
        tcph_.syn(true);
        tcph_.window(send_.wnd);// TODO: set sendewr window to this
        tcph_.urg_ptr(0);
        tcph_.calculate_checksum(iph_, {});// empty payload span for a bare SYN

        write(tun, send_.iss, 0);

        state_ = TcpState::SYN_SENT;
    }
};

struct Tcp
{
    using PortType = std::uint16_t;
    std::unordered_map<Quad, std::unique_ptr<TcpConnection>> connections;
    std::unordered_map<PortType, std::deque<Quad>> pending;

    std::condition_variable accept_var_;
    // Sockets that are ready to be accepted. When they are accepted, they are removed from this queue.

    // Accept a SYN packet
    void accept(tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
    {
        Quad quad{ iph.source_addr(), tcph.source_port(), iph.dest_addr(), tcph.dest_port() };
        auto [iter, inserted] = connections.emplace(quad, std::make_unique<TcpConnection>());
        assert(inserted);
        auto &conn = iter->second;

        conn->accept(tun, iph, tcph);
    }

    Quad connect(tun &tun, const std::uint32_t daddr, const std::uint16_t dport)
    {
        // TODO: clean it up
        std::uint32_t s_addr{};
        int ret = inet_pton(AF_INET, "10.0.0.2", &s_addr);
        assert(ret >= 0);// It can't really fail

        std::random_device rnd;
        std::mt19937 gen(rnd());
        std::uniform_int_distribution<> dist(1025, std::numeric_limits<std::uint16_t>::max());
        std::uint16_t port = static_cast<std::uint16_t>(dist(gen));
        Quad quad{ daddr, dport, s_addr, port };
        // TODO: fix QUAD things, its kinda weird that i have to reverse it

        auto [iter, inserted] = connections.emplace(quad, std::make_unique<TcpConnection>());
        assert(inserted);
        auto &conn = iter->second;

        // TODO: stooooopid, get rid of it
        pending[quad.dst_port] = {};

        conn->connect(tun, s_addr, port, daddr, dport);
        return quad;
    }

    void on_tick(tun &tun) {}

    void process_packet(tun &tun)// NOLINT
    {
        std::array<std::byte, 1500> buf{};// NOLINT

        std::array<pollfd, 1> poll_fds;
        auto &fd = poll_fds[0];
        fd.fd = tun.raw_fd();
        fd.events = POLLIN;
        int ret = poll(poll_fds.data(), poll_fds.size(), 1);
        if (ret < 0) {
            perror("poll");
            throw std::runtime_error(std::format("poll failed: {}", std::strerror(errno)));// NOLINT
            return;
        }

        on_tick(tun);

        if (ret == 0) {
            return;// Nothing to read
        }

        const ssize_t rd_bytes = tun.read(buf);
        assert(rd_bytes);

        std::println("Read something");

        const netparser::IpHeaderView iph{
            std::span<const std::byte, netparser::IPV4H_MIN_SIZE>{ buf.data(), netparser::IPV4H_MIN_SIZE } };
        if (iph.protocol() == 6) {// NOLINT
            const netparser::TcpHeaderView tcph{
                std::span<const std::byte, netparser::TCPH_MIN_SIZE>{ buf.data() + netparser::IPV4H_MIN_SIZE,
                                                                      netparser::TCPH_MIN_SIZE } };
            const Quad quad{ .src_addr = iph.source_addr(), .src_port = tcph.source_port(), .dst_addr = iph.dest_addr(),
                             .dst_port = tcph.dest_port() };

            // If we do listen to this port
            auto p_iter = pending.find(quad.dst_port);
            if (p_iter != pending.end()) {
                auto conn_iter = connections.find(quad);
                if (conn_iter != connections.end()) {
                    std::println("calling on packet");
                    const std::size_t offset = iph.ihl() * 4 + tcph.data_off() * 4;
                    const std::span<const std::byte> payload{ buf.data() + offset, rd_bytes - offset };

                    conn_iter->second->on_packet(tun, iph, tcph, payload);
                    if (conn_iter->second->state_ == TcpState::CLOSED) {
                        std::println("Delete TCB");
                        connections.erase(conn_iter);// TODO: this may cause problems when waiting on a cond var
                    }
                } else {
                    std::println("accepting");
                    // Add this new connection to the list of pending connections, then notify userspace
                    p_iter->second.push_back(quad);
                    accept(tun, iph, tcph);

                    accept_var_.notify_all();
                }
            } else {
                std::println("Port isn't bound, sending RST...");
                // TODO: send rst
            }
        }
    }
};

#endif //TCPP_TCP_HPP