#include <print>
#include "../netparser/netparser.hpp"
#include <arpa/inet.h>
#include "tun.hpp"
#include "spdlog/common.h"
#include "util.hpp"
#include <unordered_map>
#include <array>
#include <cassert>
#include <cstddef>
#include <sys/types.h>
#include <span>
#include <bits/this_thread_sleep.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

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

    // Active close
    FIN_WAIT_1,
    FIN_WAIT_2,

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
    // Not tcp protocol things
    // So I don't need to recreate ip header or tcp header each write
    netparser::IpHeader iph_;
    netparser::TcpHeader tcph_;

    // Tcp protocol stuff
    SendSequence send_;
    ReceiveSequence recv_;
    TcpState state_;

    bool validate_seq_n(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload) const
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

    void on_packet(tun &tun,
        const netparser::IpHeaderView &iph,
        const netparser::TcpHeaderView &tcph,
        std::span<const std::byte> payload)
    {
        // First, check sequence number
        if (!validate_seq_n(tcph, payload) && recv_.wnd != 0) {
            // wnd != 0 because: If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs
            // If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return):
            if (tcph.rst()) { return; }
            tcph_.seqn(send_.nxt);
            tcph_.ackn(recv_.nxt);
            tcph_.ack(true);
            tcph_.calculate_checksum(iph_, {});
            write(tun, {});
            return;
        }

        if (tcph.rst()) {
            // TODO: diff handling for diff states
            // from 3.10.7.4. Other States later TODO

            if (!is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd)) {
                // Outside the window
                return;// Just drop the segment
            } else if (tcph.seqn() != recv_.nxt) {
                // Inside window
                tcph_.seqn(send_.nxt);
                tcph_.ackn(recv_.nxt);
                tcph_.ack(true);
                tcph_.calculate_checksum(iph_, {});
                write(tun, {});
                return;
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
            // IF synchronized state: then TODO:
            default:
                break;
            }
        }

        // Fourth
        if (tcph.syn()) {
            // TODO: handle
            // TODO: Challenge ACK in synchronized states <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        }

        // Fifth, check the ACK field
        if (!tcph.ack()) { return; }
        switch (state_) {
        case TcpState::SYN_RCVD: {
            if (!is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
                std::println("ACK IS NOT VALID");
                tcph_.seqn(tcph.ackn());
                tcph_.rst(true);
                tcph_.calculate_checksum(iph_, {});
                write(tun, {});
            }

            state_ = TcpState::ESTAB;
            std::println("MOVED TO ESTABILISHED");
            send_.wnd = tcph.window();
            send_.wl1 = tcph.seqn();
            send_.wl2 = tcph.ackn();



            // TODO: for now, lets do an active close right after switching to estab
            // THIS IS the only place in state machine where passive/active close interwine
            // Note: Uncomment for active close
            tcph_.fin(true);
            tcph_.rst(false);
            tcph_.ack(true);
            tcph_.syn(false);
            tcph_.seqn(send_.nxt);
            tcph_.ackn(recv_.nxt);
            tcph_.calculate_checksum(iph_, {});

            write(tun, {});
            // TODO: Don't forget to send all the data before sending a FIN.
            send_.nxt += 1; // For FIN
            state_ = TcpState::FIN_WAIT_1;
            break;
        }
        case TcpState::ESTAB: {
            break;
        }
        case TcpState::LAST_ACK: { // The only thing that can arrive in this state is an acknowledgment of our FIN
            state_ = TcpState::CLOSED;
            break;
        }
        case TcpState::FIN_WAIT_1: {
            // Probably got an ACK of our FIN. TODO: Make sure
            state_ = TcpState::FIN_WAIT_2;
            break;
        }
        default: // TODO


        }

        // TODO: Check URG bit
        if (tcph.urg()) {}

        // TODO: Process segment text
        if (!payload.empty()) {}

        // TODO: Check FIN bit
        if (tcph.fin()) {
            recv_.nxt += 1;// Advance over FIN bit
            // TODO: SEND FINACK AND SHIT
            std::println("Connection is closing");

            // TODO: Send all buffered segments

            tcph_.fin(false);
            // tcph_.fin(true);
            tcph_.ack(true);
            tcph_.rst(false);
            tcph_.syn(false);
            tcph_.seqn(send_.nxt); // 0 payload
            tcph_.ackn(recv_.nxt);
            tcph_.calculate_checksum(iph_, {});
            write(tun, {}); // Send an ACK for the FIN. and FIN.

            // send_.nxt += 1; // For the FIN, that I have sent

            switch (state_) {
            case TcpState::ESTAB: {
                state_ = TcpState::CLOSE_WAIT; // But since I already sent a FIN and an ACK I may switch to LAST_ACK (**???**)
                // TODO: At first, i should send all data, then switch to LAST_ACK, but since no buffers yet do this.

                tcph_.fin(true);
                tcph_.ack(true);
                tcph_.seqn(send_.nxt);
                tcph_.ackn(recv_.nxt);
                tcph_.calculate_checksum(iph_, {});
                write(tun, {});
                send_.nxt += 1;

                state_ = TcpState::LAST_ACK; // TODO: Wait for ACK of FIN properly
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
        }
    }

    // TODO: this is a temp write, make it right later
    ssize_t write(tun &tun, std::span<const std::byte> payload)
    {
        std::vector<std::byte> buf{};
        buf.resize(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + payload.size());
        const auto ip_data = iph_.serialize();
        const auto tcp_data = tcph_.serialize();
        std::size_t offset = 0;
        std::memcpy(buf.data() + offset, ip_data.data(), ip_data.size());
        offset += ip_data.size();
        std::memcpy(buf.data() + offset, tcp_data.data(), tcp_data.size());
        offset += tcp_data.size();

        if (!payload.empty()) {
            std::memcpy(buf.data() + offset, payload.data(), payload.size());
            offset += payload.size();
        }
        return tun.write(buf.data(), buf.size());
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
            tcph_.seqn(tcph.ackn());
            tcph_.rst(true);
            tcph_.calculate_checksum(iph_, {});
            write(tun, {});
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
            tcph_.seqn(send_.iss);
            tcph_.ackn(recv_.nxt);
            tcph_.window(send_.wnd);
            tcph_.syn(true);
            tcph_.ack(true);

            tcph_.calculate_checksum(iph_, {});
            write(tun, {});

            send_.una = send_.iss;
            send_.nxt = send_.iss + 1;// 1 goes for SYN, since it uses up a SEQ number
            state_ = TcpState::SYN_RCVD;
        }
    }
};

struct Tcp
{
    std::unordered_map<Quad, TcpConnection> connections;

    // Accept a SYN packet
    void accept(tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
    {
        Quad quad{ iph.source_addr(), tcph.source_port(), iph.dest_addr(), tcph.dest_port() };
        auto [iter, inserted] = connections.emplace(quad, TcpConnection{});
        assert(inserted);
        auto &conn = iter->second;
        conn.accept(tun, iph, tcph);
    }

    void packet_loop(tun &tun)// NOLINT
    {
        while (true) {
            std::array<std::byte, 1500> buf{};// NOLINT
            const ssize_t rd_bytes = tun.read(buf);
            assert(rd_bytes);

            const netparser::IpHeaderView iph{
                std::span<const std::byte, netparser::IPV4H_MIN_SIZE>{ buf.data(), netparser::IPV4H_MIN_SIZE } };
            if (iph.protocol() == 6) {// NOLINT
                const netparser::TcpHeaderView tcph{
                    std::span<const std::byte, netparser::TCPH_MIN_SIZE>{ buf.data() + netparser::IPV4H_MIN_SIZE,
                                                                          netparser::TCPH_MIN_SIZE } };
                const Quad quad{ iph.source_addr(), tcph.source_port(), iph.dest_addr(), tcph.dest_port() };

                auto iter = connections.find(quad);
                if (iter == connections.end()) { accept(tun, iph, tcph); } else {
                    const std::size_t offset = netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
                    // TODO: CALCULATE PROPERLY
                    std::span<const std::byte> payload{ buf.data() + offset, rd_bytes - offset };
                    iter->second.on_packet(tun, iph, tcph, payload);
                    if (iter->second.state_ == TcpState::CLOSED) {
                        std::println("DELETE TCB");
                        connections.erase(iter);
                    }
                }
            }
        }
    }
};

int main()
{
    tun tun{ "tun1" };

    tun.set_addr("10.0.0.1");
    tun.set_mask("255.255.255.0");
    tun.set_flags(IFF_UP | IFF_RUNNING);

    Tcp tcp{};
    tcp.packet_loop(tun);
    return 0;
}