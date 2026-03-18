//
// Created by klewy on 3/18/26.
//

#include "conn.hpp"

bool TcpConnection::validate_seq_n(const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload) const
{
    if (payload.size() == 0 && recv_.wnd == 0 && tcph.seqn() == recv_.nxt) { return true; } else if (
        payload.size() == 0 && recv_.wnd > 0 &&
        is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd)) { return true; } else if (
        payload.size() > 0 && recv_.wnd == 0) { return false; } else if (
        payload.size() > 0 && recv_.wnd > 0 && (
            is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd) || is_between_wrapped(
                recv_.nxt - 1,
                static_cast<std::uint32_t>(tcph.seqn() + payload.size() - 1),
                recv_.nxt + recv_.wnd))) { return true; }
    return false;
}

bool TcpConnection::handle_rst(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
{
    // from 3.10.7.4. Other States later TODO

    if (!is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd)) {
        // Outside the window
        return false;// Just drop the segment
    } else if (tcph.seqn() != recv_.nxt) {
        // Inside window
        tcph_.ack(true);
        send(tun, send_.nxt, 0);// Challenge ACK
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

bool TcpConnection::handle_syn(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
{
    // TODO: Challenge ACK in synchronized states <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
    return true;
}

bool TcpConnection::handle_ack(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
{
    switch (state_) {
    case TcpState::SYN_RCVD: {
        if (!is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
            std::println("ACK IS NOT VALID");
            tcph_.rst(true);
            send(tun, tcph.ackn(), 0);
        }

        conn_var_.notify_all();
        state_ = TcpState::ESTAB;
        send_.wnd = tcph.window();
        send_.wl1 = tcph.seqn();
        send_.wl2 = tcph.ackn();
        break;
    }
    case TcpState::ESTAB: {
        // TODO: HANDLE ACK FOR SYn/FIN

        if (is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
            const auto acked_bytes_n = tcph.ackn() - send_.una;
            if (!send_buf_.empty()) {
                // if empty, probably means that SYN/FIN was ACKed
                send_buf_.erase(send_buf_.begin(), send_buf_.begin() + acked_bytes_n);
            }
            send_.una = tcph.ackn();
        } else if (wrapping_lt(tcph.ackn(), send_.una + 1)) {
            // duplicate ACK
            // Ignore
        } else if (wrapping_gt(tcph.ackn(), send_.nxt)) {
            tcph_.ack(true);
            send(tun, send_.nxt, 0);
            return false;// Drop the segment and return
        }

        if (is_between_wrapped(send_.una - 1, tcph.ackn(), send_.nxt + 1)) {
            // Update window
            if (wrapping_lt(send_.wl1, tcph.seqn()) || (send_.wl1 == tcph.seqn() && wrapping_lt(send_.wl2,
                                                            tcph.ackn() + 1))) {
                send_.wnd = tcph.window();
                send_.wl1 = tcph.seqn();
                send_.wl2 = tcph.ackn();
            }
        }
        break;
    }
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
    case TcpState::FIN_WAIT_2: {
        // User close can be ACKed now
        break;
    }
    default:
        break;// TODO
    }
    return true;
}

bool TcpConnection::handle_seg_text(Tun &tun,
    const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    switch (state_) {
    case TcpState::ESTAB:
    case TcpState::FIN_WAIT_1:
    case TcpState::FIN_WAIT_2: {
        // A TCP implementation MAY send an ACK segment acknowledging RCV.NXT
        // when a valid segment arrives that is in the window but not at the left window edge
        if (tcph.seqn() != recv_.nxt) {
            tcph_.ack(true);
            send(tun, send_.nxt, 0);
            return true;
        }

        recv_buf_.append_range(payload);// append new data
        recv_.nxt += payload.size() + (tcph.syn() ? 1 : 0) + (tcph.fin() ? 1 : 0);
        recv_.wnd = recv_mss_;//TODO: CALC PROEPRLY
        // Make sure RCV.WND right edge doesn't shift left
        tcph_.window(static_cast<std::uint16_t>(recv_.wnd));
        tcph_.ack(true);
        send(tun, send_.nxt, 0);// TODO: piggyback this

        recv_var_.notify_all();
        break;
    }
    case TcpState::CLOSE_WAIT:
    case TcpState::CLOSING:
    case TcpState::LAST_ACK:
    case TcpState::TIME_WAIT: {
        // This should not occur, just ignore the segment text
        break;
    }
    default:
        assert(0 && "This should not happen");
    }
    return true;
}

bool TcpConnection::handle_fin(Tun &tun, const netparser::TcpHeaderView &tcph, std::span<const std::byte> payload)
{
    is_finished_ = true;

    recv_var_.notify_all();// Notify socekts about a read, now they should check is_finished
    recv_.nxt += 1;// Advance over FIN bit

    tcph_.ack(true);
    send(tun, send_.nxt, 0);

    switch (state_) {
    case TcpState::ESTAB: {
        state_ = TcpState::CLOSE_WAIT;
        // But since I already sent a FIN and an ACK I may switch to LAST_ACK (**???**)
        // TODO: At first, i should send all data, then switch to LAST_ACK, but since no buffers yet do this.

        tcph_.fin(true);
        tcph_.ack(true);
        send(tun, send_.nxt, 0);

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

bool TcpConnection::handle_syn_sent(Tun &tun,
    const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    assert(payload.empty());// No support for payload here

    bool is_ack_acceptable = false;
    if (tcph.ack()) {
        std::println("{} {}. {} {}", tcph.ackn() - 1, send_.iss, tcph.ackn(), send_.nxt);
        if (wrapping_lt(tcph.ackn() - 1, send_.iss) || tcph.ackn() > send_.nxt) {
            tcph_.syn(false);// it was probably true because of connect()
            tcph_.rst(true);
            std::println("SENDING RST");
            send(tun, tcph.ackn(), 0);
            return false;// return from processing
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

    assert((is_ack_acceptable || !tcph.ack()) && !tcph.rst());
    // This step should be reached only if the ACK is ok, or there is no ACK, and the segment did not contain a RST.
    if (tcph.syn()) {
        recv_.nxt = tcph.seqn() + 1;
        recv_.irs = tcph.seqn();
        if (tcph.ack()) { send_.una = tcph.ackn(); }

        if (send_.una > send_.iss /* SYN has been ACKed */) {
            state_ = TcpState::ESTAB;

            tcph_.ack(true);
            send(tun, send_.nxt, 0);

            // 3 way handshake is done at this point
            conn_var_.notify_all();
        } else {
            // TODO: how to handle this in terms of *conn_var_*?
            state_ = TcpState::SYN_RCVD;// Sim. open things

            tcph_.ack(true);
            tcph_.syn(true);
            send(tun, send_.iss, 0);
        }

        send_.wnd = tcph.window();
        send_.wl1 = tcph.seqn();
        send_.wl2 = tcph.ackn();
    }

    if (!tcph.syn() && !tcph.rst()) {
        return false;// return from processing
    }
    return true;
}

void TcpConnection::on_packet(Tun &tun,
    const netparser::IpHeaderView &iph,
    const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    switch (state_) {
    case TcpState::SYN_SENT: {
        if (!handle_syn_sent(tun, tcph, payload)) { return; }
        break;
    }
    default: {
        // First, check sequence number
        if (!validate_seq_n(tcph, payload) && recv_.wnd != 0) {
            // wnd != 0 because: If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs
            // If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return):
            if (tcph.rst()) { return; }

            tcph_.ack(true);
            send(tun, send_.nxt, 0);
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

        if (!payload.empty()) { if (!handle_seg_text(tun, tcph, payload)) { return; } }// NOLINT

        // TODO: Check FIN bit
        if (tcph.fin()) { if (!handle_fin(tun, tcph, payload)) { return; } }// NOLINT

        break;
    }
    }
}

bool TcpConnection::handle_send(Tun &tun)
{
    // TODO: cong. control things. basically calculate how many bytes to send
    if (!send_buf_.empty()) {
        const auto in_flight_n = send_.nxt - send_.una;
        const auto bytes_to_send = std::min(static_cast<std::size_t>(send_mss_), send_buf_.size() - in_flight_n);
        if (bytes_to_send) {
            tcph_.ack(true);
            send(tun, send_.nxt, bytes_to_send);
            // TODO: We can piggyback FIN on last segment of data
        }
    }
    return true;
}

bool TcpConnection::handle_close(Tun &tun)
{
    // TODO: If piggybacking FIN wasn't possible, just send a raw FIN here
    if (should_send_fin_ && send_buf_.empty()) {
        tcph_.fin(true);
        tcph_.ack(true);
        send(tun, send_.nxt, 0);

        // TODO: make sure it is retransmitted
        state_ = TcpState::FIN_WAIT_1;
        should_send_fin_ = false;
    }
    return true;
}

void TcpConnection::on_tick(Tun &tun)
{
    if (!handle_send(tun)) { return; }

    // do_close is second, because if we are done sending in SEND (buffers are empty), we can try to issue a FIN
    if (!handle_close(tun)) { return; }
}

ssize_t TcpConnection::send(Tun &tun, const std::uint32_t seqn_from, const std::size_t max_size)
{
    const std::span<const std::byte> payload{ send_buf_.data(), max_size };

    iph_.total_len(static_cast<std::uint16_t>(iph_.ihl() * 4 + tcph_.data_off() * 4 + payload.size()));
    iph_.calculate_checksum();

    tcph_.seqn(seqn_from);
    tcph_.ackn(recv_.nxt);
    tcph_.calculate_checksum(iph_, payload);

    const auto ip_data = iph_.serialize();
    const auto tcp_data = tcph_.serialize();

    std::vector<std::byte> buf{};
    buf.resize(iph_.ihl() * 4 + tcph_.data_off() * 4 + payload.size());

    std::size_t offset = 0;
    std::memcpy(buf.data() + offset, ip_data.data(), ip_data.size());// NOLINT
    offset += ip_data.size();
    std::memcpy(buf.data() + offset, tcp_data.data(), tcp_data.size());// NOLINT
    offset += tcp_data.size();
    if (!payload.empty()) {
        std::memcpy(buf.data() + offset, payload.data(), payload.size());
        offset += payload.size();
    }

    const auto written = tun.write(buf.data(), offset);
    if (written < 0) {
        throw std::runtime_error(std::format("Write failed: {}", std::strerror(errno)));// NOLINT
    }
    assert(static_cast<std::size_t>(written) == offset);
    // i think it should be ok, if fails, then i have to rewrite "snd.nxt +" logic

    send_.nxt += payload.size() + (tcph_.fin() ? 1 : 0) + (tcph_.syn() ? 1 : 0);

    tcph_.syn(false);
    tcph_.ack(false);
    tcph_.fin(false);
    tcph_.rst(false);

    return written;
}

void TcpConnection::accept(Tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
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
        send(tun, tcph.ackn(), 0);
        return;
    }

    // Third, check for a SYN
    if (tcph.syn()) {
        recv_.nxt = tcph.seqn() + 1;
        recv_.irs = tcph.seqn();

        recv_.wnd = tcph.window();// I think this is correct? TODO: MAKE SURE
        send_.wnd = send_mss_;

        // SEt ISS
        // TODO: use a better mechanism, just 10 for now
        std::random_device rnd;
        std::mt19937 gen(rnd());
        std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(),
            std::numeric_limits<std::uint32_t>::max());
        auto iss = dis(gen);
        // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        tcph_.window(static_cast<std::uint16_t>(send_.wnd));
        tcph_.syn(true);
        tcph_.ack(true);
        send(tun, iss, 0);

        send_.iss = iss;
        send_.una = send_.iss;
        send_.nxt = send_.iss + 1;// 1 goes for SYN, since it uses up a SEQ number
        state_ = TcpState::SYN_RCVD;
    }
}

void TcpConnection::connect(Tun &tun,
    const std::uint32_t saddr,
    const std::uint16_t sport,
    const std::uint32_t daddr,
    const std::uint16_t dport)
{
    std::random_device rnd;
    std::mt19937 gen(rnd());
    std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(),
        std::numeric_limits<std::uint32_t>::max());

    const auto iss = dis(gen);
    const auto init_window = send_mss_;

    iph_.version(4);
    iph_.ihl(5);// 5 * 4 = 20 bytes (no options)
    iph_.type_of_service(0);
    iph_.total_len(40);// 20 (IP) + 20 (TCP)
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
    tcph_.seqn(iss);
    tcph_.ackn(0);// 0 on SYN
    tcph_.data_off(5);// 5 * 4 = 20 bytes, no options
    tcph_.syn(true);
    tcph_.window(init_window);
    tcph_.urg_ptr(0);
    tcph_.calculate_checksum(iph_, {});// empty payload span for a bare SYN

    send(tun, iss, 0);

    send_.iss = iss;
    send_.una = send_.iss;
    send_.nxt = send_.iss + 1;
    send_.wnd = init_window;

    state_ = TcpState::SYN_SENT;
}

void TcpConnection::shutdown(ShutdownType sht)
{
    // TODO: It should buffer FIN at the end of send buffer
    if (sht == ShutdownType::WRITE) { should_send_fin_ = true; } else {
        throw std::runtime_error("This shutdown type is not impl");
    }
}

void TcpConnection::close()
{
    // TODO: it should buffer FIN
    should_send_fin_ = true;
}

ssize_t TcpConnection::read(void *buf, const std::size_t buf_size)
{
    // If user hasn't read everything yet, delay signaling FIN
    if (is_finished_ && !recv_buf_.empty()) { return 0; }

    const auto bytes_copy = std::min(buf_size, recv_buf_.size());
    std::memcpy(buf, recv_buf_.data(), bytes_copy);
    recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + bytes_copy);
    return static_cast<ssize_t>(bytes_copy);
}

ssize_t TcpConnection::write(const void *buf, const std::size_t buf_size)
{
    const auto in_flight_n = static_cast<std::int64_t>(send_.nxt) - send_.una;
    assert(in_flight_n >= 0);// Well actually TCP allows window shrinks i think but it is highly discouraged
    const auto insert_bytes_n = std::min(buf_size, static_cast<std::size_t>(send_.wnd - in_flight_n));
    // Can't have more bytes, than the window allows
    if (insert_bytes_n == 0) { throw std::runtime_error("error: insufficient resources"); }

    switch (state_) {
    case TcpState::SYN_SENT:
    case TcpState::SYN_RCVD:
    case TcpState::ESTAB:
    case TcpState::CLOSE_WAIT: {
        send_buf_.append_range(std::span<const std::byte>{ static_cast<const std::byte *>(buf), insert_bytes_n });
        break;
    }
    default:
        throw std::runtime_error("error: connection is closing");
    }

    return static_cast<ssize_t>(insert_bytes_n);
}