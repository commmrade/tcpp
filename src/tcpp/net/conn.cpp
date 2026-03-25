//
// Created by klewy on 3/18/26.
//

#include "conn.hpp"

void TcpConnection::append_send_data(const std::span<const std::byte> data) { send_buf_.append_range(data); }

void TcpConnection::append_recv_data(const std::span<const std::byte> data) { recv_buf_.append_range(data); }

void TcpConnection::erase_send_data(const std::size_t bytes_n)
{
    send_buf_.erase(send_buf_.begin(), send_buf_.begin() + static_cast<const std::ptrdiff_t>(bytes_n));
}

void TcpConnection::erase_recv_data(const std::size_t bytes_n)
{
    recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + static_cast<const std::ptrdiff_t>(bytes_n));
}

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
    measure_rtt(tcph.ackn());

    switch (state_) {
    case TcpState::SYN_RCVD: { // got ACK for our SYNACK
        std::println("Ack is invalid: una {} < ackn {} <= nxt {}", send_.una, tcph.ackn(), send_.nxt);
        if (!is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
            std::println("ACK IS NOT VALID. RST SET HERE");
            tcph_.rst(true);
            send(tun, tcph.ackn(), 0);
        }

        conn_var_.notify_all();
        state_ = TcpState::ESTAB;
        send_.wnd = tcph.window();
        send_.wl1 = tcph.seqn();
        send_.wl2 = tcph.ackn();

        retransmit_syn_test_ = false;
        // TODO: imagine ACK after SYNACK is lost, we might wanna fall through if this is the case, so we can process payload. or should we fall?
        break;
    }
    case TcpState::ESTAB: {
        // TODO: HANDLE ACK FOR SYn/FIN

        if (is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
            const auto acked_bytes_n = tcph.ackn() - send_.una;// This wraps fine
            if (!send_buf_.empty()) {
                assert(acked_bytes_n <= send_buf_.size());// Just in case
                // if empty, probably means that SYN/FIN was ACKed
                erase_send_data(acked_bytes_n);
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

    update_timer(tun, tcph.ackn());
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

        append_recv_data(payload);
        recv_.nxt += payload.size() + (tcph.syn() ? 1 : 0);// FIN is handled in handle_fin()
        recv_.wnd = recv_mss_ * 3;//TODO: CALC PROEPRLY
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
        should_send_fin_ = true;

        // tcph_.fin(true);
        // tcph_.ack(true);
        // send(tun, send_.nxt, 0);

        // state_ = TcpState::LAST_ACK;// TODO: Wait for ACK of FIN properly
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

bool TcpConnection::handle_segment_syn_sent(Tun &tun,
    const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    assert(payload.empty());// No support for payload here

    bool is_ack_acceptable = false;
    if (tcph.ack()) {
        std::println("{} {}. {} {}", tcph.ackn() - 1, send_.iss, tcph.ackn(), send_.nxt);
        if (wrapping_lt(tcph.ackn() - 1, send_.iss) || tcph.ackn() > send_.nxt) {
            tcph_.rst(true);
            std::println("SENDING RST IN SYN SENT");
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

        if (auto opt = tcph.mss(); opt.has_value()) { send_mss_ = opt.value().mss; }
        send_.wnd = tcph.window();
        send_.wl1 = tcph.seqn();
        send_.wl2 = tcph.ackn();

        retransmit_syn_test_ = false; // SInce this handle SYNACK of our SYN
    }

    if (!tcph.syn() && !tcph.rst()) {
        return false;// return from processing
    }
    return true;
}

bool TcpConnection::handle_segment_other(Tun &tun,
    const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    // First, check sequence number
    if (!validate_seq_n(tcph, payload) && recv_.wnd != 0) {
        // wnd != 0 because: If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs
        // If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return):
        if (tcph.rst()) { return false; }

        tcph_.ack(true);
        send(tun, send_.nxt, 0);
        return false;
    }

    // False signals, that a handler wants to return (usually in drop-and-return situations)
    if (tcph.rst()) { if (!handle_rst(tun, tcph, payload)) { return false; } }

    // Fourth
    if (tcph.syn()) { if (!handle_syn(tun, tcph, payload)) { return false; } }// NOLINT

    // Fifth, check the ACK field
    if (!tcph.ack()) { return false; }
    if (!handle_ack(tun, tcph, payload)) { return false; }

    // TODO: Check URG bit
    if (tcph.urg()) { if (!handle_urg(tun, tcph, payload)) { return false; } }// NOLINT

    if (!payload.empty()) { if (!handle_seg_text(tun, tcph, payload)) { return false; } }// NOLINT

    // TODO: Check FIN bit
    if (tcph.fin()) { if (!handle_fin(tun, tcph, payload)) { return false; } }// NOLINT

    return true;
}

void TcpConnection::on_packet(Tun &tun,
    const netparser::IpHeaderView &iph,
    const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    switch (state_) {
    case TcpState::SYN_SENT: {
        if (!handle_segment_syn_sent(tun, tcph, payload)) { return; }
        break;
    }
    default: {
        if (!handle_segment_other(tun, tcph, payload)) { return; }
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
    if (should_send_fin_ && send_buf_.empty()) {
        tcph_.fin(true);
        tcph_.ack(true);
        send(tun, send_.nxt, 0);
        retransmit_fin_test_ = true;
        should_send_fin_ = false;

        switch (state_) {
        case TcpState::CLOSE_WAIT: {
            state_ = TcpState::LAST_ACK;
            break;
        }
        case TcpState::ESTAB: {
            state_ = TcpState::FIN_WAIT_1;
            break;
        }
        default: { break; }
        }
    }
    return true;
}

void TcpConnection::on_tick(Tun &tun)
{
    update_timer(tun, send_.una);

    if (!handle_send(tun)) { return; }

    // do_close is second, because if we are done sending in SEND (buffers are empty), we can try to issue a FIN
    if (!handle_close(tun)) { return; }
}

ssize_t TcpConnection::send(Tun &tun, const std::uint32_t seqn_from, const std::size_t max_size)
{
    const auto send_buf_idx = static_cast<std::int64_t>(seqn_from) - static_cast<std::int64_t>(send_.una);
    std::println("Send buf idx: {}", send_buf_idx);
    assert(static_cast<std::size_t>(send_buf_idx) < send_buf_.size());

    const std::span<const std::byte> payload{ send_buf_.data() + send_buf_idx, max_size };

    iph_.total_len(
        static_cast<std::uint16_t>(iph_.ihl() * 4 + (netparser::TCPH_MIN_SIZE + tcph_.options().options_size()) +
                                   payload.size()));
    iph_.calculate_checksum();
    const auto ip_data = iph_.serialize();

    tcph_.seqn(seqn_from);
    tcph_.ackn(recv_.nxt);
    const auto tcph_size = static_cast<std::uint8_t>(netparser::TCPH_MIN_SIZE + tcph_.options().options_size());
    tcph_.data_off(tcph_size / 4);
    tcph_.calculate_checksum(iph_, payload);
    const auto tcp_data = tcph_.serialize();// TCP data off is changed here


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

    // Measure once per RTT. // TODO: factor out in a separate function
    // If not measuring currently
    const auto data_size = payload.size() + (tcph_.fin() ? 1 : 0) + (tcph_.syn() ? 1 : 0);
    if (data_size > 0) {
        if (wrapping_gt(seqn_from, send_.nxt - 1)) {
            // Karn algorithm says that you shouldn't measure RTT on retransmitted segments, so this send is not retranmitting if and only if SEG.SEQ >= SND.NXT
            start_measure_rtt(seqn_from);
        }
        start_timer(send_.una, rtt_measurement_.rto_ms);
    }

    if (wrapping_gt(seqn_from + static_cast<std::uint32_t>(data_size), send_.nxt - 1)) {
        send_.nxt += seqn_from + data_size - send_.nxt;// maybe + 1?
    }

    tcph_.syn(false);
    tcph_.ack(false);
    tcph_.fin(false);
    tcph_.rst(false);
    tcph_.options().clear();
    return written;
}

void TcpConnection::accept(Tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
{
    iph_.version(iph.version());
    iph_.ihl(iph.ihl());
    iph_.total_len(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE);
    // It is just that, since IP and TCP do not support options for now.
    iph_.id(0);
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
        std::println("RST IS SET IN ACCEPT");
        tcph_.rst(true);
        send(tun, tcph.ackn(), 0);
        return;
    }

    // Third, check for a SYN
    if (tcph.syn()) {
        recv_.nxt = tcph.seqn() + 1;
        recv_.irs = tcph.seqn();
        recv_.wnd = recv_mss_ * 3;

        if (auto opt = tcph.mss(); opt.has_value()) { send_mss_ = opt.value().mss; }
        send_.wnd = tcph.window();

        // SEt ISS
        std::random_device rnd;
        std::mt19937 gen(rnd());
        std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(),
            std::numeric_limits<std::uint32_t>::max());
        auto iss = dis(gen);
        // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        tcph_.options().mss(recv_mss_);
        tcph_.window(static_cast<std::uint16_t>(recv_.wnd));
        tcph_.syn(true);
        tcph_.ack(true);


        send_.iss = iss;
        send_.una = send_.iss;
        send_.nxt = send_.iss;// 1 goes for SYN (in send()), since it uses up a SEQ number
        send(tun, iss, 0);

        retransmit_syn_test_ = true;

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
    recv_.wnd = recv_mss_ * 3;

    iph_.version(4);
    iph_.ihl(5);// 5 * 4 = 20 bytes (no options)
    iph_.type_of_service(0);
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
    tcph_.options().mss(recv_mss_);// data_off is set in send()
    tcph_.syn(true);
    tcph_.window(static_cast<std::uint16_t>(recv_.wnd));
    tcph_.urg_ptr(0);

    send_.iss = iss;
    send_.una = send_.iss;
    send_.nxt = send_.iss;// +1 is in send()
    send_.wnd = send_mss_;// Update this after we get a SYNACK. Default is 536
    send(tun, iss, 0);

    retransmit_syn_test_ = true;

    state_ = TcpState::SYN_SENT;
}

void TcpConnection::start_measure_rtt(const std::uint32_t seq_n)
{
    if (!rtt_measurement_.send_at_.has_value()) {
        rtt_measurement_.send_seq_at_ = seq_n;
        rtt_measurement_.send_at_ = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        std::println("Send at: {}", rtt_measurement_.send_at_.value());
    }
}

void TcpConnection::stop_measure_rtt() { rtt_measurement_.send_at_.reset(); }

void TcpConnection::measure_rtt(const std::uint32_t ack_n)
{
    if (rtt_measurement_.send_at_.has_value() && wrapping_gt(ack_n, rtt_measurement_.send_seq_at_)) {
        const std::int64_t cur_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        const std::int64_t res = cur_time - rtt_measurement_.send_at_.value();// cur. rtt

        static constexpr std::uint32_t GRAN_MS = 1;
        if (rtt_measurement_.rtt_ms == 0) {
            // First measurement
            rtt_measurement_.srtt = static_cast<std::uint32_t>(res);
            rtt_measurement_.rttvar = static_cast<std::uint32_t>(res / 2);
        } else {
            // Following measurements
            static constexpr double ALPHA = 1.0 / 8.0;
            static constexpr double BETA = 1.0 / 4.0;
            rtt_measurement_.rttvar = static_cast<std::uint32_t>((1.0 - BETA) * static_cast<double>(rtt_measurement_.rttvar) + BETA * std::abs(
                                                     static_cast<double>(rtt_measurement_.srtt) - static_cast<double>(res)));
            rtt_measurement_.srtt = static_cast<std::uint32_t>((1.0 - ALPHA) * static_cast<double>(rtt_measurement_.srtt) + ALPHA * static_cast<double>(
                                                   res));
        }
        rtt_measurement_.rto_ms = rtt_measurement_.srtt + std::max(GRAN_MS, 4 * rtt_measurement_.rttvar);
        // Whenever RTO is computed, if it is less than 1 second,
        // then the RTO SHOULD be rounded up to 1 second
        if (rtt_measurement_.rto_ms < 1000) { rtt_measurement_.rto_ms = 1000; }

        rtt_measurement_.rtt_ms = static_cast<std::uint32_t>(res);
        assert(rtt_measurement_.rtt_ms);// it shouldn't be 0, otherwise "initial RTT measurement" is broken

        rtt_measurement_.send_at_.reset();
        std::println("RTT IS {}, SRTT IS {}, RTTVAR IS {}, RTO IS {}", rtt_measurement_.rtt_ms, rtt_measurement_.srtt, rtt_measurement_.rttvar, rtt_measurement_.rto_ms);
    }
}

void TcpConnection::start_timer(const std::uint32_t seq_n, const std::uint32_t rto_ms)
{
    if (!timer_.timer_start.has_value()) {
        const auto cur_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        timer_.timer_start.emplace(cur_time);// Start timer
        timer_.timer_expire_at = cur_time + static_cast<std::int64_t>(rto_ms);// It expires at RTO
        timer_.timer_start_seq_at = seq_n;
        std::println("Armed timer until {}. Now is {}. timer seq {}", timer_.timer_expire_at, cur_time, timer_.timer_start_seq_at);
    }
}

void TcpConnection::stop_timer() { timer_.timer_start.reset(); }

void TcpConnection::handle_timer_retransmit(Tun &tun)
{
    // Retransmission should happen
    stop_measure_rtt();// Must not measure on retransmits

    // (5.4) Retransmit the earliest segment that has not been acknowledged by the TCP receiver.
    const auto bytes_to_send = std::min(static_cast<std::size_t>(send_mss_), send_buf_.size());
    // it looks like repacketization ahh thing
    // For now retransmit everything inside window (not bigger than MSS)
    if (bytes_to_send || retransmit_fin_test_ || retransmit_syn_test_) {
        std::println("RETRANSMITTING after {} ms!!!!!!!!!!!!", rtt_measurement_.rto_ms);

        tcph_.ack(true);
        // TODO: THIS IS TEMP, UNTIL I HAVE segemtnation
        if (retransmit_fin_test_) { tcph_.fin(true); }
        if (retransmit_syn_test_) {
            tcph_.syn(true);

            switch (state_) {
            case TcpState::SYN_SENT:
                // Since we are in SYN_SENT -> we should retransmit SYN withotu ACK
                tcph_.ack(false);
                break;
            default:
                break;
            }
        }

        send(tun, send_.una, bytes_to_send);
    }


    // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
    // maximum value discussed in (2.5) above may be used to provide
    // an upper bound to this doubling operation.
    rtt_measurement_.rto_ms = rtt_measurement_.rto_ms * 2;
    // rtt_measurement_.rto_ms = rtt_measurement_.rto_ms * static_cast<std::size_t>(backoff_factor_);

    std::println("TIMER EXPIRED with rto now: {}", rtt_measurement_.rto_ms);
    // These values are likely bogus after several backoffs (3)
    if (rtt_measurement_.rto_ms > 10000) {
        rtt_measurement_.srtt = 0;
        rtt_measurement_.rttvar = 0;
    }
    if (rtt_measurement_.rto_ms > 60000) {
        rtt_measurement_.rto_ms = 60000;// Upper bound
    }

    //  (5.6) Start the retransmission timer, such that it expires after RTO
    //  seconds
    stop_timer();
    start_timer(send_.una, rtt_measurement_.rto_ms);

    // TODO: handle 5.7 (ABOUT SYN SEGMENTS)
}


void TcpConnection::update_timer(Tun &tun, const std::uint32_t ack_n)
{
    if (timer_.timer_start.has_value()) {
        const auto cur_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (ack_n == send_.nxt) {
            std::println("All outstanding data ACKED. Disable timer");
            // (5.2) When all outstanding data has been acknowledged, turn off the retransmission timer.
            stop_timer();
        } else if (wrapping_gt(ack_n, timer_.timer_start_seq_at)) {
            // Window was moved, restart timer
            // (5.3) When an ACK is received that acknowledges new data, restart the retransmission timer so that it will expire
            // after RTO seconds (for the current value of RTO).
            std::println("Window moved. Restart the timer");

            // Restart
            stop_timer();
            start_timer(ack_n, rtt_measurement_.rto_ms);
        } else {
            // timer is neither updated nor disabled
            if (cur_time_ms >= timer_.timer_expire_at) { handle_timer_retransmit(tun); }
        }
    }
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
    if (bytes_copy) {
        std::memcpy(buf, recv_buf_.data(), bytes_copy);
        erase_recv_data(bytes_copy);
    }
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
        const std::span<const std::byte> data{ static_cast<const std::byte *>(buf), insert_bytes_n };
        append_send_data(data);
        break;
    }
    default:
        throw std::runtime_error("error: connection is closing");
    }

    return static_cast<ssize_t>(insert_bytes_n);
}