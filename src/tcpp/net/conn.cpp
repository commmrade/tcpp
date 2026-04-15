//
// Created by klewy on 3/18/26.
//

#include "conn.hpp"
#include "common.hpp"
#include <limits>
#include <print>
#include <random>

void TcpConnection::append_send_data(const std::span<const std::byte> data) { send_buf_.append_range(data); }

void TcpConnection::append_recv_data(const std::span<const std::byte> data) { recv_buf_.append_range(data); }

void TcpConnection::erase_send_data(const std::size_t bytes_n)
{
    send_buf_.erase(send_buf_.begin(), send_buf_.begin() + static_cast<const std::ptrdiff_t>(bytes_n));
    send_var_.notify_all();
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

bool TcpConnection::handle_rst(const netparser::TcpHeaderView &tcph)
{
    // from 3.10.7.4. Other States later TODO

    if (!is_between_wrapped(recv_.nxt - 1, tcph.seqn(), recv_.nxt + recv_.wnd)) {
        // Outside the window
        return false;// Just drop the segment
    } else if (tcph.seqn() != recv_.nxt) {
        // Inside window
        tcph_.ack(true);
        send(send_.nxt, 0);// Challenge ACK
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

bool TcpConnection::handle_syn(const netparser::TcpHeaderView &tcph)
{
    // TODO: Challenge ACK in synchronized states <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
    return true;
}

bool TcpConnection::handle_ack(const netparser::TcpHeaderView &tcph)
{
    rtt_measurement_.measure(clock_->now(), tcph.ackn());

    std::println("Got ack n {}, SEND.NXT {}, UNA", tcph.ackn(), send_.nxt, send_.una);
    switch (state_) {
    case TcpState::SYN_RCVD: {
        // got ACK for our SYNACK
        std::println("Ack is invalid: una {} < ackn {} <= nxt {}", send_.una, tcph.ackn(), send_.nxt);
        if (!is_between_wrapped(send_.una, tcph.ackn(), send_.nxt + 1)) {
            std::println("ACK IS NOT VALID. RST SET HERE");
            tcph_.rst(true);
            send(tcph.ackn(), 0);
        }

        conn_var_.notify_all();
        state_ = TcpState::ESTAB;
        set_send_wnd(tcph.window());
        send_.wl1 = tcph.seqn();
        send_.wl2 = tcph.ackn();

        [[fallthrough]];
    }
    case TcpState::FIN_WAIT_1:
    case TcpState::FIN_WAIT_2:
    case TcpState::CLOSE_WAIT:
    case TcpState::CLOSING:
    case TcpState::ESTAB: {
        // TODO: this handling is used for other states besides ESTABLISHED, like FIN_WAIT_1 and FIN_WAIT_2, CLOSING
        // TODO: HANDLE ACK FOR SYn/FIN
        if (tcph.seqn() == recv_.nxt - 1 && recv_.wnd == 0) {
            // It is a window probe probably (at least Linux Net. Stack one)
            tcph_.ack(true);
            send(send_.nxt, 0);
        }
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
            send(send_.nxt, 0);
            return false;// Drop the segment and return
        }

        if (is_between_wrapped(send_.una - 1, tcph.ackn(), send_.nxt + 1)) {
            // Update window
            if (wrapping_lt(send_.wl1, tcph.seqn()) || (send_.wl1 == tcph.seqn() && wrapping_lt(send_.wl2,
                                                            tcph.ackn() + 1))) {
                // send_.wnd = tcph.window();
                set_send_wnd(tcph.window());
                send_.wl1 = tcph.seqn();
                send_.wl2 = tcph.ackn();
            }
        }

        update_send_window();
        break;
    }
    case TcpState::LAST_ACK: {
        // The only thing that can arrive in this state is an acknowledgment of our FIN
        state_ = TcpState::CLOSED;
        break;
    }
    default:
        break;// TODO
    }

    // Process those states, that require ESTAB processing + something else
    switch (state_) {
    case TcpState::FIN_WAIT_1: {

        // if FIN segment is ACKed, then continue in FIN_WAIT_2
        // TOOD: actually make sure fin is acked
        state_ = TcpState::FIN_WAIT_2;
        [[fallthrough]];
    }
    case TcpState::FIN_WAIT_2: {
        // if the retrans. queue is empty, then closing is done
        if (send_buf_.empty()) {
            // acknowledge user close
        }
        break;
    }
    case TcpState::CLOSING: {
        // TOOD: actually make sure fin is acked
        state_ = TcpState::TIME_WAIT;
        break;
    }
    default:
        break;
    }

    update_timers();
    return true;
}

void TcpConnection::update_recv_window()
{
    const std::size_t buffer_size = std::numeric_limits<std::uint16_t>::max();
    const auto free_space = buffer_size - recv_buf_.size();

    if (free_space == 0) {
        set_recv_wnd(0, recv_.nxt);
        return;
    }

    const auto wnd_size = get_recv_wnd();
    const auto increment = free_space > wnd_size ? free_space - wnd_size : 0;
    if (increment >= std::min(buffer_size / 2, static_cast<std::size_t>(recv_mss_))) {
        set_recv_wnd(static_cast<std::uint32_t>(free_space), recv_.nxt);
    }
}

void TcpConnection::update_send_window()
{
    const auto in_flight_n = send_.nxt - send_.una;
    const auto unsent = static_cast<std::uint32_t>(send_buf_.size()) - in_flight_n;
    // Start probing only if there is data to send, otherwise it is useless
    // Stop probing when SND.WND has been updated and now TCP is about to send new data (in on_tick()).
    // So (unsent > 0) is safe for stopping ZWP scenario
    if (unsent > 0) {
        if (send_.wnd == 0 && !z_timer_.is_armed()) {
            assert(!send_buf_.empty());
            const auto seq_num = send_.una;
            rtt_measurement_.rto_ms = RttMeasurement::DEFAULT_RTO_MS;
            std::println("START ZWP TIMER AGAIN");

            r_timer_.stop(); // Retrans. timer should be suspended when ZWP is running
            z_timer_.start(seq_num, 1, rtt_measurement_.rto_ms, clock_->now());

            // TODO: do i really need old_wnd_size condition?
        } else if (send_.wnd > 0 && z_timer_.is_armed()) {
            z_timer_.stop();

            // Reset RTT variables, since they may be kinda wrong after probing packets
            // FIXME: this is prolly unncesea since timers use rto 1 time
            rtt_measurement_.reset();
            rtt_measurement_.rto_ms = RttMeasurement::DEFAULT_RTO_MS;

            // I think It is kinda logical to start sending from UNA after ZWP is finished
            send_.nxt = send_.una;
        }
    }

}

bool TcpConnection::handle_seg_text(const netparser::TcpHeaderView &tcph,
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
            send(send_.nxt, 0);
            return true;
        }

        // This should not be done in ZWP state
        if (recv_.wnd != 0) {
            const auto payload_size = payload.size() + (tcph.syn() ? 1 : 0) + (tcph.fin() ? 1 : 0);
            append_recv_data(payload);
            recv_.nxt += payload_size;// FIN is handled in handle_fin()
        }

        // FIN is gonna be handled in handle_fin()
        if (!tcph_.fin()) {
            tcph_.ack(true);
            send(send_.nxt, 0);// TODO: piggyback this
            recv_var_.notify_all();
        }
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
        // assert(0 && "This should not happen");
        break;
    }
    return true;
}

bool TcpConnection::handle_fin()
{
    is_finished_ = true;
    recv_var_.notify_all();// Notify socekts about a read, now they should check is_finished

    switch (state_) {
    case TcpState::ESTAB: {
        state_ = TcpState::CLOSE_WAIT;
        should_send_fin_ = true;// Fin will be sent in on_tick()
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

bool TcpConnection::handle_segment_syn_sent(const netparser::TcpHeaderView &tcph)
{
    bool is_ack_acceptable = false;
    if (tcph.ack()) {
        std::println("{} {}. {} {}", tcph.ackn() - 1, send_.iss, tcph.ackn(), send_.nxt);
        if (wrapping_lt(tcph.ackn() - 1, send_.iss) || tcph.ackn() > send_.nxt) {
            tcph_.rst(true);
            std::println("SENDING RST IN SYN SENT");
            send(tcph.ackn(), 0);
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
        update_recv_window();
        if (tcph.ack()) { send_.una = tcph.ackn(); }

        if (send_.una > send_.iss /* SYN has been ACKed */) {
            state_ = TcpState::ESTAB;

            tcph_.ack(true);
            send(send_.nxt, 0);

            // 3 way handshake is done at this point
            conn_var_.notify_all();
        } else {
            // TODO: how to handle this in terms of *conn_var_*?
            state_ = TcpState::SYN_RCVD;// Sim. open things

            tcph_.ack(true);
            tcph_.syn(true);
            send(send_.iss, 0);
        }

        if (auto opt = tcph.mss(); opt.has_value()) { send_mss_ = opt.value().mss; }
        // send_.wnd = tcph.window();
        set_send_wnd(tcph.window());
        send_.wl1 = tcph.seqn();
        send_.wl2 = tcph.ackn();
    }

    if (!tcph.syn() && !tcph.rst()) {
        return false;// return from processing
    }
    return true;
}

bool TcpConnection::handle_segment_other(const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    // First, check sequence number
    if (!validate_seq_n(tcph, payload) && recv_.wnd != 0) {
        // wnd != 0 because: If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs
        // If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return):
        if (tcph.rst()) { return false; }

        tcph_.ack(true);
        send(send_.nxt, 0);
        return false;
    }

    // False signals, that a handler wants to return (usually in drop-and-return situations)
    if (tcph.rst()) { if (!handle_rst(tcph)) { return false; } }

    // Fourth
    if (tcph.syn()) { if (!handle_syn(tcph)) { return false; } }// NOLINT

    // Fifth, check the ACK field
    if (!tcph.ack()) { return false; }
    if (!handle_ack(tcph)) { return false; }

    // Ignore URG bit

    const auto payload_size = payload.size() + (tcph.syn() ? 1 : 0) + (tcph.fin() ? 1 : 0);
    if (payload_size > 0) { if (!handle_seg_text(tcph, payload)) { return false; } }

    // TODO: Check FIN bit
    if (tcph.fin()) { if (!handle_fin()) { return false; } }// NOLINT

    return true;
}

void TcpConnection::on_packet(const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    switch (state_) {
    case TcpState::SYN_SENT: {
        if (!handle_segment_syn_sent(tcph)) { return; }
        break;
    }
    default: {
        if (!handle_segment_other(tcph, payload)) { return; }
        break;
    }
    }
}

bool TcpConnection::handle_send()
{
    const auto in_flight_n = send_.nxt - send_.una;

    // FIXME: This happens on SYN and FIN, can't fix it unless I implement segments
    if (in_flight_n > send_buf_.size()) {
        // assert(in_flignt_n == 1); // Usually it is just 1 byte - FIN,SYN, but if it is more, then it is kind of suspicious
        return true;
    }

    const auto unsent = static_cast<std::uint32_t>(send_buf_.size()) - in_flight_n;
    if (unsent > 0 && send_.wnd > 0) {
        // Sender SWS
        const auto usable_wnd = send_.wnd - in_flight_n;
        // const auto bytes_to_send = std::min({ static_cast<std::size_t>(send_mss_), send_buf_.size() - in_flight_n,
                                              // static_cast<std::size_t>(send_.wnd - in_flight_n) });
        const auto bytes_to_send = std::min<std::size_t>({send_mss_, unsent, usable_wnd});
        if (bytes_to_send == 0) {
            return true;
        }

        // TODO: PUSH flag in segments
        // FIXME: SND.NXT == SND.UNA is a NAGLE condition. I should let user disable NAgle so this cond. isnt enforced
        bool can_send = (std::min(usable_wnd, unsent) >= send_mss_) || (send_.nxt == send_.una && unsent <= usable_wnd)
                        || (send_.nxt == send_.una && std::min(unsent, usable_wnd) >= send_wnd_max_ / 2);
        if (can_send) {
            s_timer_.stop(); // FIXME: should it be here?

            std::println("SWS SEnding: {} {} {} {}, flight: {}",
                send_buf_.size(),
                usable_wnd,
                bytes_to_send,
                unsent,
                in_flight_n);
            tcph_.ack(true);
            send(send_.nxt, bytes_to_send);
        } else {
            std::println("Start SWS override timer. send nxt: {}, send una: {}, data len {}", send_.nxt, send_.una, bytes_to_send);
            // FIXME: I MAY NEED TO IMPL. TIMERS OTEHR WAY, SINCE SWS AND RETRANS SHOULD NOT BE SHARED
            s_timer_.start(send_.nxt,
                static_cast<std::uint32_t>(bytes_to_send),
                RttMeasurement::SWS_OVERRIDE_MS, clock_->now());
        }
    }
    return true;
}

bool TcpConnection::handle_close()
{
    if (should_send_fin_ && send_buf_.empty()) {
        tcph_.fin(true);
        tcph_.ack(true);
        send(send_.nxt, 0);
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

void TcpConnection::on_tick()
{
    update_timers();
    // First, deal with window stuff (zero window, to be exact) and then handle send
    update_send_window();

    if (!handle_send()) { return; }
    if (!handle_close()) { return; }
}

ssize_t TcpConnection::send(const std::uint32_t seqn_from, const std::size_t max_size)
{
    const auto send_buf_idx = static_cast<std::int64_t>(seqn_from) - static_cast<std::int64_t>(send_.una);
    std::println("Send buf idx: {}, send buf size: {}, send size: {}", send_buf_idx, send_buf_.size(), max_size);
    // assert(static_cast<std::size_t>(send_buf_idx) <= send_buf_.size());

    const std::span<const std::byte> payload{ send_buf_.data() + send_buf_idx, max_size };

    iph_.total_len(
        static_cast<std::uint16_t>(static_cast<std::size_t>(iph_.ihl() * 4) + (
                                       netparser::TCPH_MIN_SIZE + tcph_.options().options_size()) +
                                   payload.size()));
    iph_.calculate_checksum();
    const auto ip_data = iph_.serialize();

    tcph_.seqn(seqn_from);
    tcph_.ackn(recv_.nxt);

    update_recv_window();
    const auto wnd_to_advertise = static_cast<std::uint16_t>(get_recv_wnd());
    tcph_.window(wnd_to_advertise);
    const auto tcph_size = static_cast<std::uint8_t>(netparser::TCPH_MIN_SIZE + tcph_.options().options_size());
    tcph_.data_off(tcph_size / 4);
    tcph_.calculate_checksum(iph_, payload);
    const auto tcp_data = tcph_.serialize();// TCP data off is changed here


    std::vector<std::byte> buf{};
    buf.resize(
        static_cast<std::size_t>(iph_.ihl() * 4) + static_cast<std::size_t>(tcph_.data_off() * 4) + payload.size());

    std::size_t offset = 0;
    std::memcpy(buf.data() + offset, ip_data.data(), ip_data.size());// NOLINT
    offset += ip_data.size();
    std::memcpy(buf.data() + offset, tcp_data.data(), tcp_data.size());// NOLINT
    offset += tcp_data.size();
    if (!payload.empty()) {
        std::memcpy(buf.data() + offset, payload.data(), payload.size());
        offset += payload.size();
    }

    const auto written = tun_.write(buf.data(), offset);
    if (written < 0) {
        throw std::runtime_error(std::format("Write failed: {}", std::strerror(errno)));// NOLINT
    }
    assert(static_cast<std::size_t>(written) == offset);
    // i think it should be ok, if fails, then i have to rewrite "snd.nxt +" logic

    // Measure once per RTT. // TODO: factor out in a separate function
    // If not measuring currently
    const auto data_size = payload.size() + (tcph_.fin() ? 1 : 0) + (tcph_.syn() ? 1 : 0);
    if (data_size > 0) {
        const auto time_now = clock_->now();
        if (wrapping_gt(seqn_from, send_.nxt - 1)) {
            // Karn algorithm says that you shouldn't measure RTT on retransmitted segments, so this send is not retranmitting if and only if SEG.SEQ >= SND.NXT
            rtt_measurement_.start(time_now, seqn_from);
        }
        if (!z_timer_.is_armed()) { // Should not run while ZWP is active
            r_timer_.start(send_.una,
            static_cast<std::uint32_t>(payload.size()),
            rtt_measurement_.rto_ms, time_now);
        }
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

void TcpConnection::accept(const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
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
        send(tcph.ackn(), 0);
        return;
    }

    // Third, check for a SYN
    if (tcph.syn()) {
        recv_.nxt = tcph.seqn() + 1;
        recv_.irs = tcph.seqn();
        // recv_.wnd = recv_mss_ * 3;
        set_recv_wnd(std::numeric_limits<std::uint16_t>::max(), recv_.nxt);

        if (auto opt = tcph.mss(); opt.has_value()) { send_mss_ = opt.value().mss; }
        // send_.wnd = tcph.window();
        set_send_wnd(tcph.window());

        // SEt ISS
        std::random_device rnd;
        std::mt19937 gen(rnd());
        std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(),
            std::numeric_limits<std::uint32_t>::max());
        auto iss = dis(gen);
        // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        tcph_.options().mss(recv_mss_); // FIXME: SHOULD I SEND IT IF THAT PEER DID NOT HAVE THIS????
        tcph_.window(static_cast<std::uint16_t>(recv_.wnd));
        tcph_.syn(true);
        tcph_.ack(true);


        send_.iss = iss;
        send_.una = send_.iss;
        send_.nxt = send_.iss;// 1 goes for SYN (in send()), since it uses up a SEQ number
        send(iss, 0);

        state_ = TcpState::SYN_RCVD;
    }
}

void TcpConnection::connect(const std::uint32_t saddr,
    const std::uint16_t sport,
    const std::uint32_t daddr,
    const std::uint16_t dport)
{
    std::random_device rnd;
    std::mt19937 gen(rnd());
    std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(),
        std::numeric_limits<std::uint32_t>::max());

    const auto iss = dis(gen);
    // recv_.wnd = recv_mss_ * 3;
    set_recv_wnd(std::numeric_limits<std::uint16_t>::max(), recv_.nxt);

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
    // send_.wnd = send_mss_;// Update this after we get a SYNACK. Default is 536
    set_send_wnd(send_mss_);
    send(iss, 0);

    state_ = TcpState::SYN_SENT;
}

// void TcpConnection::start_measure_rtt(const std::uint32_t seq_n)
// {
//     if (!rtt_measurement_.send_at_.has_value()) {
//         rtt_measurement_.send_seq_at_ = seq_n;
//         rtt_measurement_.send_at_ = clock_->now();
//         std::println("Send at: {}", rtt_measurement_.send_at_.value());
//     }
// }

// void TcpConnection::stop_measure_rtt() { rtt_measurement_.send_at_.reset(); }

// void TcpConnection::measure_rtt(const std::uint32_t ack_n)
// {
//     if (rtt_measurement_.send_at_.has_value() && wrapping_gt(ack_n, rtt_measurement_.send_seq_at_)) {
//         const std::int64_t cur_time = clock_->now();
//         const std::int64_t res = cur_time - rtt_measurement_.send_at_.value();// cur. rtt
//
//         static constexpr std::uint32_t GRAN_MS = 1;
//         if (rtt_measurement_.rtt_ms == 0) {
//             // First measurement
//             rtt_measurement_.srtt = static_cast<std::uint32_t>(res);
//             rtt_measurement_.rttvar = static_cast<std::uint32_t>(res / 2);
//         } else {
//             // Following measurements
//             static constexpr double ALPHA = 1.0 / 8.0;
//             static constexpr double BETA = 1.0 / 4.0;
//             rtt_measurement_.rttvar = static_cast<std::uint32_t>(
//                 (1.0 - BETA) * static_cast<double>(rtt_measurement_.rttvar) + BETA * std::abs(
//                     static_cast<double>(rtt_measurement_.srtt) - static_cast<double>(res)));
//             rtt_measurement_.srtt = static_cast<std::uint32_t>(
//                 (1.0 - ALPHA) * static_cast<double>(rtt_measurement_.srtt) + ALPHA * static_cast<double>(
//                     res));
//         }
//         rtt_measurement_.rto_ms = rtt_measurement_.srtt + std::max(GRAN_MS, 4 * rtt_measurement_.rttvar);
//         // Whenever RTO is computed, if it is less than 1 second,
//         // then the RTO SHOULD be rounded up to 1 second
//         rtt_measurement_.rto_ms = std::max(rtt_measurement_.rto_ms, RttMeasurement::DEFAULT_RTO_MS);
//
//         rtt_measurement_.rtt_ms = static_cast<std::uint32_t>(res);
//
//         rtt_measurement_.send_at_.reset();
//         std::println("RTT IS {}, SRTT IS {}, RTTVAR IS {}, RTO IS {}",
//             rtt_measurement_.rtt_ms,
//             rtt_measurement_.srtt,
//             rtt_measurement_.rttvar,
//             rtt_measurement_.rto_ms);
//     }
// }

// void TcpConnection::reset_rtt()
// {
//     rtt_measurement_.rttvar = 0;
//     rtt_measurement_.srtt = 0;
// }

// void TcpConnection::start_timer(const std::uint32_t seq_n,
//     const std::uint32_t data_len,
//     const std::uint32_t rto_ms,
//     const Timer::TimerState start_state)
// {
//     if (!timer_.timer_start.has_value()) {
//         const auto cur_time = clock_->now();
//         timer_.timer_start.emplace(cur_time);// Start timer
//         timer_.timer_expire_at = cur_time + static_cast<std::int64_t>(rto_ms);// It expires at RTO
//         timer_.timer_start_seq_at = seq_n;
//         timer_.timer_data_length = data_len;
//         timer_.state = start_state;
//         std::println("Armed timer until {}. Now is {}. timer seq {}, state: {}",
//             timer_.timer_expire_at,
//             cur_time,
//             timer_.timer_start_seq_at,
//             static_cast<int>(timer_.state));
//     }
// }

// void TcpConnection::stop_timer()
// {
//     timer_.timer_start.reset();
//     // timer_.state = Timer::TimerState::RETRANSMISSION;
// }

void TcpConnection::retransmit(Timer& timer)
{
    // Retransmission should happen
    rtt_measurement_.stop_measure();// Must not measure on retransmits

    // (5.4) Retransmit the earliest segment that has not been acknowledged by the TCP receiver.
    tcph_.ack(true);

    if (is_fin_state(state_)) { tcph_.fin(true); }
    if (is_syn_state(state_)) {
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

    send(timer.timer_start_seq_at, timer.timer_data_length);
    timer.retransmitted(send_.una, clock_->now());
}

void TcpConnection::update_timers()
{

    // TODO: retrans fires and breaks zwp and so on
    const auto time_now = clock_->now();
    const bool should_retrans = r_timer_.update(send_.nxt, send_.una, time_now, rtt_measurement_);
    if (should_retrans) {
        std::println("Retransmit fires");
        retransmit(r_timer_);
    }
    const bool should_zwp = z_timer_.update(time_now);
    if (should_zwp) {
        std::println("zwp fires");
        retransmit(z_timer_);
    }
    const bool should_sws = s_timer_.update(time_now);
    // FIXME: this causes a segf because send buf idx is -100 idk why
    if (should_sws) {
        std::println("SWS TIMER FIRES: send nxt: {}, send una: {}", send_.nxt, send_.una);
        retransmit(s_timer_);
    }
}

void TcpConnection::set_send_wnd(const std::uint32_t wnd)
{
    send_wnd_max_ = std::max(send_.wnd, wnd);
    send_.wnd = wnd;
}

void TcpConnection::set_recv_wnd(const std::uint32_t wnd, const std::uint32_t nxt)
{
    recv_.wnd = wnd;
    right_wnd_edge_ = nxt + wnd;
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
    if (bytes_copy > 0) {
        std::memcpy(buf, recv_buf_.data(), bytes_copy);
        erase_recv_data(bytes_copy);
    }
    return static_cast<ssize_t>(bytes_copy);
}

ssize_t TcpConnection::write(const void *buf, const std::size_t buf_size)
{
    const auto insert_bytes_n = std::min(send_buf_free_space(), buf_size);
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