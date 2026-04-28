//
// Created by klewy on 3/18/26.
//

#include "conn.hpp"
#include "common.hpp"
#include <limits>
#include <print>
#include <random>

void TcpConnection::append_recv_data(const std::span<const std::byte> data) { recv_buf_.append_range(data); }

// void TcpConnection::erase_send_data(const std::size_t bytes_n)
// {
    // send_buf_.erase(send_buf_.begin(), send_buf_.begin() + static_cast<const std::ptrdiff_t>(bytes_n));
    // send_var_.notify_all();
// }

void TcpConnection::erase_recv_data(const std::size_t bytes_n)
{
    recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + static_cast<const std::ptrdiff_t>(bytes_n));
}

static bool validate_seq_n(const std::uint32_t seq_n, std::size_t payload_size, const std::uint32_t recv_wnd, const std::uint32_t recv_nxt)
{
    if (payload_size == 0 && recv_wnd == 0 && seq_n == recv_nxt) { return true; } else if (
        payload_size == 0 && recv_wnd > 0 &&
        is_between_wrapped(recv_nxt - 1, seq_n, recv_nxt + recv_wnd)) { return true; } else if (
        payload_size > 0 && recv_wnd == 0) { return false; } else if (
        payload_size > 0 && recv_wnd > 0 && (
            is_between_wrapped(recv_nxt - 1, seq_n, recv_nxt + recv_wnd) || is_between_wrapped(
                recv_nxt - 1,
                static_cast<std::uint32_t>(seq_n + payload_size - 1),
                recv_nxt + recv_wnd))) { return true; }
    return false;
}

bool TcpConnection::on_rst(const netparser::TcpHeaderView &tcph)
{
    // from 3.10.7.4. Other States later TODO

    if (!is_between_wrapped(recv_.nxt() - 1, tcph.seqn(), recv_.nxt() + recv_.wnd())) {
        // Outside the window
        return false;// Just drop the segment
    } else if (tcph.seqn() != recv_.nxt()) {
        // Inside window

        TcpSegment chall_ack{send_.nxt(), {}};
        chall_ack.set_ack(true);
        chall_ack.set_ackn(recv_.nxt());
        send_pure(chall_ack); // Challenge ACK
        return false;
    }

    // If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT),
    // then TCP endpoints MUST reset the connection in the manner prescribed below according to the connection state
    switch (state_) {
    case TcpState::SYN_RCVD: {
        // This should be returned to LISTEN state, which is basically CLOSED. Then when a packet comes it is gonna just create a new conn.
        state_ = TcpState::CLOSED;

        // If the connection was initiated with a passive OPEN,
        // then return this connection to the LISTEN state and return.
        // Otherwise, handle per the directions for synchronized states below.
        break;
    }
    case TcpState::SYN_SENT: {
        // This should signal "connection refused" to the user.

        // TODO: signal state, impl. errno variable
        state_ = TcpState::CLOSED;
        break;
    }
    case TcpState::ESTAB:
    case TcpState::FIN_WAIT_1:
    case TcpState::FIN_WAIT_2:
    case TcpState::CLOSE_WAIT:
        // TODO: signal "connection reset" errno

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

bool TcpConnection::on_syn(const netparser::TcpHeaderView &tcph)
{
    switch (state_) {
        case TcpState::SYN_RCVD: {
            // Return to LISTEn and return from processing
            state_ = TcpState::CLOSED;

            return false; // Signal that we shall return.
        }
        case TcpState::ESTAB:
        case TcpState::FIN_WAIT_1:
        case TcpState::FIN_WAIT_2:
        case TcpState::CLOSE_WAIT:
        case TcpState::CLOSING:
        case TcpState::LAST_ACK:
        case TcpState::TIME_WAIT: {
            // Since we follow RFC 793 in this case, not RFC 5961
            // We shall send a RST
            // In RFC 5961 it is told to send a "challenge ACK".

            // This should only be done if SEGMENT is in window, but if it wasn't in window, it would have never gotten here because of "SEQN check".
            // tcph_.rst(true);
            // send(send_.nxt(), 0);
            TcpSegment rst_seg{send_.nxt(), {}};
            rst_seg.set_rst(true);
            send_pure(rst_seg);

            state_ = TcpState::CLOSED;

            // TODO: "connection reset" error errno

            return false; // Signal that we should return, then delete TCB.
        }
        default: {
            // Just ignore
            break;
        }
    }
    return true;
}

bool TcpConnection::on_ack(const netparser::TcpHeaderView &tcph)
{
    rtt_measurement_.update(clock_->now(), tcph.ackn());

    std::println("Got ack n {}, SEND.NXT {}, UNA", tcph.ackn(), send_.nxt(), send_.una());
    switch (state_) {
    case TcpState::SYN_RCVD: {
        // got ACK for our SYNACK
        std::println("Ack is invalid: una {} < ackn {} <= nxt {}", send_.una(), tcph.ackn(), send_.nxt());
        if (!is_between_wrapped(send_.una(), tcph.ackn(), send_.nxt() + 1)) {
            std::println("ACK IS NOT VALID. RST SET HERE");
            // tcph_.rst(true);
            // send(tcph.ackn(), 0);
            TcpSegment rst_seg{tcph.ackn(), {}};
            rst_seg.set_rst(true);
            send_pure(rst_seg);
        }

        conn_var_.notify_all();
        state_ = TcpState::ESTAB;
        send_.set_wnd(tcph.window());
        send_.set_wl1(tcph.seqn());
        send_.set_wl2(tcph.ackn());

        [[fallthrough]];
    }
    case TcpState::FIN_WAIT_1:
    case TcpState::FIN_WAIT_2:
    case TcpState::CLOSE_WAIT:
    case TcpState::CLOSING:
    case TcpState::ESTAB: {
        if (tcph.seqn() == recv_.nxt() - 1 && recv_.wnd()== 0) {
            // It is a window probe probably (at least Linux Net. Stack one)
            // tcph_.ack(true);
            // send(send_.nxt(), 0);
            TcpSegment ack_seg{send_.nxt(), {}};
            ack_seg.set_ack(true);
            ack_seg.set_ackn(recv_.nxt());
            send_pure(ack_seg);
        }
        if (is_between_wrapped(send_.una(), tcph.ackn(), send_.nxt() + 1)) {
            // const auto acked_bytes_n = tcph.ackn() - send_.una();// This wraps fine
            if (!send_buf_.empty()) {
                const auto res = send_buf_.consume(tcph.ackn()); // TODO: check if this correctly consumes UP TO (especially when SYN/FIN)
                assert(res > 0);
                // assert(acked_bytes_n <= send_buf_.size());// Just in case
                // if empty, probably means that SYN/FIN was ACKed
                // erase_send_data(acked_bytes_n);
            }
            send_.set_una(tcph.ackn());
        } else if (wrapping_lt(tcph.ackn(), send_.una() + 1)) {
            // duplicate ACK
            // Ignore
        } else if (wrapping_gt(tcph.ackn(), send_.nxt())) {
            TcpSegment ack_seg{send_.nxt(), {}};
            ack_seg.set_ack(true);
            ack_seg.set_ackn(recv_.nxt());
            send_pure(ack_seg);
            // tcph_.ack(true);
            // send(send_.nxt(), 0);
            return false;// Drop the segment and return
        }

        if (is_between_wrapped(send_.una() - 1, tcph.ackn(), send_.nxt() + 1)) {
            // Update window
            if (wrapping_lt(send_.wl1(), tcph.seqn()) || (send_.wl1() == tcph.seqn() && wrapping_lt(send_.wl2(),
                                                            tcph.ackn() + 1))) {
                // send_.wnd = tcph.window();
                send_.set_wnd(tcph.window());
                send_.set_wl1(tcph.seqn());
                send_.set_wl2(tcph.ackn());
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
    case TcpState::TIME_WAIT: {
        // The only thing that can arrive is retr. of remote FIN
        // ACK it and restart 2 MSL timeout
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
            // acknowledge user close, but do not close conn.
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
        recv_.set_wnd(0);
        return;
    }

    const auto wnd_size = recv_.wnd();
    const auto increment = free_space > wnd_size ? free_space - wnd_size : 0;
    if (increment >= std::min(buffer_size / 2, static_cast<std::size_t>(recv_mss_))) {
        recv_.set_wnd(static_cast<const std::uint32_t>(free_space));
    }
}

void TcpConnection::update_send_window()
{
    const auto in_flight_n = send_.nxt() - send_.una();
    const auto unsent = static_cast<std::uint32_t>(send_buf_.size_bytes()) - in_flight_n;
    // Start probing only if there is data to send, otherwise it is useless
    // Stop probing when SND.WND has been updated and now TCP is about to send new data (in on_tick()).
    // So (unsent > 0) is safe for stopping ZWP scenario
    if (unsent > 0) {
        if (send_.wnd() == 0 && !z_timer_.is_armed()) {
            assert(!send_buf_.empty());
            const auto seq_num = send_.una();
            rtt_measurement_.rto(RttMeasurement::DEFAULT_RTO_MS);

            r_timer_.stop(); // Retrans. timer should be suspended when ZWP is running
            z_timer_.start(clock_->now(), rtt_measurement_.rto(), seq_num, 1);
        } else if (send_.wnd() > 0 && z_timer_.is_armed()) {
            z_timer_.stop();

            rtt_measurement_.reset();
            rtt_measurement_.rto(RttMeasurement::DEFAULT_RTO_MS);

            // I think It is kinda logical to start sending from UNA after ZWP is finished
            send_.set_nxt(send_.una());
        }
    }

}

bool TcpConnection::on_data(const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    switch (state_) {
    case TcpState::ESTAB:
    case TcpState::FIN_WAIT_1:
    case TcpState::FIN_WAIT_2: {
        // A TCP implementation MAY send an ACK segment acknowledging RCV.NXT
        // when a valid segment arrives that is in the window but not at the left window edge
        if (tcph.seqn() != recv_.nxt()) {
            // tcph_.ack(true);
            // send(send_.nxt(), 0);

            TcpSegment ack_seg{send_.nxt(), {}};
            ack_seg.set_ack(true);
            ack_seg.set_ackn(recv_.nxt());
            send_pure(ack_seg);
            return true;
        }

        // This should not be done in ZWP state
        if (recv_.wnd()!= 0) {
            const std::uint32_t payload_size = static_cast<std::uint32_t>(payload.size() + (tcph.syn() ? 1 : 0) + (tcph.fin() ? 1 : 0));
            append_recv_data(payload);
            recv_.set_nxt(recv_.nxt() + payload_size);// FIN is handled in handle_fin()
        }

        // TODO: Could piggyback this ack
        TcpSegment ack_seg{send_.nxt(), {}};
        ack_seg.set_ack(true);
        ack_seg.set_ackn(recv_.nxt());
        send_pure(ack_seg);

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
        // assert(0 && "This should not happen");
        break;
    }
    return true;
}

bool TcpConnection::on_fin()
{
    is_finished_ = true;
    recv_var_.notify_all();// Notify socekts about a read, now they should check is_finished

    switch (state_) {
    case TcpState::ESTAB: {
        state_ = TcpState::CLOSE_WAIT;
        add_fin_segment();
        break;
    }
    case TcpState::FIN_WAIT_2: {
        // WE got a FIN from the other side, now switch to time_wait
        state_ = TcpState::TIME_WAIT;
        // TODO: start wait timer and then close

        state_ = TcpState::CLOSED;
        break;
    }
    default:
        break;
    }
    return true;
}

bool TcpConnection::segment_arrived_syn_sent(const netparser::TcpHeaderView &tcph)
{
    if (tcph.ack()) {
        if (wrapping_lt(tcph.ackn() - 1, send_.iss()) || tcph.ackn() > send_.nxt()) {
            // tcph_.rst(true);
            // send(tcph.ackn(), 0);

            TcpSegment rst_seg{tcph.ackn(), {}};
            rst_seg.set_rst(true);
            send_pure(rst_seg);
            return false;// return from processing
        }
        if (!is_between_wrapped(send_.una(), tcph.ackn(), send_.nxt() + 1)) { // Otherwise ACK is acceptable
            return false; // No point in going on if ACK is not acceptable
        }
    }
    if (tcph.rst()) {
        // ACK is acceptable at this point
        // Notice: If we are ever to follow RFC 5961, then it is all different

        if (tcph.ack()) {
            // If ACK: Drop the segment, return, delete TCB

            // TODO: Signal "error: conn. reset"
            state_ = TcpState::CLOSED;
            return false;
        } else {
            // Else: drop the segment and return
            return false;
        }
    }

    // This step should be reached only if the ACK is ok, or there is no ACK, and the segment did not contain a RST.
    if (tcph.syn()) {
        recv_.set_nxt(tcph.seqn() + 1);
        recv_.set_irs(tcph.seqn());

        update_recv_window();
        if (tcph.ack()) { send_.set_una(tcph.ackn()); }

        assert(send_buf_.front().syn());
        if (send_.una() > send_buf_.front().seq_start()) { // Check if it has ACKed SYN
            send_buf_.consume(tcph.ackn()); // Consume up to SYN

            state_ = TcpState::ESTAB;
            TcpSegment ack_seg{send_.nxt(), {}};
            ack_seg.set_ack(true);
            ack_seg.set_ackn(recv_.nxt());
            send_pure(ack_seg);

            // 3 way handshake is done at this point
            conn_var_.notify_all();
        } else {
            // TODO: how to handle this in terms of *conn_var_*? Simultaneous open
            state_ = TcpState::SYN_RCVD;// Sim. open things

            TcpSegment synack_seg{send_.iss(), {}, true};
            synack_seg.set_ack(true);
            synack_seg.set_ackn(recv_.nxt());
            send_buf_.insert(synack_seg);
            send_data(1, 0);

            // tcph_.ack(true);
            // tcph_.syn(true);
            // send(send_.iss(), 0);
        }

        if (auto opt = tcph.mss(); opt.has_value()) { send_mss_ = opt.value().mss; }
        // send_.wnd = tcph.window();
        send_.set_wnd(tcph.window());
        send_.set_wl1(tcph.seqn());
        send_.set_wl2(tcph.ackn());
    }

    if (!tcph.syn() && !tcph.rst()) {
        return false;// return from processing
    }
    return true;
}

bool TcpConnection::segment_arrived_other(const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    // First, check sequence number
    if (!validate_seq_n(tcph.seqn(), payload.size(), recv_.wnd(), recv_.nxt()) && recv_.wnd() != 0) {
        // wnd != 0 because: If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs
        // If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return):
        if (tcph.rst()) { return false; }

        TcpSegment ack_seg{send_.nxt(), {}};
        ack_seg.set_ack(true);
        ack_seg.set_ackn(recv_.nxt());

        send_pure(ack_seg);

        // tcph_.ack(true);
        // send(send_.nxt(), 0);
        return false;
    }

    // False signals, that a handler wants to return (usually in drop-and-return situations)
    if (tcph.rst()) { if (!on_rst(tcph)) { return false; } }

    // Fourth
    if (tcph.syn()) { if (!on_syn(tcph)) { return false; } }// NOLINT

    // Fifth, check the ACK field
    if (!tcph.ack()) { return false; }
    if (!on_ack(tcph)) { return false; }

    // Ignore URG bit

    const auto payload_size = payload.size() + (tcph.syn() ? 1 : 0) + (tcph.fin() ? 1 : 0);
    if (payload_size > 0) { if (!on_data(tcph, payload)) { return false; } }

    if (tcph.fin()) { if (!on_fin()) { return false; } }// NOLINT

    return true;
}

void TcpConnection::on_packet(const netparser::TcpHeaderView &tcph,
    std::span<const std::byte> payload)
{
    if (TcpState::SYN_SENT == state_) {
        segment_arrived_syn_sent(tcph);
    } else {
        segment_arrived_other(tcph, payload);
    }
}

void TcpConnection::add_fin_segment() {
    std::uint32_t seq_start{};
    if (send_buf_.empty()) {
        seq_start = send_.nxt();
    } else {
        seq_start = send_buf_.back().seq_end();
    }
    TcpSegment fin_seg{seq_start, {}, false, true};
    fin_seg.set_ack(true);
    fin_seg.set_ackn(recv_.nxt());
    send_buf_.insert(fin_seg);
}

bool TcpConnection::handle_send()
{
    const auto in_flight_n = send_.nxt() - send_.una();
    const auto send_buf_bytes = send_buf_.size_bytes();

    assert(in_flight_n <= send_buf_bytes);

    const auto unsent = static_cast<std::uint32_t>(send_buf_bytes) - in_flight_n;
    // unsent may actually be more than there are payload bytes, but IDC because it won't send more that there are bytes anyhow
    if (unsent > 0 && send_.wnd() > 0) {
        // Sender SWS
        const auto usable_wnd = send_.wnd() - in_flight_n;
        // const auto bytes_to_send = std::min({ static_cast<std::size_t>(send_mss_), send_buf_.size() - in_flight_n,
                                              // static_cast<std::size_t>(send_.wnd - in_flight_n) });
        const auto bytes_to_send = std::min<std::size_t>({send_mss_, unsent, usable_wnd});
        if (bytes_to_send == 0) {
            return true;
        }

        // TODO: PUSH flag in segments
        // FIXME: SND.NXT == SND.UNA is a NAGLE condition. I should let user disable NAgle so this cond. isnt enforced
        bool can_send = (std::min(usable_wnd, unsent) >= send_mss_) || (send_.nxt() == send_.una() && unsent <= usable_wnd)
                        || (send_.nxt() == send_.una() && std::min(unsent, usable_wnd) >= send_wnd_max_ / 2);
        if (can_send) {
            s_timer_.stop();

            std::println("SWS SEnding: {} {} {} {}, flight: {}",
                send_buf_bytes,
                usable_wnd,
                bytes_to_send,
                unsent,
                in_flight_n);

            // tcph_.ack(true); // ACK is supposed to be already set in all data segments
            // send(send_.nxt(), bytes_to_send);
            send_data(1ul, bytes_to_send);
        } else {
            std::println("Start SWS override timer. send nxt: {}, send una: {}, data len {}", send_.nxt(), send_.una(), bytes_to_send);

            const auto& seg = send_buf_.find(send_.nxt());
            s_timer_.start(clock_->now(), RttMeasurement::SWS_OVERRIDE_MS, seg.seq_start(),
                static_cast<std::uint32_t>(bytes_to_send));
        }
    }
    return true;
}

void TcpConnection::on_tick()
{
    update_timers();
    // First, deal with window stuff (zero window, to be exact) and then handle send
    update_recv_window();
    update_send_window();

    if (!handle_send()) { return; }
}

ssize_t TcpConnection::send_data(const int segs, const std::size_t max_size_pl)
{
    ssize_t total_written_pl = 0;
    bool rtt_started = false;

    for (auto i = 0; i < segs && total_written_pl <= static_cast<ssize_t>(max_size_pl); ++i) {
        // Same goes for settings SND.NXT evry time
        TcpSegment& seg = send_buf_.at(i);
        seg.set_ackn(recv_.nxt());

        update_recv_window();

        const auto wnd_to_adv = static_cast<std::uint16_t>(recv_.wnd());
        const auto to_send_max = std::min(seg.payload_size(), max_size_pl - static_cast<std::size_t>(total_written_pl));
        const auto written_bytes = output_.send(seg, to_send_max, wnd_to_adv);
        total_written_pl += to_send_max;

        const auto data_size = seg.size_in_seq();
        const auto time_now = clock_->now();
        if (wrapping_gt(seg.seq_start(), send_.nxt() - 1) && !rtt_started) {
            // Karn algorithm says that you shouldn't measure RTT on retransmitted segments, so this send is not retranmitting if and only if SEG.SEQ >= SND.NXT
            rtt_measurement_.start(time_now, seg.seq_start());
            rtt_started = true;
        }

        if (wrapping_gt(seg.seq_start() + static_cast<std::uint32_t>(data_size), send_.nxt() - 1)) {
            send_.set_nxt(send_.nxt() + (seg.seq_start() + static_cast<std::uint32_t>(data_size) - send_.nxt()));
        }

        // This is kinda weird, but I have no idea where else to place this
        switch (state_) {
            case TcpState::CLOSE_WAIT: {
                if (seg.fin()) {
                    state_ = TcpState::LAST_ACK;
                }
                break;
            }
            case TcpState::ESTAB: {
                if (seg.fin()) {
                    state_ = TcpState::FIN_WAIT_1;
                }
                break;
            }
            default: break;
        }
    }

    if (!z_timer_.is_armed()) {
        const auto time_now = clock_->now();
        // Should not run while ZWP is active
        const auto& seg = send_buf_.find(send_.una());
        r_timer_.start(time_now, rtt_measurement_.rto(), seg.seq_start(),
        static_cast<std::uint32_t>(seg.payload_size()));
    }

    return total_written_pl;
}

ssize_t TcpConnection::send_pure(const TcpSegment &seg)
{
    update_recv_window();
    const auto wnd_to_adv = static_cast<std::uint16_t>(recv_.wnd());
    return output_.send(seg, 0, wnd_to_adv);
}

ssize_t TcpConnection::send_retransmit(const TcpSegment &retrans_seg)
{
    update_recv_window();
    const auto wnd_to_adv = static_cast<std::uint16_t>(recv_.wnd());
    return output_.send(retrans_seg, retrans_seg.size_in_seq(), wnd_to_adv);
}


void TcpConnection::open_passive(const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
{
    output_.init_headers(iph.dest_addr(), iph.source_addr(), tcph.dest_port(), tcph.source_port());

    // 3.10.7.2. LISTEN STATE
    if (tcph.rst()) {
        // RST should be ignored at this point, since connection doesn't even exist yet. So this RST is a creepy one :/
        return;
    }

    // Second, check for an ACK:
    if (tcph.ack()) {
        // ACK shouldn't be set in initial SYN segment
        std::println("RST IS SET IN ACCEPT");

        TcpSegment rst_seg{tcph.ackn(), {}};
        rst_seg.set_rst(true);
        send_pure(rst_seg);
        // tcph_.rst(true);
        // send(tcph.ackn(), 0);
        return;
    }

    // Third, check for a SYN
    if (tcph.syn()) {
        recv_.set_nxt(tcph.seqn() + 1);
        recv_.set_irs(tcph.seqn());
        // recv_.wnd()= recv_mss_ * 3;
        recv_.set_wnd(std::numeric_limits<std::uint16_t>::max());

        if (auto opt = tcph.mss(); opt.has_value()) { send_mss_ = opt.value().mss; }
        // send_.wnd = tcph.window();
        send_.set_wnd(tcph.window());

        // SEt ISS
        std::random_device rnd;
        std::mt19937 gen(rnd());
        std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(),
            std::numeric_limits<std::uint32_t>::max());
        auto iss = dis(gen);
        // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

        output_.set_mss(recv_mss_); // FIXME: SHOULD I SEND IT IF THAT PEER DID NOT HAVE THIS????

        TcpSegment synack_seg{iss, {}, true};
        synack_seg.set_ack(true);
        synack_seg.set_ackn(recv_.nxt());
        send_buf_.insert(synack_seg); // Put it onto retrans. queue

        // tcph_.options().mss(recv_mss_);
        // tcph_.window(static_cast<std::uint16_t>(recv_.wnd())); // FIXME: Won't update_recv_window fuck this up
        // tcph_.syn(true);
        // tcph_.ack(true);

        send_.set_iss(iss);
        send_.set_una(iss);
        send_.set_nxt(iss);// 1 goes for SYN (in send()), since it uses up a SEQ number
        send_data(1, 0);
        // send(iss, 0);

        output_.clear_options();
        state_ = TcpState::SYN_RCVD;
    }
}

void TcpConnection::open_active(const std::uint32_t saddr,
    const std::uint16_t sport,
    const std::uint32_t daddr,
    const std::uint16_t dport)
{
    std::random_device rnd;
    std::mt19937 gen(rnd());
    std::uniform_int_distribution<std::uint32_t> dis(std::numeric_limits<std::uint32_t>::min(),
        std::numeric_limits<std::uint32_t>::max());

    const auto iss = dis(gen);

    output_.init_headers(saddr, daddr, sport, dport);

    output_.set_mss(recv_mss_);
    // tcph_.options().mss(recv_mss_);

    TcpSegment seg{iss, {}, true};
    send_buf_.insert(seg);

    send_.set_iss(iss);
    send_.set_una(iss);
    send_.set_nxt(iss);// +1 is in send()

    recv_.set_wnd(std::numeric_limits<std::uint16_t>::max());
    send_.set_wnd(send_mss_);

    send_data(1, 0);

    output_.clear_options();
    state_ = TcpState::SYN_SENT;
}

void TcpConnection::retransmit(Timer& timer)
{
    // Retransmission should happen
    rtt_measurement_.stop();// Must not measure on retransmits

    // (5.4) Retransmit the earliest segment that has not been acknowledged by the TCP receiver.
    TcpSegment& retrans_seg = send_buf_.find(timer.start_seq());
    retrans_seg.set_ackn(recv_.nxt());
    send_retransmit(retrans_seg);

    timer.retransmitted(clock_->now(), send_.una());
}

void TcpConnection::update_timers()
{
    const auto time_now = clock_->now();
    const bool should_retrans = r_timer_.update(time_now, rtt_measurement_.rto(), send_.nxt(), send_.una());
    if (should_retrans) {
        retransmit(r_timer_);
    }
    const bool should_zwp = z_timer_.update(time_now);
    if (should_zwp) {
        retransmit(z_timer_);
    }
    const bool should_sws = s_timer_.update(time_now);
    if (should_sws) {
        retransmit(s_timer_);
    }
}

void TcpConnection::shutdown(ShutdownType sht)
{
    if (sht == ShutdownType::WRITE) {
        add_fin_segment();
    } else {
        throw std::runtime_error("This shutdown type is not impl");
    }
}

void TcpConnection::close()
{
    // So at this point we wanna send a FIN segment
    add_fin_segment();
}

ssize_t TcpConnection::read(void *buf, const std::size_t buf_size)
{
    // If user hasn't read everything yet, delay signaling FIN
    if (is_finished_ && !recv_buf_.empty()) { return 0; }

    const auto bytes_copy = std::min(buf_size, recv_buf_.size());
    std::println("bytes copy: {}", bytes_copy);
    if (bytes_copy > 0) {
        std::memcpy(buf, recv_buf_.data(), bytes_copy);
        erase_recv_data(bytes_copy);
    }
    return static_cast<ssize_t>(bytes_copy);
}

ssize_t TcpConnection::write(std::span<const std::byte> buf)
{
    const auto insert_bytes_n = std::min(send_buf_free_space(), buf.size());
    switch (state_) {
    case TcpState::SYN_SENT:
    case TcpState::SYN_RCVD:
    case TcpState::ESTAB:
    case TcpState::CLOSE_WAIT: {
        std::span<const std::byte> data{buf.data(), insert_bytes_n};

        // Fill unsent back segment up to MSS first
        if (!send_buf_.empty() && send_buf_.back().seq_start() >= send_.nxt()) {
            const auto space_left = send_mss_ - send_buf_.back().payload_size();
            const auto to_append = std::min(space_left, data.size());
            send_buf_.append_back(data.subspan(0, to_append));
            data = data.subspan(to_append);
        }

        // Write remaining data as new MSS-sized segments
        while (!data.empty()) {
            const auto seg_size = std::min<std::size_t>(send_mss_, data.size());

            const uint32_t seq_start = send_buf_.empty()
                ? send_.nxt()
                : send_buf_.back().seq_end();

            TcpSegment seg{seq_start, data.subspan(0, seg_size)};
            seg.set_ack(true);
            const auto res = send_buf_.insert(seg);
            assert(res);

            data = data.subspan(seg_size);
        }
        break;
    }
    default:
        throw std::runtime_error("error: connection is closing");
    }

    return static_cast<ssize_t>(insert_bytes_n);
}
