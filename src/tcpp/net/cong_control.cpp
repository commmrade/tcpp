//
// Created by klewy on 5/27/26.
//

#include "cong_control.hpp"
#include "sequence.hpp"
#include "../../netparser/netparser.hpp"
#include "../util.hpp"

bool CongestionControl::is_dup_ack(const netparser::TcpHeaderView &tcph,
    const std::size_t pl_size,
    const SendSequence &seq)
{
    if (seq.una() != seq.nxt() &&
        pl_size == 0 &&
        (!tcph.syn() && !tcph.fin()) &&
        tcph.ackn() == seq.una() &&
        tcph.window() == last_window_) { return true; }
    return false;
}

void CongestionControl::on_fast_recovery(const std::uint32_t ackn,
    const SendSequence &seq,
    const std::uint32_t send_mss)
{
    if (wrapping_gt(ackn, seq.una()) && dup_acks_ > 0) {
        if (dup_acks_ >= 3) {
            // We were in a fast recovery state
            cwnd_ = ssthresh_;
        }
        dup_acks_ = 0;
    }

    if (dup_acks_ == 3) {
        const auto in_flignt = seq.nxt() - seq.una();
        ssthresh_ = std::max(in_flignt / 2, 2 * send_mss);
        cwnd_ = ssthresh_ + 3 * send_mss;
    } else if (dup_acks_ > 3) { cwnd_ += send_mss; }
}

void CongestionControl::on_slow_start(const std::uint32_t ackn,
    const std::uint32_t snd_una,
    const std::uint32_t send_mss)
{
    const auto acked_bytes = ackn - snd_una;
    cwnd_ += std::min<std::uint32_t>(acked_bytes, send_mss);
}

void CongestionControl::on_cong_avoidance(const std::uint32_t send_mss)
{
    const auto increased_bytes = std::max<std::uint32_t>(send_mss * send_mss / cwnd_, 1);
    // If 0, SHOULD be rounded to 1
    cwnd_ += increased_bytes;
}

void CongestionControl::on_ack(const netparser::TcpHeaderView &tcph,
    const std::size_t pl_size,
    const SendSequence &send,
    const std::uint32_t send_mss)
{
    if (is_dup_ack(tcph, pl_size, send)) { ++dup_acks_; }

    if (dup_acks_ < 3 && wrapping_gt(tcph.ackn(), send.una())) {
        if (cwnd_ < ssthresh_) { on_slow_start(tcph.ackn(), send.una(), send_mss); } else {
            on_cong_avoidance(send_mss);
        }
    }

    if (dup_acks_ > 0) { on_fast_recovery(tcph.ackn(), send, send_mss); }

    last_window_ = tcph.window();
}

void CongestionControl::init(const std::uint32_t send_mss)
{
    ssthresh_ = std::numeric_limits<std::uint16_t>::max();
    const auto smss = std::max<std::uint16_t>(536, static_cast<std::uint16_t>(send_mss));
    if (smss > 2190) { cwnd_ = 2 * send_mss; } else if (
        smss > 1095 && smss <= 2190) { cwnd_ = 3 * send_mss; } else if (smss <= 1095) { cwnd_ = 4 * send_mss; }
}

void CongestionControl::retransmitted(const std::uint32_t send_mss, const std::uint32_t nxt, const std::uint32_t una)
{
    const auto in_flight = nxt - una;
    ssthresh_ = std::max<std::uint32_t>(in_flight / 2, send_mss * 2);
    cwnd_ = send_mss;
}