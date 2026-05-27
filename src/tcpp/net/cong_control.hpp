//
// Created by klewy on 5/27/26.
//

#ifndef TCPP_CONG_CONTROL_HPP
#define TCPP_CONG_CONTROL_HPP
#include "conn.hpp"

#include <cstddef>

namespace netparser {
class TcpHeaderView;
}

class CongestionControl
{
private:
    bool is_dup_ack(const netparser::TcpHeaderView &tcph, const std::size_t pl_size, const SendSequence &seq);

    void on_fast_recovery(const std::uint32_t ackn, const SendSequence &seq, const std::uint32_t send_mss);

    void on_slow_start(const std::uint32_t ackn, const std::uint32_t snd_una, const std::uint32_t send_mss);

    void on_cong_avoidance(const std::uint32_t send_mss);

public:
    std::uint32_t get_cwnd() const { return cwnd_; }
    void set_cwnd(const std::uint32_t cwnd) { cwnd_ = cwnd; }

    std::uint32_t get_ssthresh() const { return ssthresh_; }
    void set_ssthresh(const std::uint32_t ssth) { ssthresh_ = ssth; }

    int dup_acks() const { return dup_acks_; }

    void set_last_window(const std::uint32_t win) { last_window_ = win; }

    void on_ack(const netparser::TcpHeaderView &tcph,
        const std::size_t pl_size,
        const SendSequence &send,
        const std::uint32_t send_mss);

    void init(const std::uint32_t send_mss);

    void retransmitted(const std::uint32_t send_mss, const std::uint32_t nxt, const std::uint32_t una);

private:
    std::uint32_t cwnd_;
    std::uint32_t ssthresh_;

    std::uint32_t last_window_{ 0 };
    int dup_acks_{ 0 };
};


#endif //TCPP_CONG_CONTROL_HPP