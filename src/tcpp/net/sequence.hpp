//
// Created by klewy on 6/6/26.
//

#ifndef TCPP_SEQUENCE_HPP
#define TCPP_SEQUENCE_HPP
#include <algorithm>
#include <cstddef>
#include <cstdint>

class SendSequence
{
public:
    [[nodiscard]] std::uint32_t wnd() const { return wnd_; }

    void set_wnd(const std::uint32_t wnd)
    {
        wnd_max_ = std::max(wnd_max_, wnd);
        wnd_ = wnd;
    }

    [[nodiscard]] std::uint32_t nxt() const { return nxt_; }
    void set_nxt(const std::uint32_t nxt) { nxt_ = nxt; }

    [[nodiscard]] std::uint32_t una() const { return una_; }
    void set_una(const std::uint32_t una) { una_ = una; }

    [[nodiscard]] std::uint32_t iss() const { return iss_; }
    void set_iss(const std::uint32_t iss) { iss_ = iss; }

    [[nodiscard]] std::uint32_t wl1() const { return wl1_; }
    void set_wl1(const std::uint32_t wl1) { wl1_ = wl1; }

    [[nodiscard]] std::uint32_t wl2() const { return wl2_; }
    void set_wl2(const std::uint32_t wl2) { wl2_ = wl2; }

private:
    std::uint32_t una_;// send unack'ed
    std::uint32_t nxt_;// send next
    std::uint32_t wnd_;// send window size. It is recommended to use 32 bit int for WND
    std::uint16_t up_;// urgent pointer
    std::uint32_t wl1_;// segment sequence number used for last window update
    std::uint32_t wl2_;// segment acknowledgment number used for last window update
    std::uint32_t iss_;// initial sequence number

    std::uint32_t wnd_max_;
};

struct ReceiveSequence
{
public:
    void set_wnd(const std::uint32_t wnd)
    {
        wnd_ = wnd;
        right_wnd_edge_ = nxt_ + wnd;
    }

    [[nodiscard]] std::uint32_t wnd() const { return right_wnd_edge_ - nxt_; }
    [[nodiscard]] std::uint32_t nxt() const { return nxt_; }
    void set_nxt(const std::uint32_t nxt) { nxt_ = nxt; }

    void set_irs(const std::uint32_t irs) { irs_ = irs; }

    void set_ts_recent(const std::uint32_t val) { ts_recent_ = val; }
    std::uint32_t ts_recent() const { return ts_recent_; }
    void set_last_ack(const std::uint32_t val) { last_ack_sent_ = val; }
    std::uint32_t last_ack() const { return last_ack_sent_; }

private:
    std::uint32_t nxt_;// next to receive, which is +1 byte. so this equals to the next seqn that is expected
    std::uint32_t wnd_;// receiver window size. It is recommended to use 32 bit int for WND
    std::uint16_t up_;// urgent pointer
    std::uint32_t irs_;// initial receiver seq n

    std::uint32_t ts_recent_{};
    std::uint32_t last_ack_sent_{};

    std::uint32_t right_wnd_edge_;
};

#endif //TCPP_SEQUENCE_HPP