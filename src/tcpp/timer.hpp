//
// Created by klewy on 4/15/26.
//

#ifndef TCPP_TIMER_HPP
#define TCPP_TIMER_HPP

#include <cstdint>
#include <optional>
#include "util.hpp"

class RttMeasurement
{
public:
    constexpr static std::uint32_t DEFAULT_RTO_MS = 1000;
    constexpr static std::uint32_t MAX_RTO_MS = 60'000;
    constexpr static std::uint32_t SWS_OVERRIDE_MS = 100;// 0.1...1.0

    void reset();

    void start_measure(const std::int64_t now_ms, const std::uint32_t seq_n);
    void stop_measure() { send_at_.reset(); }

    void update(const std::int64_t cur_time, const std::uint32_t ack_n);

    std::uint32_t rto() const
    {
        return rto_ms_;
    }
    void rto(const std::uint32_t rto_ms)
    {
        rto_ms_ = rto_ms;
    }
private:
    std::optional<std::int64_t> send_at_;// Time at which oldest UNACKed segment was sent.
    std::uint32_t send_seq_at_;// Seq n at which send_at_ segmetn was sent

    std::uint32_t rtt_ms_{};
    std::uint32_t srtt_{};// Smothed round-trip time
    std::uint32_t rttvar_{};// round-trip time variation
    std::uint32_t rto_ms_{ DEFAULT_RTO_MS };// Default RTO is 1 (1000ms) second, as per RFC 6298
};

class Timer
{
public:
    virtual ~Timer() = default;

    [[nodiscard]] bool is_armed() const { return start_time_.has_value(); }

    void start(const std::uint32_t seq_n,
     const std::uint32_t data_len,
     const std::uint32_t rto_ms,
     const std::int64_t cur_time);
    void stop();

    virtual void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) = 0;

    std::uint32_t start_seq() const
    {
        return start_seq_at_;
    }
    std::uint32_t data_len() const
    {
        return data_length_;
    }
protected:
    std::optional<std::int64_t> start_time_{};
    std::uint32_t start_seq_at_{};
    std::uint32_t data_length_{};// Payload length
    std::int64_t expire_at_time_{ -1 };
    std::optional<std::uint32_t> rto_ms_;
};

struct RetransTimer : public Timer
{
    bool update(const std::uint32_t send_nxt, const std::uint32_t ack_n, const std::int64_t cur_time_ms, const std::uint32_t rto_ms);
    void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) override;
};

struct ZwpTimer : public Timer
{
    bool update(const std::int64_t cur_time_ms);
    void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) override;
};

struct SwsTimer : public Timer
{
    bool update(const std::int64_t cur_time_ms);
    void retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) override;
};



#endif //TCPP_TIMER_HPP