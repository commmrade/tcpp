//
// Created by klewy on 4/15/26.
//

#include "timer.hpp"

void RttMeasurement::reset() {
    rttvar_ = 0;
    srtt_ = 0;
}

void RttMeasurement::start(const std::int64_t now_ms, const std::uint32_t seq_n) {
    if (!send_at_.has_value()) {
        send_seq_at_ = seq_n;
        send_at_ = now_ms;
    }
}

void RttMeasurement::update(const std::int64_t now_ms, const std::uint32_t ack_n) {
    if (send_at_.has_value() && wrapping_gt(ack_n, send_seq_at_)) {
        const std::int64_t res = now_ms - send_at_.value();// cur. rtt

        static constexpr std::uint32_t GRAN_MS = 1;
        if (rtt_ms_ == 0) {
            // First measurement
            srtt_ = static_cast<std::uint32_t>(res);
            rttvar_ = static_cast<std::uint32_t>(res / 2);
        } else {
            // Following measurements
            static constexpr double ALPHA = 1.0 / 8.0;
            static constexpr double BETA = 1.0 / 4.0;
            rttvar_ = static_cast<std::uint32_t>(
                (1.0 - BETA) * static_cast<double>(rttvar_) + BETA * std::abs(
                    static_cast<double>(srtt_) - static_cast<double>(res)));
            srtt_ = static_cast<std::uint32_t>(
                (1.0 - ALPHA) * static_cast<double>(srtt_) + ALPHA * static_cast<double>(
                    res));
        }
        rto_ms_ = srtt_ + std::max(GRAN_MS, 4 * rttvar_);
        // Whenever RTO is computed, if it is less than 1 second,
        // then the RTO SHOULD be rounded up to 1 second
        rto_ms_ = std::max(rto_ms_, RttMeasurement::DEFAULT_RTO_MS);

        rtt_ms_ = static_cast<std::uint32_t>(res);

        send_at_.reset();
    }
}

void Timer::start(const std::int64_t cur_time,
        const std::uint32_t rto_ms,
        const std::uint32_t seq_n,
        const std::uint32_t data_len) {
    if (!start_time_.has_value()) {
        start_time_.emplace(cur_time);// Start timer
        expire_at_time_.emplace(cur_time + static_cast<std::int64_t>(rto_ms));// It expires at RTO
        start_seq_at_ = seq_n;
        data_length_ = data_len;
        rto_ms_.emplace(rto_ms);
    }
}

void Timer::stop() {
    start_time_.reset();
    expire_at_time_.reset();
}

bool RetransTimer::update(const std::uint32_t send_nxt,
    const std::uint32_t ack_n,
    const std::int64_t cur_time_ms,
    const std::uint32_t rto_ms) {
    if (start_time_.has_value()) {
        if (ack_n >= send_nxt && is_armed()) {
            std::println("All outstanding data ACKED. Disable timer");
            // (5.2) When all outstanding data has been acknowledged, turn off the retransmission timer.
            stop();
        } else if (wrapping_gt(ack_n, start_seq_at_) &&
                   is_armed()) {
            // Window was moved, restart timer
            // (5.3) When an ACK is received that acknowledges new data, restart the retransmission timer so that it will expire
            // after RTO seconds (for the current value of RTO).
            std::println("Window moved. Restart the timer");

            // Restart
            stop();
            start(cur_time_ms, rto_ms, ack_n, data_length_);
        } else {
            // timer is neither updated nor disabled
            if (cur_time_ms >= expire_at_time_.value()) {
                // handle_timer_retransmit();
                return true; // should retransmit
            }
        }
    }
    return false;
}

void RetransTimer::retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) {
    // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
    // maximum value discussed in (2.5) above may be used to provide
    // an upper bound to this doubling operation.
    rto_ms_ = rto_ms_.value() * 2;

    // These values are likely bogus after several backoffs (3)
    constexpr std::uint32_t BACKOFF_THRESHOLD = 10000;
    rto_ms_ = std::min(rto_ms_.value(), RttMeasurement::MAX_RTO_MS);

    //  (5.6) Start the retransmission timer, such that it expires after RTO
    //  seconds
    stop();
    start(cur_time, rto_ms_.value(), send_una, data_length_);
}

bool ZwpTimer::update(const std::int64_t cur_time_ms) {
    if (start_time_.has_value()) {
        // timer is neither updated nor disabled
        if (cur_time_ms >= expire_at_time_.value()) {
            // handle_timer_retransmit();
            return true; // should retransmit
        }
    }
    return false;
}

void ZwpTimer::retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) {
    // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
    // maximum value discussed in (2.5) above may be used to provide
    // an upper bound to this doubling operation.
    rto_ms_ = rto_ms_.value() * 2;

    // These values are likely bogus after several backoffs (3)
    constexpr std::uint32_t BACKOFF_THRESHOLD = 10000;
    rto_ms_ = std::min(rto_ms_.value(), RttMeasurement::MAX_RTO_MS);

    //  (5.6) Start the retransmission timer, such that it expires after RTO
    //  seconds
    stop();
    start(cur_time, rto_ms_.value(),  send_una, data_length_);
}

bool SwsTimer::update(const std::int64_t cur_time_ms) {
    if (start_time_.has_value()) {
        // timer is neither updated nor disabled
        if (cur_time_ms >= expire_at_time_.value()) {
            // handle_timer_retransmit();
            return true; // should retransmit
        }
    }
    return false;
}

void SwsTimer::retransmitted(const std::uint32_t send_una, const std::int64_t cur_time) {
    // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
    // maximum value discussed in (2.5) above may be used to provide
    // an upper bound to this doubling operation.
    rto_ms_ = rto_ms_.value() * 2;

    // These values are likely bogus after several backoffs (3)
    constexpr std::uint32_t BACKOFF_THRESHOLD = 10000;
    rto_ms_ = std::min(rto_ms_.value(), RttMeasurement::MAX_RTO_MS);

    //  (5.6) Start the retransmission timer, such that it expires after RTO
    //  seconds
    stop();
    // Sws timer does not exp. backoff
}
