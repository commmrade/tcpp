//
// Created by klewy on 4/23/26.
//

#include "buffer.hpp"
#include <stdexcept>
#include <algorithm>

bool TcpBuffer::insert(const TcpSegment &seg)
{
    // 1. Iterate through segments and compare sequence numbers
    // 2. If it is THE segment, append data

    // TODO: Make sure seg.seq_end is < next_iter->seq_start
    const auto seq_n = seg.seq_start();
    auto iter = segs_.begin();
    while (iter != segs_.end()) {
        // It is usually the case for Receiver Queue
        if (seq_n < iter->seq_start()) {
            // Inserts before
            segs_.insert(iter, seg);
            return true;
            break;
        } else if (seq_n == iter->seq_start()) {
            return false;
            // return; // Such segment already exists, wtf?
        }
        ++iter;
    }

    if (iter == segs_.end()) {
        // We did not find a place for this segment, which means it is in-order
        segs_.push_back(seg);
        // Insert a new one
        return true;
    }
    return false;
}

std::size_t TcpBuffer::consume_seq(const std::uint32_t seq_range_to)
{
    std::size_t res = 0;
    auto iter = segs_.begin();
    while (iter != segs_.end()) {
        auto old_iter = iter;
        ++iter;

        if (seq_range_to >= old_iter->seq_end()) {
            res += old_iter->size_in_seq();
            segs_.erase(old_iter);
        } else if (seq_range_to >= old_iter->seq_start() && seq_range_to < old_iter->seq_end()) {
            // Erase inside a segment
            const auto to_idx = seq_range_to - old_iter->seq_start();
            const auto payload_size = old_iter->payload_size();
            // Since we use payload_size() special handling for SYN/FIN is not needed, if this is a data segment,
            // to_erase_n will be empty, so all good.

            // FIXME: I think handling SYN/FIN requires special care, what if range_to points to a no-data segment, but with SYN/FIN
            const auto to_erase_n = std::min<std::size_t>(to_idx, payload_size);// In case this segment contains SYN/FIN
            res += to_erase_n;
            old_iter->erase(to_erase_n);
            // old_iter->set_seq_start(range_to);
        }
    }
    return res;
}


TcpSegment &TcpBuffer::at(const std::ptrdiff_t idx)
{
    assert(static_cast<std::size_t>(idx) < segs_.size());

    auto iter = segs_.begin();
    return *std::next(iter, static_cast<std::ptrdiff_t>(idx));
}

TcpSegment &TcpBuffer::find(const std::uint32_t seq)
{
    auto iter = std::find_if(segs_.begin(),
        segs_.end(),
        [seq](const TcpSegment &seg) { return seg.seq_start() == seq; });
    assert(iter != segs_.end());
    return *iter;
}

std::size_t TcpBuffer::size_segs() const { return segs_.size(); }

std::size_t TcpBuffer::size_bytes() const
{
    std::size_t res = 0;
    auto iter = segs_.cbegin();
    for (; iter != segs_.end(); ++iter) { res += iter->size_in_seq(); }
    return res;
}

std::size_t TcpBuffer::size_payload_bytes() const
{
    std::size_t res = 0;
    auto iter = segs_.cbegin();
    for (; iter != segs_.cend(); ++iter) { res += iter->payload_size(); }
    return res;
}

void TcpSenderBuffer::append_back(std::span<const std::byte> payload)
{
    if (empty()) { throw std::out_of_range{ "You cannot append, when there is no segments in this buffer" }; }
    segs_.back().append(payload);
}

std::pair<std::vector<std::byte>, std::uint32_t> TcpReceiverBuffer::read(const std::size_t max_size, const std::uint32_t recv_nxt)
{
    std::vector<std::byte> res;
    if (empty()) { return {res, 0}; }
    res.reserve(max_size);

    auto iter = segs_.cbegin();
    auto to_read = max_size;
    auto current_read_seq = iter->seq_start();

    if (current_read_seq >= recv_nxt) {
        // This means that buffer contains only out-of-order segments.
        return {res, current_read_seq};
    }

    while (iter != segs_.end() &&
           to_read > 0 &&
           (current_read_seq < recv_nxt && current_read_seq == iter->seq_start())) {
        const auto read_n = std::min(to_read, iter->payload_size());
        const auto pload = iter->payload();

        std::copy(pload.begin(), pload.begin() + static_cast<std::ptrdiff_t>(read_n), std::back_inserter(res));

        to_read -= read_n;
        // If we read whole segment, then also skip SYN/FIN that there may be
        current_read_seq += (read_n == iter->payload_size()) ? iter->size_in_seq() : read_n;
        ++iter;
    }

    return {res, current_read_seq};
}

std::uint32_t TcpReceiverBuffer::check_gaps(const std::uint32_t recv_nxt) const
{
    // My idea is that it is gonna iterate through consequential segments until it finds a gap or comes to the end and return that seq. num which will be new RECV.NXT
    if (empty()) {
        return recv_nxt;
    }
    auto iter = segs_.cbegin();
    if (iter->seq_start() > recv_nxt) {
        // This means that even the first segment's seq_start is more than recv_nxt which means that there is an unfilled gap
        // == is fine, because that just means that it kinda filled a gap just now
        return recv_nxt;
    }

    auto cur_seq = iter->seq_start();
    // It loops until it finds a segment, that is out of order and the gap is not filled
    while (iter != segs_.end() && cur_seq == iter->seq_start()) {
        cur_seq += iter->size_in_seq();
        ++iter;
    }
    return cur_seq;
}
