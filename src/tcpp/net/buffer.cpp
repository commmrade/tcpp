//
// Created by klewy on 4/23/26.
//

#include "buffer.hpp"

// This should only be used for NAGLE?? Like when it is enabled and a segment is kinda small, so instead of creating a new node, you can append payload to the already existing node
void TcpBuffer::append_back(std::span<const std::byte> payload)
{
    if (empty()) {
        throw std::out_of_range{"You cannot append, when there is no segments in this buffer"};
    }
    segs_.back().append(payload);
}

bool TcpBuffer::insert(const TcpSegment &seg) {
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

    if (iter == segs_.end()) { // We did not find a place for this segment, which means it is in-order
        segs_.push_back(seg);
        // Insert a new one
        return true;
    }
    return false;
}

std::size_t TcpBuffer::consume(const std::uint32_t range_to) {
    std::size_t res = 0;
    auto iter = segs_.begin();
    while (iter != segs_.end()) {
        auto old_iter = iter;
        ++iter;

        if (range_to >= old_iter->seq_end()) {
            res += old_iter->size_in_seq();
            segs_.erase(old_iter);
        } else if (range_to >= old_iter->seq_start() && range_to < old_iter->seq_end()) {
            // Erase inside a segment
            const auto to_idx = range_to - old_iter->seq_start();
            const auto payload_size = old_iter->payload_size();
            // Since we use payload_size() special handling for SYN/FIN is not needed, if this is a data segment,
            // to_erase_n will be empty, so all good.

            // FIXME: I think handling SYN/FIN requires special care, what if range_to points to a no-data segment, but with SYN/FIN
            const auto to_erase_n = std::min<std::size_t>(to_idx, payload_size); // In case this segment contains SYN/FIN
            res += to_erase_n;
            old_iter->erase(to_erase_n);
            old_iter->set_seq_start(range_to);
        }
    }
    return res;
}

TcpSegment & TcpBuffer::at(const std::ptrdiff_t idx) {
    assert(static_cast<std::size_t>(idx) < segs_.size());

    auto iter = segs_.begin();
    return *std::next(iter, static_cast<std::ptrdiff_t>(idx));
}

TcpSegment& TcpBuffer::find(const std::uint32_t seq)
{
    auto iter = std::find_if(segs_.begin(), segs_.end(), [seq](const TcpSegment& seg) {
        return seg.seq_start() == seq;
    });
    assert(iter != segs_.end());
    return *iter;
}


std::vector<std::byte> TcpBuffer::read(const std::size_t len) {
    std::vector<std::byte> res;
    if (empty()) {
        return res;
    }

    res.reserve(len);
    auto iter = segs_.cbegin();
    auto to_read = len;
    auto seq_read = front().seq_start();

    while (iter != segs_.cend() && to_read > 0) {
        if (seq_read >= iter->seq_start() && seq_read < iter->seq_start() + iter->payload_size()) {
            const auto idx = seq_read - iter->seq_start();
            const auto read_n = std::min(to_read, iter->payload_size() - idx);

            const auto pload = iter->payload();
            const auto from = pload.begin() + idx;
            const auto to = from + static_cast<std::ptrdiff_t>(read_n);
            std::copy(from, to, std::back_inserter(res));

            to_read -= read_n;
            seq_read += read_n;
        }
        // TODO: Should this also consume()??
        // FIXME: Does SYN/FIN no data segments require special handling?
        ++iter;
    }
    return res;
}

std::vector<std::byte> TcpBuffer::read(const std::uint32_t seq_n, const std::size_t len)
{
    std::vector<std::byte> res;
    if (empty()) {
        return res;
    }

    res.reserve(len);
    auto iter = segs_.cbegin();
    auto to_read = len;
    auto seq_read = seq_n;

    while (iter != segs_.cend() && to_read > 0) {
        if (seq_read >= iter->seq_start() && seq_read < iter->seq_start() + iter->payload_size()) {
            const auto idx = seq_read - iter->seq_start();
            const auto read_n = std::min(to_read, iter->payload_size() - idx);

            const auto pload = iter->payload();
            const auto from = pload.begin() + idx;
            const auto to = from + static_cast<std::ptrdiff_t>(read_n);
            std::copy(from, to, std::back_inserter(res));

            to_read -= read_n;
            seq_read += read_n;
        }
        // TODO: Should this also consume()??
        // FIXME: Does SYN/FIN no data segments require special handling?
        ++iter;
    }
    return res;
}

std::size_t TcpBuffer::size_segs() const {
    return segs_.size();
}

std::size_t TcpBuffer::size_bytes() const {
    std::size_t res = 0;
    auto iter = segs_.cbegin();
    for (; iter != segs_.end(); ++iter) {
        res += iter->size_in_seq();
    }
    return res;
}

std::size_t TcpBuffer::size_payload_bytes() const {
    std::size_t res = 0;
    auto iter = segs_.cbegin();
    for (; iter != segs_.cend(); ++iter) {
        res += iter->payload_size();
    }
    return res;
}