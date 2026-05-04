//
// Created by klewy on 4/23/26.
//

#ifndef TCPP_BUFFER_HPP
#define TCPP_BUFFER_HPP
#include "buffer.hpp"

#include <cassert>
#include <cstddef>
#include <list>
#include <cstdint>
#include <cstring>
#include <vector>
#include <span>

class TcpSegment
{
    friend class TcpBuffer;
    friend class TcpSenderBuffer;
    friend class TcpSegmentTest;
private:
    void set_syn(bool val)
    {
        if (!syn_ && val) {
            ++end_seq_n_;
        } else if (syn_ && !val) {
            --end_seq_n_;
        }

        syn_ = val;
    }
    void set_fin(bool val)
    {
        if (!fin_ && val) {
            ++end_seq_n_;
        } else if (fin_ && !val) {
            --end_seq_n_;
        }

        fin_ = val;
    }
    void append(std::span<const std::byte> payload)
    {
        payload_.append_range(payload);
        end_seq_n_ += payload.size();
    }
    void erase(const std::size_t range_to)
    {
        assert(range_to <= payload_.size());
        payload_.erase(payload_.begin(), payload_.begin() + static_cast<std::ptrdiff_t>(range_to));
        seq_n_ += range_to;
    }
    void set_seq_start(const std::uint32_t seq)
    {
        seq_n_ = seq;
    }
    void set_seq_end(const std::uint32_t seq)
    {
        end_seq_n_ = seq;
    }
public:
    TcpSegment(const std::uint32_t seq_start, std::span<const std::byte> payload, bool syn = false, bool fin = false)
        : payload_(payload.begin(), payload.end()), syn_(syn), fin_(fin),
        seq_n_(seq_start), end_seq_n_(seq_n_ + static_cast<std::uint32_t>(payload.size()) + (fin_ ? 1 : 0) + (syn_ ? 1 : 0))
    {
    }

    [[nodiscard]] bool ack() const
    {
        return ack_;
    }
    void set_ack(bool val)
    {
        ack_ = val;
    }
    [[nodiscard]] std::uint32_t ackn() const
    {
        return ack_n_;
    }
    void set_ackn(const std::uint32_t seq)
    {
        ack_n_ = seq;
    }
    [[nodiscard]] bool syn() const
    {
        return syn_;
    }
    [[nodiscard]] bool fin() const
    {
        return fin_;
    }
    [[nodiscard]] bool rst() const
    {
        return rst_;
    }
    void set_rst(bool val)
    {
        rst_ = val;
    }

    [[nodiscard]] std::size_t size_in_seq() const
    {
        return end_seq_n_ - seq_n_;
    }
    [[nodiscard]] std::size_t payload_size() const
    {
        return payload_.size();
    }

    [[nodiscard]] std::uint32_t seq_start() const
    {
        return seq_n_;
    }
    [[nodiscard]] std::uint32_t seq_end() const
    {
        return end_seq_n_;
    }

    [[nodiscard]] std::span<const std::byte> payload() const
    {
        return {payload_};
    }
private:
    std::vector<std::byte> payload_;

    bool ack_{};
    bool rst_{};
    bool syn_{};
    bool fin_{};

    std::uint32_t seq_n_{};
    std::uint32_t end_seq_n_{};

    std::uint32_t ack_n_{};
};

class TcpBuffer
{
public:
    friend class TcpBufferTest;
    friend class TcpReceiverBufferTest;

    // Inserts a new node
    bool insert(const TcpSegment& seg);
    std::size_t consume(const std::uint32_t seq_range_to);

    TcpSegment& at(const std::ptrdiff_t idx);
    TcpSegment& find(const std::uint32_t seq);

    std::size_t size_segs() const;
    std::size_t size_bytes() const;
    std::size_t size_payload_bytes() const;

    [[nodiscard]] bool empty() const
    {
        return size_segs() == 0;
    }

    // I guess this is used for sending, but what if we are sending several segments in 1 RTT, then I need to access nodes after front()
    TcpSegment& front()
    {
        assert(!empty());
        return segs_.front();
    }
    TcpSegment& back()
    {
        assert(!empty());
        return segs_.back();
    }
protected:
    std::list<TcpSegment> segs_;
};

class TcpSenderBuffer : public TcpBuffer
{
public:
    // Appends bytes to the last node
    void append_back(std::span<const std::byte> payload);
};

class TcpReceiverBuffer : public TcpBuffer
{
public:
    std::vector<std::byte> read(const std::size_t max_size, const std::uint32_t recv_nxt);

    // This function should be called after a segment was inserted on receive. It checks if that segment had filled a gap and therefore updated RECV.NXT
    std::uint32_t check_gaps(const std::uint32_t recv_nxt) const;
};

#endif //TCPP_BUFFER_HPP
