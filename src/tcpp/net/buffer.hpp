//
// Created by klewy on 4/23/26.
//

#ifndef TCPP_BUFFER_HPP
#define TCPP_BUFFER_HPP
#include <cassert>
#include <cstddef>
#include <list>
#include <cstdint>
#include <iostream>
#include <cstring>
#include <print>
#include <vector>
#include <span>

class TcpSegment
{
public:
    TcpSegment(const std::uint32_t seq_start, std::span<const std::byte> payload, bool syn = false, bool fin = false) : payload_(payload.begin(), payload.end())
    {
        syn_ = syn;
        fin_ = fin;

        seq_n_ = seq_start;
        end_seq_n_ = seq_n_ + static_cast<std::uint32_t>(payload.size()) + (fin ? 1 : 0) + (syn ? 1 : 0);
    }

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
        end_seq_n_ -= range_to;
    }

    std::size_t size_in_seq() const
    {
        return end_seq_n_ - seq_n_;
    }
    std::size_t payload_size() const
    {
        return payload_.size();
    }

    void set_seq_start(const std::uint32_t seq)
    {
        seq_n_ = seq;
    }
    std::uint32_t seq_start() const
    {
        return seq_n_;
    }

    void set_seq_end(const std::uint32_t seq)
    {
        end_seq_n_ = seq;
    }
    std::uint32_t seq_end() const
    {
        return end_seq_n_;
    }

    bool syn() const
    {
        return syn_;
    }
    bool fin() const
    {
        return fin_;
    }

    std::span<const std::byte> payload() const
    {
        return {payload_};
    }
private:



    bool ack_{};
    bool rst_{};
    bool syn_{};
    bool fin_{};

    std::uint32_t seq_n_{};
    std::uint32_t end_seq_n_{};

    std::uint32_t ack_n_{};

    std::vector<std::byte> payload_{};
};

class TcpBuffer
{
    // TODO: I would kinda like to make it a base class and then derive TcpReceiveBuf and TcpSendBuf, because each have diff. logic in some places
public:

    // Appends bytes to the last node
    void append_back(std::span<const std::byte> payload);

    // Inserts a new node
    // TODO: Out-of-order inserts
    void insert(const TcpSegment& seg);
    void consume(const std::uint32_t range_to);

    const TcpSegment& at(const std::ptrdiff_t idx) const;

    // May be used for Receive QUEUE
    std::vector<std::byte> read(const std::size_t len);

    std::size_t size() const
    {
        return segs_.size();
    }
    bool empty() const
    {
        return size() == 0;
    }

    // I guess this is used for sending, but what if we are sending several segments in 1 RTT, then I need to access nodes after front() - TODO: how?
    const TcpSegment& front() const
    {
        assert(!empty());
        return segs_.front();
    }
    const TcpSegment& back() const
    {
        assert(!empty());
        return segs_.back();
    }

    const std::list<TcpSegment>& inner() const
    {
        return segs_;
    }
private:
    std::list<TcpSegment> segs_;
};


#endif //TCPP_BUFFER_HPP
