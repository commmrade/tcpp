//
// Created by klewy on 4/23/26.
//

#ifndef TCPP_BUFFER_HPP
#define TCPP_BUFFER_HPP
#include <cassert>
#include <list>
#include <cstdint>
#include <cstring>
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

    void erase(const std::size_t range_to)
    {
        assert(range_to <= payload_.size());
        payload_.erase(payload_.begin(), payload_.begin() + static_cast<std::ptrdiff_t>(range_to));
    }

    std::size_t size_in_seq() const
    {
        return payload_.size() + (syn_ ? 1 : 0) + (fin_ ? 1 : 0);
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
public:
    void insert(const TcpSegment& seg)
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
                break;
            } else if (seq_n == iter->seq_start()) {
                return; // Such segment already exists, wtf?
            }
            ++iter;
        }

        if (iter == segs_.end()) { // We did not find a place for this segment, which means it is in-order
            segs_.push_back(seg);
            // Insert a new one
        }
    }

    void consume(const std::uint32_t to_seq_n)
    {
        auto iter = segs_.begin();
        while (iter != segs_.end()) {
            auto old_iter = iter;
            ++iter;

            if (to_seq_n >= old_iter->seq_end()) {
                segs_.erase(old_iter);
            } else if (to_seq_n >= old_iter->seq_start() && to_seq_n < old_iter->seq_end()) {
                // Erase inside a segment
                const auto to_idx = to_seq_n - old_iter->seq_start();
                const auto payload_size = old_iter->payload_size();

                const auto to_erase_n = std::min<std::size_t>(to_idx, payload_size); // In case this segment contains SYN/FIN
                old_iter->erase(to_erase_n);
                old_iter->set_seq_start(to_seq_n);
            }
        }
    }

    std::vector<std::byte> read(const std::uint32_t seq_n, const std::size_t len)
    {
        std::vector<std::byte> res;

        auto iter = segs_.cbegin();

        auto read_total = len;
        auto next_seq = seq_n;
        while (iter != segs_.cend()) {
            if (next_seq >= iter->seq_start() && next_seq < iter->seq_start() + iter->payload_size() && read_total > 0) {
                const auto idx = seq_n - iter->seq_start();
                const auto to_read_n = std::min(len, iter->payload_size() - idx);
                res.resize(to_read_n);

                const auto payload = iter->payload();

                const auto from = payload.begin() + idx;
                const auto to = from + static_cast<std::ptrdiff_t>(to_read_n);
                std::copy(from, to, res.begin());

                read_total -= to_read_n;
                next_seq += to_read_n;
                // MAKE IT WORK, ReadTwoSegments fails
            }
            // TODO: Make it stop reading after its done reading several segments
            ++iter;
        }

        return res;
    }

    std::size_t size() const
    {
        return segs_.size();
    }
    bool empty() const
    {
        return size() == 0;
    }

    TcpSegment front()
    {
        assert(!empty());
        return segs_.front();
    }

    const std::list<TcpSegment>& inner() const
    {
        return segs_;
    }
private:
    std::list<TcpSegment> segs_;
    std::uint32_t mss_{536};
};


#endif //TCPP_BUFFER_HPP