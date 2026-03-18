//
// Created by klewy on 3/9/26.
//

#ifndef TCPP_UTIL_HPP
#define TCPP_UTIL_HPP

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

inline std::string addr_to_str(const std::uint32_t addr)
{
    std::string res;
    res.resize(INET_ADDRSTRLEN);
    const auto* r = inet_ntop(AF_INET, &addr, res.data(), res.size());
    if (!r) {
        throw std::runtime_error(std::format("Failed to convert addr to str: {}", std::strerror(errno))); // NOLINT
    }
    return res;
}

template <class T>
inline void hash_combine(std::size_t& seed, const T& v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
}

inline bool wrapping_lt(std::uint32_t lhs, std::uint32_t rhs) {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     ensure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.

    return (lhs - rhs) > (1U << 31U);
}

inline bool wrapping_gt(std::uint32_t lhs, std::uint32_t rhs)
{
    return wrapping_lt(rhs, lhs);
}

inline bool is_between_wrapped(std::uint32_t start, std::uint32_t x, std::uint32_t end) {
    return wrapping_lt(start, x) && wrapping_lt(x, end);
}

#endif //TCPP_UTIL_HPP