//
// Created by klewy on 3/18/26.
//

#ifndef TCPP_COMMON_HPP
#define TCPP_COMMON_HPP
#include <cstdint>
#include "../util.hpp"

enum class ShutdownType
{
    WRITE,
    READ,
    RDWR,
};

enum class TcpState// NOLINT
{
    // Passive open
    CLOSED,
    LISTEN,
    SYN_RCVD,
    ESTAB,

    // Passive close
    CLOSE_WAIT,
    LAST_ACK,

    // Active open
    SYN_SENT,

    // Active close
    FIN_WAIT_1,
    FIN_WAIT_2,

    CLOSING,
    TIME_WAIT,
};

struct Quad
{
    std::uint32_t src_addr;
    std::uint16_t src_port;

    std::uint32_t dst_addr;
    std::uint16_t dst_port;

    bool operator==(const Quad &quad) const
    {
        return src_addr == quad.src_addr && src_port == quad.src_port && dst_addr == quad.dst_addr && dst_port == quad.
               dst_port;
    }
};

template<> struct std::hash<Quad>
{
    std::size_t operator()(const Quad &quad) const noexcept
    {
        std::size_t hash;
        hash_combine(hash, quad.src_addr);
        hash_combine(hash, quad.src_port);
        hash_combine(hash, quad.dst_addr);
        hash_combine(hash, quad.dst_port);
        return hash;
    };
};


#endif //TCPP_COMMON_HPP