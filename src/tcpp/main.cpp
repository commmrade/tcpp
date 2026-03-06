#include <print>
#include <spdlog/spdlog.h>
#include "../netparser/netparser.hpp"
#include <arpa/inet.h>
#include <cstring>
#include "tun.hpp"

constexpr std::array<std::byte, 20> ip_header{
    std::byte{0x45}, // Version(4) + IHL(5)
    std::byte{0x00}, // DSCP/ECN
    std::byte{0x00}, std::byte{0x28}, // Total length = 40
    std::byte{0x12}, std::byte{0x34}, // Identification
    std::byte{0x40}, std::byte{0x00}, // Flags + fragment offset
    std::byte{0x40}, // TTL = 64
    std::byte{0x06}, // Protocol = TCP
    std::byte{0x00}, std::byte{0x00}, // Header checksum (placeholder)
    std::byte{0xC0}, std::byte{0xA8}, std::byte{0x01}, std::byte{0x01}, // Source IP
    std::byte{0xC0}, std::byte{0xA8}, std::byte{0x01}, std::byte{0x02}  // Destination IP
};

int main()
{


    tun tun{"tun1"};
    while (true) {
        std::array<std::byte, 1500> buf{};
        const ssize_t rd_bytes = tun.read(buf);
        assert(rd_bytes);

        netparser::IpHeaderView iph{std::span<const std::byte, netparser::IPV4H_MIN_SIZE>{buf.data(), netparser::IPV4H_MIN_SIZE}};

        const auto src_addr = iph.source_addr();
        const auto dest_addr = iph.dest_addr();

        std::array<char, INET_ADDRSTRLEN> src{};
        std::array<char, INET_ADDRSTRLEN> dest{};

        inet_ntop(AF_INET, src_addr.data(), src.data(), INET_ADDRSTRLEN);
        inet_ntop(AF_INET, dest_addr.data(), dest.data(), INET_ADDRSTRLEN);


        std::println("Protocol: {}. Addr {} and {}", iph.protocol(), src.data(), dest.data());
    }

    return 0;
}