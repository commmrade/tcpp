#include <print>
#include "../netparser/netparser.hpp"
#include <arpa/inet.h>
#include "tun.hpp"
#include <array>
#include <cassert>
#include <cstddef>
#include <sys/types.h>
#include <span>
#include <netinet/in.h>

int main()
{
    tun tun{"tun1"};
    while (true) {
        std::array<std::byte, 1500> buf{}; // NOLINT
        const ssize_t rd_bytes = tun.read(buf);
        assert(rd_bytes);

        const netparser::IpHeaderView iph{std::span<const std::byte, netparser::IPV4H_MIN_SIZE>{buf.data(), netparser::IPV4H_MIN_SIZE}};
        if (iph.protocol() == 6) { // NOLINT
            const netparser::TcpHeaderView tcph{std::span<const std::byte, netparser::TCPH_MIN_SIZE>{buf.data() + netparser::IPV4H_MIN_SIZE, netparser::TCPH_MIN_SIZE}};

            std::array<char, INET_ADDRSTRLEN> src{};
            std::array<char, INET_ADDRSTRLEN> dest{};
            const auto src_addr = iph.source_addr();
            const auto dest_addr = iph.dest_addr();

            inet_ntop(AF_INET, &src_addr, src.data(), src.size());
            inet_ntop(AF_INET, &dest_addr, dest.data(), dest.size());

            std::println("{}:{} -> {}:{}. SEQ: {}, ACK: {}", src.data(), tcph.src_port(), dest.data(), tcph.dest_port(), tcph.seqn(), tcph.ack() ? tcph.ackn() : 0UL);
        }

    }

    return 0;
}