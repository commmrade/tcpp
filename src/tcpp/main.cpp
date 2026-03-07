#include <print>
#include <spdlog/spdlog.h>
#include "../netparser/netparser.hpp"
#include <arpa/inet.h>
#include <cstring>
#include "tun.hpp"




int main()
{


    tun tun{"tun1"};
    while (true) {
        std::array<std::byte, 1500> buf{};
        const ssize_t rd_bytes = tun.read(buf);
        assert(rd_bytes);

        const netparser::IpHeaderView iph{std::span<const std::byte, netparser::IPV4H_MIN_SIZE>{buf.data(), netparser::IPV4H_MIN_SIZE}};
        if (iph.protocol() == 6) {

            const netparser::IpHeader owned_iph{iph};
            // iphdr iph = owned_iph.test();
            // const auto src_addr = iph.saddr;
            // const auto dest_addr = iph.daddr;

            // std::array<char, INET_ADDRSTRLEN> src{};
            // std::array<char, INET_ADDRSTRLEN> dest{};

            // inet_ntop(AF_INET, &src_addr, src.data(), INET_ADDRSTRLEN);
            // inet_ntop(AF_INET, &dest_addr, dest.data(), INET_ADDRSTRLEN);

            // auto ver = iph.version;
            // auto ihl = iph.ihl;
            // std::println("RAW IP Ver: {}, IHL: {}, Protocol: {}. Addr {} and {}", ver, ihl, iph.protocol, src.data(), dest.data());
            // std::println("DF: {}. MF: {}", iph.dont_fragment(), iph.more_fragments());


        }

    }

    return 0;
}