//
// Created by klewy on 3/7/26.
//
#include "../src/netparser/netparser.hpp"
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <span>
#include <array>
#include <arpa/inet.h>

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

TEST_CASE("Check all the fields", "[IpHeaderView]")
{
    const netparser::IpHeaderView iph{ip_header};
    REQUIRE(iph.version() == 4);
    REQUIRE(iph.ihl() == 5);
    REQUIRE(iph.type_of_service() == 0);
    REQUIRE(iph.total_len() == 40);
    REQUIRE(iph.id() == 0x1234);
    REQUIRE(iph.dont_fragment() == true);   // 0x40 = 0100 0000 → DF bit set
    REQUIRE(iph.more_fragments() == false); // MF bit not set
    REQUIRE(iph.frag_offset() == 0);
    REQUIRE(iph.ttl() == 64);              // 0x40
    REQUIRE(iph.protocol() == 6);          // TCP
    REQUIRE(iph.checksum() == 0x0000);
    REQUIRE(iph.source_addr() == ntohl(0xC0A80101)); // 192.168.1.1
    REQUIRE(iph.dest_addr() == ntohl(0xC0A80102));   // 192.168.1.2
}

TEST_CASE("Check all the fields (owned)", "[IpHeader]")
{
    const netparser::IpHeaderView iph_view{ip_header};
    const netparser::IpHeader iph{iph_view};

    REQUIRE(iph.version() == 4);
    REQUIRE(iph.ihl() == 5);
    REQUIRE(iph.type_of_service() == 0);
    REQUIRE(iph.total_len() == 40);
    REQUIRE(iph.id() == 0x1234);
    REQUIRE(iph.dont_fragment() == true);
    REQUIRE(iph.more_fragments() == false);
    REQUIRE(iph.frag_offset() == 0);
    REQUIRE(iph.ttl() == 64);
    REQUIRE(iph.protocol() == 6);
    REQUIRE(iph.checksum() == 0x0000);
    REQUIRE(iph.source_addr() == ntohl(0xC0A80101));
    REQUIRE(iph.dest_addr() == ntohl(0xC0A80102));
}

TEST_CASE("Check setting and then getting fields", "[IpHeader]")
{
    netparser::IpHeader iph{};
    iph.version(4);
    iph.ihl(5);
    iph.type_of_service(0);
    iph.total_len(40);
    iph.id(0x1234);
    iph.dont_fragment(true);
    iph.more_fragments(false);
    iph.frag_offset(5); // For testing only
    iph.ttl(64);
    iph.protocol(6);
    iph.checksum(0x0000);
    iph.source_addr(0xC0A80101);
    iph.dest_addr(0xC0A80102);

    REQUIRE(iph.version() == 4);
    REQUIRE(iph.ihl() == 5);
    REQUIRE(iph.type_of_service() == 0);
    REQUIRE(iph.total_len() == 40);
    REQUIRE(iph.id() == 0x1234);
    REQUIRE(iph.dont_fragment() == true);
    REQUIRE(iph.more_fragments() == false);
    REQUIRE(iph.frag_offset() == 5);
    REQUIRE(iph.ttl() == 64);
    REQUIRE(iph.protocol() == 6);
    REQUIRE(iph.checksum() == 0x0000);
    REQUIRE(iph.source_addr() == 0xC0A80101);
    REQUIRE(iph.dest_addr() == 0xC0A80102);
}

TEST_CASE("Construct and serialize, then compare", "[IpHeader]")
{
    netparser::IpHeader iph{};
    iph.version(4);
    iph.ihl(5);
    iph.type_of_service(0);
    iph.total_len(40);
    iph.id(0x1234);
    iph.dont_fragment(true);
    iph.more_fragments(false);
    iph.frag_offset(0);
    iph.ttl(64);
    iph.protocol(6);
    iph.checksum(0x0000);
    iph.source_addr(htonl(0xC0A80101));
    iph.dest_addr(htonl(0xC0A80102));

    const auto data = iph.serialize();
    REQUIRE(data.size() == ip_header.size());
    REQUIRE(std::memcmp(data.data(), ip_header.data(), ip_header.size()) == 0);
}










