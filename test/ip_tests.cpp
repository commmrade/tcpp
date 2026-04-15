#include "../src/netparser/netparser.hpp"
#include <gtest/gtest.h>
#include <cstddef>
#include <span>
#include <array>
#include <arpa/inet.h>

constexpr std::array<std::byte, 20> ip_header{
    std::byte{0x45},
    std::byte{0x00},
    std::byte{0x00}, std::byte{0x28},
    std::byte{0x12}, std::byte{0x34},
    std::byte{0x40}, std::byte{0x00},
    std::byte{0x40},
    std::byte{0x06},
    std::byte{0x00}, std::byte{0x00},
    std::byte{0xC0}, std::byte{0xA8}, std::byte{0x01}, std::byte{0x01},
    std::byte{0xC0}, std::byte{0xA8}, std::byte{0x01}, std::byte{0x02}
};

TEST(IpHeaderViewTest, CheckAllFields) {
    const netparser::IpHeaderView iph{ip_header};
    EXPECT_EQ(iph.version(), 4);
    EXPECT_EQ(iph.ihl(), 5);
    EXPECT_EQ(iph.type_of_service(), 0);
    EXPECT_EQ(iph.total_len(), 40);
    EXPECT_EQ(iph.id(), 0x1234);
    EXPECT_TRUE(iph.dont_fragment());
    EXPECT_FALSE(iph.more_fragments());
    EXPECT_EQ(iph.frag_offset(), 0);
    EXPECT_EQ(iph.ttl(), 64);
    EXPECT_EQ(iph.protocol(), 6);
    EXPECT_EQ(iph.checksum(), 0x0000);
    EXPECT_EQ(iph.source_addr(), ntohl(0xC0A80101));
    EXPECT_EQ(iph.dest_addr(), ntohl(0xC0A80102));
}

TEST(IpHeaderTest, CheckAllFieldsOwned) {
    const netparser::IpHeaderView iph_view{ip_header};
    const netparser::IpHeader iph{iph_view};
    EXPECT_EQ(iph.version(), 4);
    EXPECT_EQ(iph.ihl(), 5);
    EXPECT_EQ(iph.type_of_service(), 0);
    EXPECT_EQ(iph.total_len(), 40);
    EXPECT_EQ(iph.id(), 0x1234);
    EXPECT_TRUE(iph.dont_fragment());
    EXPECT_FALSE(iph.more_fragments());
    EXPECT_EQ(iph.frag_offset(), 0);
    EXPECT_EQ(iph.ttl(), 64);
    EXPECT_EQ(iph.protocol(), 6);
    EXPECT_EQ(iph.checksum(), 0x0000);
    EXPECT_EQ(iph.source_addr(), ntohl(0xC0A80101));
    EXPECT_EQ(iph.dest_addr(), ntohl(0xC0A80102));
}

TEST(IpHeaderTest, SetAndGetFields) {
    netparser::IpHeader iph{};
    iph.version(4);
    iph.ihl(5);
    iph.type_of_service(0);
    iph.total_len(40);
    iph.id(0x1234);
    iph.dont_fragment(true);
    iph.more_fragments(false);
    iph.frag_offset(5);
    iph.ttl(64);
    iph.protocol(6);
    iph.checksum(0x0000);
    iph.source_addr(0xC0A80101);
    iph.dest_addr(0xC0A80102);

    EXPECT_EQ(iph.version(), 4);
    EXPECT_EQ(iph.ihl(), 5);
    EXPECT_EQ(iph.type_of_service(), 0);
    EXPECT_EQ(iph.total_len(), 40);
    EXPECT_EQ(iph.id(), 0x1234);
    EXPECT_TRUE(iph.dont_fragment());
    EXPECT_FALSE(iph.more_fragments());
    EXPECT_EQ(iph.frag_offset(), 5);
    EXPECT_EQ(iph.ttl(), 64);
    EXPECT_EQ(iph.protocol(), 6);
    EXPECT_EQ(iph.checksum(), 0x0000);
    EXPECT_EQ(iph.source_addr(), 0xC0A80101);
    EXPECT_EQ(iph.dest_addr(), 0xC0A80102);
}

TEST(IpHeaderTest, SerializeMatchesRawBytes) {
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
    ASSERT_EQ(data.size(), ip_header.size());
    EXPECT_EQ(std::memcmp(data.data(), ip_header.data(), ip_header.size()), 0);
}