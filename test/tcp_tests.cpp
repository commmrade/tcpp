//
// Created by klewy on 3/7/26.
//
#include "../src/netparser/netparser.hpp"
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <span>
#include <array>
#include <arpa/inet.h>

constexpr std::array<std::byte, 20> tcp_header{
    std::byte{0x00}, std::byte{0x50}, // Source port = 80 (HTTP)
    std::byte{0x1F}, std::byte{0x90}, // Destination port = 8080
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, // Sequence number (server ISN)
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02}, // ACK number = client ISN + 1
    std::byte{0x50},                  // Data offset (5 * 4 = 20 bytes) + reserved (0)
    std::byte{0x12},                  // Flags = SYN + ACK (0b00010010)
    std::byte{0xFF}, std::byte{0xFF}, // Window size = 65535
    std::byte{0x00}, std::byte{0x00}, // Checksum (placeholder)
    std::byte{0x00}, std::byte{0x00}  // Urgent pointer (not set)
};

TEST_CASE("Check all the fields TCP view", "[TcpHeaderView]")
{
    const netparser::TcpHeaderView tcph{tcp_header};
    REQUIRE(tcph.src_port() == 80);
    REQUIRE(tcph.dest_port() == 8080);
    REQUIRE(tcph.seqn() == 1);
    REQUIRE(tcph.ackn() == 2);
    REQUIRE(tcph.data_off() == 5);
    REQUIRE(tcph.ack() == true);
    REQUIRE(tcph.syn() == true);
    REQUIRE(tcph.window() == 65535);
    REQUIRE(tcph.checksum() == 0x00);
    REQUIRE((tcph.urg_ptr() == 0 && tcph.urg() == false));
}

TEST_CASE("Check all the fields TCP owned", "[TcpHeader]")
{
    const netparser::TcpHeaderView tcph_view{tcp_header};
    const netparser::TcpHeader tcph{tcph_view};
    REQUIRE(tcph.src_port() == 80);
    REQUIRE(tcph.dest_port() == 8080);
    REQUIRE(tcph.seqn() == 1);
    REQUIRE(tcph.ackn() == 2);
    REQUIRE(tcph.data_off() == 5);
    REQUIRE(tcph.ack() == true);
    REQUIRE(tcph.syn() == true);
    REQUIRE(tcph.window() == 65535);
    REQUIRE(tcph.checksum() == 0x00);
    REQUIRE((tcph.urg_ptr() == 0 && tcph.urg() == false));
}

TEST_CASE("Set and get", "[TcpHeader]")
{
    netparser::TcpHeader tcph{};
    tcph.src_port(80);
    tcph.dest_port(8080);
    tcph.seqn(1);
    tcph.ackn(2);
    tcph.data_off(5);
    tcph.ack(true);
    tcph.syn(true);
    tcph.window(65535);
    tcph.checksum(0x00);
    tcph.urg_ptr(0);
    tcph.urg(false);

    REQUIRE(tcph.src_port() == 80);
    REQUIRE(tcph.dest_port() == 8080);
    REQUIRE(tcph.seqn() == 1);
    REQUIRE(tcph.ackn() == 2);
    REQUIRE(tcph.data_off() == 5);
    REQUIRE(tcph.ack() == true);
    REQUIRE(tcph.syn() == true);
    REQUIRE(tcph.window() == 65535);
    REQUIRE(tcph.checksum() == 0x00);
    REQUIRE((tcph.urg_ptr() == 0 && tcph.urg() == false));
}

TEST_CASE("Construct, serialize, compare", "[TcpHeader]")
{
    netparser::TcpHeader tcph{};
    tcph.src_port(80);
    tcph.dest_port(8080);
    tcph.seqn(1);
    tcph.ackn(2);
    tcph.data_off(5);
    tcph.ack(true);
    tcph.syn(true);
    tcph.window(65535);
    tcph.checksum(0x00);
    tcph.urg_ptr(0);
    tcph.urg(false);

    const auto data = tcph.serialize();
    REQUIRE(std::memcmp(data.data(), tcp_header.data(), tcp_header.size()) == 0);
}