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
    REQUIRE(tcph.source_port() == 80);
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
    REQUIRE(tcph.source_port() == 80);
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
    tcph.source_port(80);
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

    REQUIRE(tcph.source_port() == 80);
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
    tcph.source_port(80);
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

constexpr std::array<std::byte, 50> tcp_syn_header{
    std::byte{0x80}, std::byte{0xf4}, // Source port = 32980
    std::byte{0x1f}, std::byte{0x9a}, // Destination port = 8090
    std::byte{0x76}, std::byte{0x1f}, std::byte{0xb8}, std::byte{0x7a}, // Sequence number
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, // ACK number
    std::byte{0xa0},                  // Data offset (10 * 4 = 40 bytes) + reserved
    std::byte{0x02},                  // Flags = SYN
    std::byte{0xfa}, std::byte{0xf0}, // Window size = 64240
    std::byte{0xb3}, std::byte{0x4c}, // Checksum
    std::byte{0x00}, std::byte{0x00}, // Urgent pointer
    std::byte{0x02}, std::byte{0x04}, std::byte{0x05}, std::byte{0xb4}, // Option: MSS = 1460
    std::byte{0x04}, std::byte{0x02}, // Option: SACK permitted
    std::byte{0x08}, std::byte{0x0a}, std::byte{0x7e}, std::byte{0x7d}, std::byte{0x38}, std::byte{0x17}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, // Option: Timestamps
    std::byte{0x01},                  // Option: NOP
    std::byte{0x03}, std::byte{0x03}, std::byte{0x0a}, // Option: Window scale = 10
    std::byte{0x03}, std::byte{0x03}, std::byte{0x0a},  std::byte{0x03}, std::byte{0x03}, std::byte{0x0a},  std::byte{0x03}, std::byte{0x03}, std::byte{0x0a}, std::byte{0x1} // Imagine these are paload bytes
};

TEST_CASE("Check options in view", "[TcpHeaderView]")
{
    const netparser::TcpHeaderView tcph{tcp_syn_header};

    REQUIRE(tcph.has_option(netparser::TcpOptionKind::MSS));
    REQUIRE(tcph.has_option(netparser::TcpOptionKind::SACK_PERM));
    REQUIRE(tcph.has_option(netparser::TcpOptionKind::TIMESTAMP));
    REQUIRE(tcph.has_option(netparser::TcpOptionKind::WIN_SCALE));

    auto mss_opt = tcph.mss();
    REQUIRE(mss_opt.has_value());
    REQUIRE(mss_opt.value().mss == 1460);

    auto sack_p = tcph.sack_perm();
    REQUIRE(sack_p.has_value());

    auto ts_opt = tcph.timestamp();
    REQUIRE(ts_opt.has_value());
    REQUIRE(ts_opt.value().tv == 2122135575);
    REQUIRE(ts_opt.value().tr == 0);

    auto wscl_opt = tcph.win_scale();
    REQUIRE(wscl_opt.has_value());
    REQUIRE(wscl_opt.value().shift_cnt == 10);
}

TEST_CASE("Check options in owned", "[TcpHeader]")
{
    const netparser::TcpHeaderView tcph_view{tcp_syn_header};
    const netparser::TcpHeader tcph{tcph_view};
    const auto& options = tcph.options();

    REQUIRE(options.has_option(netparser::TcpOptionKind::MSS));
    REQUIRE(options.has_option(netparser::TcpOptionKind::SACK_PERM));
    REQUIRE(options.has_option(netparser::TcpOptionKind::TIMESTAMP));
    REQUIRE(options.has_option(netparser::TcpOptionKind::WIN_SCALE));

    auto mss_opt = options.mss();
    REQUIRE(mss_opt.has_value());
    REQUIRE(mss_opt.value().mss == 1460);

    auto sack_p = options.sack_perm();
    REQUIRE(sack_p.has_value());

    auto ts_opt = options.timestamp();
    REQUIRE(ts_opt.has_value());
    REQUIRE(ts_opt.value().tv == 2122135575);
    REQUIRE(ts_opt.value().tr == 0);

    auto wscl_opt = options.win_scale();
    REQUIRE(wscl_opt.has_value());
    REQUIRE(wscl_opt.value().shift_cnt == 10);
}