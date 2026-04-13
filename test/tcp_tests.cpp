#include "../src/netparser/netparser.hpp"
#include <gtest/gtest.h>
#include <cstddef>
#include <span>
#include <array>
#include <arpa/inet.h>

constexpr std::array<std::byte, 20> tcp_header{
    std::byte{0x00}, std::byte{0x50},
    std::byte{0x1F}, std::byte{0x90},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
    std::byte{0x50},
    std::byte{0x12},
    std::byte{0xFF}, std::byte{0xFF},
    std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x00}
};

constexpr std::array<std::byte, 50> tcp_syn_header{
    std::byte{0x80}, std::byte{0xf4},
    std::byte{0x1f}, std::byte{0x9a},
    std::byte{0x76}, std::byte{0x1f}, std::byte{0xb8}, std::byte{0x7a},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xa0},
    std::byte{0x02},
    std::byte{0xfa}, std::byte{0xf0},
    std::byte{0xb3}, std::byte{0x4c},
    std::byte{0x00}, std::byte{0x00},
    std::byte{0x02}, std::byte{0x04}, std::byte{0x05}, std::byte{0xb4},
    std::byte{0x04}, std::byte{0x02},
    std::byte{0x08}, std::byte{0x0a}, std::byte{0x7e}, std::byte{0x7d}, std::byte{0x38}, std::byte{0x17}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x01},
    std::byte{0x03}, std::byte{0x03}, std::byte{0x0a},
    std::byte{0x03}, std::byte{0x03}, std::byte{0x0a}, std::byte{0x03}, std::byte{0x03}, std::byte{0x0a}, std::byte{0x03}, std::byte{0x03}, std::byte{0x0a}, std::byte{0x1}
};

constexpr std::array<std::byte, 20> plain_tcp_header{
    std::byte{0x00}, std::byte{0x50},
    std::byte{0x1F}, std::byte{0x90},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
    std::byte{0x50},
    std::byte{0x02},
    std::byte{0xFF}, std::byte{0xFF},
    std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x00}
};

// TcpHeaderView tests

TEST(TcpHeaderViewTest, CheckAllFields) {
    const netparser::TcpHeaderView tcph{tcp_header};
    EXPECT_EQ(tcph.source_port(), 80);
    EXPECT_EQ(tcph.dest_port(), 8080);
    EXPECT_EQ(tcph.seqn(), 1);
    EXPECT_EQ(tcph.ackn(), 2);
    EXPECT_EQ(tcph.data_off(), 5);
    EXPECT_TRUE(tcph.ack());
    EXPECT_TRUE(tcph.syn());
    EXPECT_EQ(tcph.window(), 65535);
    EXPECT_EQ(tcph.checksum(), 0x00);
    EXPECT_EQ(tcph.urg_ptr(), 0);
    EXPECT_FALSE(tcph.urg());
}

TEST(TcpHeaderViewTest, CheckOptions) {
    const netparser::TcpHeaderView tcph{tcp_syn_header};

    EXPECT_TRUE(tcph.has_option(netparser::TcpOptionKind::MSS));
    EXPECT_TRUE(tcph.has_option(netparser::TcpOptionKind::SACK_PERM));
    EXPECT_TRUE(tcph.has_option(netparser::TcpOptionKind::TIMESTAMP));
    EXPECT_TRUE(tcph.has_option(netparser::TcpOptionKind::WIN_SCALE));

    auto mss_opt = tcph.mss();
    ASSERT_TRUE(mss_opt.has_value());
    EXPECT_EQ(mss_opt->mss, 1460);

    EXPECT_TRUE(tcph.sack_perm().has_value());

    auto ts_opt = tcph.timestamp();
    ASSERT_TRUE(ts_opt.has_value());
    EXPECT_EQ(ts_opt->tv, 2122135575);
    EXPECT_EQ(ts_opt->tr, 0);

    auto wscl_opt = tcph.win_scale();
    ASSERT_TRUE(wscl_opt.has_value());
    EXPECT_EQ(wscl_opt->shift_cnt, 10);
}

TEST(TcpHeaderViewTest, MissingOptionsReturnNullopt) {
    const netparser::TcpHeaderView tcph{plain_tcp_header};
    EXPECT_FALSE(tcph.has_option(netparser::TcpOptionKind::MSS));
    EXPECT_FALSE(tcph.has_option(netparser::TcpOptionKind::SACK_PERM));
    EXPECT_FALSE(tcph.has_option(netparser::TcpOptionKind::TIMESTAMP));
    EXPECT_FALSE(tcph.has_option(netparser::TcpOptionKind::WIN_SCALE));
    EXPECT_FALSE(tcph.mss().has_value());
    EXPECT_FALSE(tcph.sack_perm().has_value());
    EXPECT_FALSE(tcph.timestamp().has_value());
    EXPECT_FALSE(tcph.win_scale().has_value());
}

TEST(TcpHeaderViewTest, MalformedOptionLengthDoesNotCrash) {
    constexpr std::array<std::byte, 24> bad_mss_header{
        std::byte{0x00}, std::byte{0x50},
        std::byte{0x1F}, std::byte{0x90},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x60},
        std::byte{0x02},
        std::byte{0xFF}, std::byte{0xFF},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x02}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}
    };

    const netparser::TcpHeaderView tcph{bad_mss_header};
    EXPECT_NO_THROW(tcph.has_option(netparser::TcpOptionKind::MSS));
    EXPECT_NO_THROW(tcph.mss());
}

// TcpHeader (owned) tests

TEST(TcpHeaderTest, CheckAllFieldsOwned) {
    const netparser::TcpHeaderView tcph_view{tcp_header};
    const netparser::TcpHeader tcph{tcph_view};
    EXPECT_EQ(tcph.source_port(), 80);
    EXPECT_EQ(tcph.dest_port(), 8080);
    EXPECT_EQ(tcph.seqn(), 1);
    EXPECT_EQ(tcph.ackn(), 2);
    EXPECT_EQ(tcph.data_off(), 5);
    EXPECT_TRUE(tcph.ack());
    EXPECT_TRUE(tcph.syn());
    EXPECT_EQ(tcph.window(), 65535);
    EXPECT_EQ(tcph.checksum(), 0x00);
    EXPECT_EQ(tcph.urg_ptr(), 0);
    EXPECT_FALSE(tcph.urg());
}

TEST(TcpHeaderTest, SetAndGet) {
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

    EXPECT_EQ(tcph.source_port(), 80);
    EXPECT_EQ(tcph.dest_port(), 8080);
    EXPECT_EQ(tcph.seqn(), 1);
    EXPECT_EQ(tcph.ackn(), 2);
    EXPECT_EQ(tcph.data_off(), 5);
    EXPECT_TRUE(tcph.ack());
    EXPECT_TRUE(tcph.syn());
    EXPECT_EQ(tcph.window(), 65535);
    EXPECT_EQ(tcph.checksum(), 0x00);
    EXPECT_EQ(tcph.urg_ptr(), 0);
    EXPECT_FALSE(tcph.urg());
}

TEST(TcpHeaderTest, SerializeMatchesRawBytes) {
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
    ASSERT_EQ(data.size(), tcp_header.size());
    EXPECT_EQ(std::memcmp(data.data(), tcp_header.data(), tcp_header.size()), 0);
}

TEST(TcpHeaderTest, CheckOptionsOwned) {
    const netparser::TcpHeaderView tcph_view{tcp_syn_header};
    const netparser::TcpHeader tcph{tcph_view};
    const auto& options = tcph.options();

    EXPECT_TRUE(options.has_option(netparser::TcpOptionKind::MSS));
    EXPECT_TRUE(options.has_option(netparser::TcpOptionKind::SACK_PERM));
    EXPECT_TRUE(options.has_option(netparser::TcpOptionKind::TIMESTAMP));
    EXPECT_TRUE(options.has_option(netparser::TcpOptionKind::WIN_SCALE));

    auto mss_opt = options.mss();
    ASSERT_TRUE(mss_opt.has_value());
    EXPECT_EQ(mss_opt->mss, 1460);

    EXPECT_TRUE(options.sack_perm().has_value());

    auto ts_opt = options.timestamp();
    ASSERT_TRUE(ts_opt.has_value());
    EXPECT_EQ(ts_opt->tv, 2122135575);
    EXPECT_EQ(ts_opt->tr, 0);

    auto wscl_opt = options.win_scale();
    ASSERT_TRUE(wscl_opt.has_value());
    EXPECT_EQ(wscl_opt->shift_cnt, 10);
}

TEST(TcpHeaderTest, MissingOptionsReturnNulloptOwned) {
    const netparser::TcpHeaderView tcph_view{plain_tcp_header};
    const netparser::TcpHeader tcph{tcph_view};
    EXPECT_FALSE(tcph.options().has_option(netparser::TcpOptionKind::MSS));
    EXPECT_FALSE(tcph.options().has_option(netparser::TcpOptionKind::SACK_PERM));
    EXPECT_FALSE(tcph.options().has_option(netparser::TcpOptionKind::TIMESTAMP));
    EXPECT_FALSE(tcph.options().has_option(netparser::TcpOptionKind::WIN_SCALE));
    EXPECT_FALSE(tcph.options().mss().has_value());
    EXPECT_FALSE(tcph.options().sack_perm().has_value());
    EXPECT_FALSE(tcph.options().timestamp().has_value());
    EXPECT_FALSE(tcph.options().win_scale().has_value());
}

// Round-trip test — replaces SECTION with sub-assertions in one TEST

TEST(TcpHeaderTest, RoundTripWithOptions) {
    netparser::TcpHeader tcph{};
    tcph.source_port(32980);
    tcph.dest_port(8090);
    tcph.seqn(0x761fb87a);
    tcph.ackn(0);
    tcph.syn(true);
    tcph.window(64240);
    tcph.checksum(0);
    tcph.urg_ptr(0);
    tcph.options().mss(1460);
    tcph.options().set_sack_perm();
    tcph.options().timestamp(0x7e7d3817, 0x00000000);
    tcph.options().win_scale(10);

    const auto bytes = tcph.serialize();
    ASSERT_FALSE(bytes.empty());

    const netparser::TcpHeaderView view{bytes};

    EXPECT_EQ(view.source_port(), 32980);
    EXPECT_EQ(view.dest_port(), 8090);
    EXPECT_EQ(view.seqn(), 0x761fb87a);
    EXPECT_EQ(view.ackn(), 0);
    EXPECT_TRUE(view.syn());
    EXPECT_EQ(view.window(), 64240);

    auto mss = view.mss();
    ASSERT_TRUE(mss.has_value());
    EXPECT_EQ(mss->kind, 2);
    EXPECT_EQ(mss->size, 4);
    EXPECT_EQ(mss->mss, 1460);

    auto sack = view.sack_perm();
    ASSERT_TRUE(sack.has_value());
    EXPECT_EQ(sack->kind, 4);
    EXPECT_EQ(sack->size, 2);

    auto ts = view.timestamp();
    ASSERT_TRUE(ts.has_value());
    EXPECT_EQ(ts->tv, 0x7e7d3817);
    EXPECT_EQ(ts->tr, 0x00000000);

    auto ws = view.win_scale();
    ASSERT_TRUE(ws.has_value());
    EXPECT_EQ(ws->shift_cnt, 10);

    EXPECT_TRUE(view.has_option(netparser::TcpOptionKind::MSS));
    EXPECT_TRUE(view.has_option(netparser::TcpOptionKind::SACK_PERM));
    EXPECT_TRUE(view.has_option(netparser::TcpOptionKind::TIMESTAMP));
    EXPECT_TRUE(view.has_option(netparser::TcpOptionKind::WIN_SCALE));
}