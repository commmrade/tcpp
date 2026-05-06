//
// Created by klewy on 5/5/26.
//
#include "tcp_conn_test.hpp"
#include <gmock/gmock.h>

using namespace testing;

class TcpReceiverBufTest : public TcpConnectionTest
{
protected:
    // Sends an arbitrary segment from the peer side.
    // Always expects exactly one write() call (ACK or dup-ACK).
    void peer_send(const std::uint32_t seqn,
                   std::span<const std::byte> payload,
                   const bool fin = false)
    {
        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT,
            .dport  = LOCAL_PORT,
            .seqn   = seqn,
            .ackn   = get_send_iss() + 1,
            .window = 65535,
            .ack    = true,
            .fin    = fin,
        });
        const auto seg_d = seg.serialize();
        const netparser::TcpHeaderView seg_view{seg_d};

        EXPECT_CALL(mock_io_, write(_)).Times(AnyNumber());
        conn_.on_packet(seg_view, payload);
        Mock::VerifyAndClearExpectations(&mock_io_);
    }

    ssize_t conn_read(void* buf, const std::size_t n)
    {
        return conn_.read(buf, n);
    }
};

// -------------------------------------------------------------------
// Test 1: read all data, then read again → EOF (0)
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, ReadDataThenFin_ReturnsDataThenEof)
{
    do_handshake();

    constexpr std::size_t DATA_LEN = 200;
    std::vector<std::byte> payload(DATA_LEN);
    std::memset(payload.data(), 'A', DATA_LEN);

    // In-order data segment: seq [PEER_ISN+1, PEER_ISN+201)
    peer_send(PEER_ISN + 1, payload);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1 + DATA_LEN);

    // FIN: seq = PEER_ISN+201, no payload
    peer_send(PEER_ISN + 1 + DATA_LEN, {}, /*fin=*/true);

    // Read all data
    std::vector<std::byte> read_buf(DATA_LEN + 64, std::byte{0});
    ssize_t n = conn_read(read_buf.data(), read_buf.size());
    ASSERT_EQ(n, static_cast<ssize_t>(DATA_LEN));
    ASSERT_EQ(std::memcmp(read_buf.data(), payload.data(), DATA_LEN), 0);

    // Second read: FIN consumed → EOF
    n = conn_read(read_buf.data(), read_buf.size());
    ASSERT_EQ(n, 0);
}

// -------------------------------------------------------------------
// Test 2: partial read doesn't consume more than requested
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, PartialRead_ConsumesOnlyRequested)
{
    do_handshake();

    constexpr std::size_t DATA_LEN = 300;
    std::vector<std::byte> payload(DATA_LEN);
    for (std::size_t i = 0; i < DATA_LEN; ++i)
        payload[i] = static_cast<std::byte>(i & 0xFF);

    peer_send(PEER_ISN + 1, payload);

    std::vector<std::byte> buf(100, std::byte{0});

    ssize_t n = conn_read(buf.data(), 100);
    ASSERT_EQ(n, 100);
    ASSERT_EQ(std::memcmp(buf.data(), payload.data(), 100), 0);

    n = conn_read(buf.data(), 100);
    ASSERT_EQ(n, 100);
    ASSERT_EQ(std::memcmp(buf.data(), payload.data() + 100, 100), 0);

    n = conn_read(buf.data(), 100);
    ASSERT_EQ(n, 100);
    ASSERT_EQ(std::memcmp(buf.data(), payload.data() + 200, 100), 0);
}

// -------------------------------------------------------------------
// Test 3: out-of-order arrival; recv.nxt doesn't advance until gap filled
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, OutOfOrder_RecvNxtHoldsUntilGapFilled)
{
    do_handshake();

    // In-order [0, 1200): seq PEER_ISN+1 .. PEER_ISN+1201
    std::vector<std::byte> p1(1200, std::byte{1});
    peer_send(PEER_ISN + 1, p1);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1201);

    // OOO: [1400, 1500): gap at [1200, 1400)
    std::vector<std::byte> p3(100, std::byte{3});
    peer_send(PEER_ISN + 1401, p3);
    // recv.nxt must NOT advance past the gap
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1201);

    // Fill lower half of gap [1200, 1300)
    std::vector<std::byte> p2a(100, std::byte{2});
    peer_send(PEER_ISN + 1201, p2a);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1301);

    // Fill upper half of gap [1300, 1400): now gap is closed, p3 becomes contiguous
    std::vector<std::byte> p2b(100, std::byte{2});
    peer_send(PEER_ISN + 1301, p2b);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1501);
}

// -------------------------------------------------------------------
// Test 4: single large OOO segment, then in-order fill, recv.nxt jumps
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, OutOfOrder_SingleGapFill_RecvNxtJumps)
{
    do_handshake();

    // OOO first: [500, 1000) — nothing in order yet
    std::vector<std::byte> late(500, std::byte{0xBB});
    peer_send(PEER_ISN + 501, late);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1); // nxt still at start

    // In-order [0, 500): fills the gap, chained with the OOO segment
    std::vector<std::byte> early(500, std::byte{0xAA});
    peer_send(PEER_ISN + 1, early);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1001);

    // Data is readable in order: first 'early', then 'late'
    std::vector<std::byte> buf(1000);
    const ssize_t n = conn_read(buf.data(), buf.size());
    ASSERT_EQ(n, 1000);
    ASSERT_EQ(buf[0],   std::byte{0xAA});
    ASSERT_EQ(buf[499], std::byte{0xAA});
    ASSERT_EQ(buf[500], std::byte{0xBB});
    ASSERT_EQ(buf[999], std::byte{0xBB});
}