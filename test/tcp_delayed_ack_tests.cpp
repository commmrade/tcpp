//
// Created by klewy on 5/6/26.
//

#include "tcp_conn_test.hpp"
#include <gmock/gmock.h>

class TcpDelAckTest : public TcpConnectionTest
{
protected:
    // peer_send variant that does NOT set up a write expectation
    void peer_send_no_ack(const std::uint32_t seqn, std::span<const std::byte> payload, bool fin = false)
    {
        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT, .dport  = LOCAL_PORT,
            .seqn   = seqn,
            .ackn   = get_send_iss() + 1,
            .window = 65535,
            .ack    = true,
            .fin    = fin,
        });
        const auto seg_d = seg.serialize();
        const netparser::TcpHeaderView seg_view{seg_d};
        conn_.on_packet(seg_view, payload);
    }

    void advance_clock(const std::int64_t ms)
    {
        static_cast<FakeClock&>(get_clock()).advance(ms);
    }
};
TEST_F(TcpDelAckTest, SingleSmallSegment_NoImmediateAck)
{
    do_handshake();

    // One segment well below 2*RMSS — no ACK should be sent immediately
    std::vector<std::byte> payload(100, std::byte{0xAA});

    EXPECT_CALL(mock_io_, write(_)).Times(0);
    peer_send_no_ack(PEER_ISN + 1, payload);
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpDelAckTest, SingleSmallSegment_AckAfterTimeout)
{
    do_handshake();

    std::vector<std::byte> payload(100, std::byte{0xAA});

    EXPECT_CALL(mock_io_, write(_)).Times(0);
    peer_send_no_ack(PEER_ISN + 1, payload);
    Mock::VerifyAndClearExpectations(&mock_io_);

    // Advance clock just under 200ms — still no ACK
    advance_clock(199);
    EXPECT_CALL(mock_io_, write(_)).Times(0);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);

    // Advance past 200ms — ACK fires
    advance_clock(1);
    EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpDelAckTest, TwoSegmentsReaching2Rmss_ImmediateAck)
{
    do_handshake();

    const auto rmss = recv_mss();
    std::vector<std::byte> p1(rmss, std::byte{1});
    std::vector<std::byte> p2(rmss, std::byte{2});

    // First segment — below threshold, no ACK
    EXPECT_CALL(mock_io_, write(_)).Times(0);
    peer_send_no_ack(PEER_ISN + 1, p1);
    Mock::VerifyAndClearExpectations(&mock_io_);

    // Second segment pushes total to 2*RMSS — immediate ACK
    EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE));
    peer_send_no_ack(PEER_ISN + 1 + rmss, p2);
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpDelAckTest, PiggybackOnOutgoingData)
{
    do_handshake();

    // Peer sends data — delayed ACK armed, no immediate ACK
    std::vector<std::byte> incoming(100, std::byte{0xBB});
    EXPECT_CALL(mock_io_, write(_)).Times(0);
    peer_send_no_ack(PEER_ISN + 1, incoming);
    Mock::VerifyAndClearExpectations(&mock_io_);

    // We have data to send — on_tick should piggyback ACK on the data segment
    std::vector<std::byte> outgoing(send_mss(), std::byte{0xCC});
    write(outgoing);

    // on_tick triggers send — one write (data + piggybacked ACK), not two separate writes
    EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + send_mss()));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpDelAckTest, MultipleSmallSegments_AckFiresOncAtTimeout)
{
    do_handshake();

    std::vector<std::byte> p(50, std::byte{1});

    EXPECT_CALL(mock_io_, write(_)).Times(0);
    peer_send_no_ack(PEER_ISN + 1,      p);
    peer_send_no_ack(PEER_ISN + 1 + 50, p);
    peer_send_no_ack(PEER_ISN + 1 + 100, p);
    Mock::VerifyAndClearExpectations(&mock_io_);

    // Only one ACK at timeout, not three
    advance_clock(200);
    EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}
