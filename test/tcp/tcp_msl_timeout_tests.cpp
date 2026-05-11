//
// Created by klewy on 5/11/26.
//
#include "include/tcp_common.hpp"
#include <gmock/gmock.h>

class TcpConnMslTimeoutTest : public TcpConnectionTest
{
protected:
    static constexpr std::int64_t TWO_MSL_MS = 60'000;

    // Perform active close from our side:
    // conn_.shutdown() -> we send FIN -> peer ACKs -> peer sends FIN -> we ACK -> TIME_WAIT
    void do_active_close()
    {
        // We initiate close — FIN is sent on next tick
        EXPECT_CALL(output(), send).Times(AnyNumber());
        conn_.shutdown(ShutdownType::WRITE);
        conn_.on_tick(); // sends FIN
        Mock::VerifyAndClearExpectations(&output());

        // Peer ACKs our FIN
        peer_send_ack(get_send_nxt()); // ACKs the FIN byte

        // Peer sends its own FIN (simultaneous or sequential)
        peer_send_fin(PEER_ISN + 1);

        // We ACK peer's FIN — transition to TIME_WAIT
        EXPECT_CALL(output(), send).Times(AnyNumber());
        conn_.on_tick();
        Mock::VerifyAndClearExpectations(&output());
    }

    // Send a pure ACK from peer (no payload)
    void peer_send_ack(const std::uint32_t ackn)
    {
        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN + 1,
            .ackn   = ackn,
            .window = 65535,
            .ack    = true,
        });
        const auto seg_d = seg.serialize();
        const netparser::TcpHeaderView seg_view{seg_d};
        conn_.on_packet(seg_view, {});
    }

    // Send FIN from peer
    void peer_send_fin(const std::uint32_t seqn)
    {
        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = seqn,
            .ackn   = get_send_nxt(),
            .window = 65535,
            .ack    = true,
            .fin    = true,
        });
        const auto seg_d = seg.serialize();
        const netparser::TcpHeaderView seg_view{seg_d};
        conn_.on_packet(seg_view, {});
    }

    void advance_clock(const std::int64_t ms)
    {
        static_cast<FakeClock&>(get_clock()).advance(ms);
    }
};

// After active close sequence completes, connection must be in TIME_WAIT, not CLOSED yet.
TEST_F(TcpConnMslTimeoutTest, EntersTimeWaitAfterActiveClose)
{
    do_handshake();
    do_active_close();

    EXPECT_EQ(conn_.get_state(), TcpState::TIME_WAIT);
}

// Just under 2MSL — must still be TIME_WAIT.
TEST_F(TcpConnMslTimeoutTest, StaysInTimeWaitBefore2Msl)
{
    do_handshake();
    do_active_close();

    advance_clock(TWO_MSL_MS - 1);
    EXPECT_CALL(output(), send).Times(AnyNumber());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(conn_.get_state(), TcpState::TIME_WAIT);
}

// Exactly at 2MSL boundary — must transition to CLOSED.
TEST_F(TcpConnMslTimeoutTest, TransitionToClosedAt2Msl)
{
    do_handshake();
    do_active_close();

    advance_clock(TWO_MSL_MS);
    EXPECT_CALL(output(), send).Times(AnyNumber());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(conn_.get_state(), TcpState::CLOSED);
}

// No data must be accepted in TIME_WAIT.
TEST_F(TcpConnMslTimeoutTest, TimeWaitDropsIncomingData)
{
    do_handshake();
    do_active_close();

    ASSERT_EQ(conn_.get_state(), TcpState::TIME_WAIT);

    // Peer retransmits data — we should send ACK but not change state
    // (RFC 9293: in TIME_WAIT, retransmitted FIN gets re-ACKed, 2MSL restarts)
    EXPECT_CALL(output(), send).Times(AnyNumber());
    peer_send_fin(PEER_ISN + 1); // retransmit of peer FIN
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(conn_.get_state(), TcpState::TIME_WAIT);
}

// RFC 9293: retransmitted FIN in TIME_WAIT restarts the 2MSL timer.
TEST_F(TcpConnMslTimeoutTest, RetransmittedFinResets2MslTimer)
{
    do_handshake();
    do_active_close();

    // Advance almost to timeout
    advance_clock(TWO_MSL_MS - 100);
    EXPECT_CALL(output(), send).Times(AnyNumber());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
    ASSERT_EQ(conn_.get_state(), TcpState::TIME_WAIT);

    // Peer retransmits FIN — 2MSL timer should restart
    EXPECT_CALL(output(), send).Times(AnyNumber());
    peer_send_fin(PEER_ISN + 2);
    Mock::VerifyAndClearExpectations(&output());

    // Another almost-full 2MSL after the reset — should still be TIME_WAIT
    advance_clock(TWO_MSL_MS - 1);
    EXPECT_CALL(output(), send).Times(AnyNumber());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(conn_.get_state(), TcpState::TIME_WAIT);

    // Now expire
    advance_clock(1);
    EXPECT_CALL(output(), send).Times(AnyNumber());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(conn_.get_state(), TcpState::CLOSED);
}