//
// Created by klewy on 5/25/26.
//

// Created by klewy
// Tests for TCP Slow Start (RFC 5681)

#include "include/tcp_common.hpp"
#include <gmock/gmock.h>
#include <limits>

class TcpSlowStartTest : public TcpConnectionTest
{
protected:
    void advance_clock(const std::int64_t ms)
    {
        static_cast<FakeClock&>(get_clock()).advance(ms);
    }

    // Write exactly one SMSS to send buffer and flush via on_tick.
    // Returns SND.NXT after the segment is sent.
    std::uint32_t send_one_segment()
    {
        const std::size_t smss = send_mss();
        std::vector<std::byte> data(smss);
        EXPECT_CALL(output(), send)
            .WillOnce(Return(static_cast<ssize_t>(
                netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
        write(data);
        conn_.on_tick();
        Mock::VerifyAndClearExpectations(&output());
        return get_send_nxt();
    }

    // Deliver a pure ACK from the peer. Expects no output (nothing queued).
    void peer_ack(const std::uint32_t ackn, const std::uint16_t wnd = 65535)
    {
        auto ack = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN + 1,
            .ackn   = ackn,
            .window = wnd,
            .ack    = true,
        });
        const auto ack_d = ack.serialize();
        EXPECT_CALL(output(), send).Times(0);
        conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
        Mock::VerifyAndClearExpectations(&output());
    }
};

// ─── Initial state ─────────────────────────────────────────────────────────

// RFC 5681 §3.1: IW depends on SMSS.
TEST_F(TcpSlowStartTest, InitialCwndEqualsIW)
{
    do_handshake();
    const auto smss = send_mss();

    std::uint32_t expected_iw;
    if (smss > 2190)
        expected_iw = 2 * smss;
    else if (smss > 1095)
        expected_iw = 3 * smss;
    else
        expected_iw = 4 * smss;

    EXPECT_EQ(cong_cwnd(), expected_iw);
}

// RFC 5681 §3.1: ssthresh SHOULD be set arbitrarily high initially.
TEST_F(TcpSlowStartTest, InitialSsthreshIsArbitrarilyHigh)
{
    do_handshake();
    EXPECT_GE(cong_ssthresh(),
              static_cast<std::uint32_t>(std::numeric_limits<std::uint16_t>::max()));
}

// ─── cwnd growth in slow start ─────────────────────────────────────────────

// RFC 5681 §3.1: cwnd += min(N, SMSS) per ACK of new data.
// When one full SMSS segment is ACKed, N == SMSS, so cwnd grows by exactly SMSS.
TEST_F(TcpSlowStartTest, CwndGrowsBySmssOnSingleAck)
{
    do_handshake();
    const auto smss      = send_mss();
    const auto cwnd_before = cong_cwnd();

    const auto seq_after = send_one_segment();
    peer_ack(seq_after);

    EXPECT_EQ(cong_cwnd(), cwnd_before + smss);
}

// After N ACKs of full-sized segments, cwnd == IW + N*SMSS.
TEST_F(TcpSlowStartTest, CwndGrowsBySmssForEachAck)
{
    do_handshake();
    const auto smss = send_mss();
    const auto iw   = cong_cwnd();

    for (std::uint32_t i = 1; i <= 4; ++i) {
        const auto seq_after = send_one_segment();
        peer_ack(seq_after);
        EXPECT_EQ(cong_cwnd(), iw + i * smss)
            << "after ACK #" << i;
    }
}

// ACK of a partial segment (N < SMSS) must only add N bytes, not a full SMSS.
// Guards against the ACK-division attack mitigation: cwnd += min(N, SMSS).
TEST_F(TcpSlowStartTest, CwndGrowsByAckedBytesWhenPartialAck)
{
    do_handshake();
    const auto smss  = send_mss();
    const std::size_t half = smss / 2;

    // Send exactly half an SMSS
    std::vector<std::byte> data(half);
    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + half)));
    write(data);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    const auto cwnd_before = cong_cwnd();
    peer_ack(get_send_nxt());

    // N = half < SMSS → cwnd grows by half, not SMSS
    EXPECT_EQ(cong_cwnd(), cwnd_before + half);
}

// ─── RTO handling ──────────────────────────────────────────────────────────

// RFC 5681 §3.1: on RTO, cwnd = LW = 1 SMSS.
TEST_F(TcpSlowStartTest, RtoResetsCwndToLW)
{
    do_handshake();
    const auto smss = send_mss();

    send_one_segment(); // leave unACKed

    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(cong_cwnd(), static_cast<std::uint32_t>(smss));
}

// RFC 5681 §3.1: on RTO, ssthresh = max(FlightSize/2, 2*SMSS).
TEST_F(TcpSlowStartTest, RtoSetsSsthreshToHalfFlightSize)
{
    do_handshake();
    const auto smss = send_mss();

    // Send 2 segments unACKed → FlightSize = 2*SMSS.
    // IW >= 2*SMSS always, so cwnd allows this.
    {
        std::vector<std::byte> data(2 * smss);
        EXPECT_CALL(output(), send)
            .Times(AnyNumber())
            .WillRepeatedly(Return(static_cast<ssize_t>(
                netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
        write(data);
        conn_.on_tick();
        Mock::VerifyAndClearExpectations(&output());
    }

    const std::uint32_t flight_size       = get_send_nxt() - send_una();
    const std::uint32_t expected_ssthresh = std::max(flight_size / 2, 2u * smss);

    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(cong_ssthresh(), expected_ssthresh);
}

// FlightSize = SMSS → ssthresh = max(SMSS/2, 2*SMSS) = 2*SMSS (floor at 2*SMSS).
TEST_F(TcpSlowStartTest, RtoSsthreshFloorIsTwoSmss)
{
    do_handshake();
    const auto smss = send_mss();

    send_one_segment(); // FlightSize = 1*SMSS

    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(cong_ssthresh(), 2u * smss);
}

// ─── Slow start restart after RTO ──────────────────────────────────────────

// After RTO, cwnd = SMSS. Receiving an ACK should increment cwnd by SMSS (still SS).
TEST_F(TcpSlowStartTest, SlowStartRestartsAfterRto)
{
    do_handshake();
    const auto smss = send_mss();

    const auto seq_after = send_one_segment();

    // RTO fires → retransmit
    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    ASSERT_EQ(cong_cwnd(), static_cast<std::uint32_t>(smss));

    // ACK the retransmit — cwnd should grow from LW
    peer_ack(seq_after);
    EXPECT_EQ(cong_cwnd(), 2u * smss);
}

// ─── ssthresh held constant on repeated RTO (same segment) ─────────────────

// RFC 5681 §3.1: if the segment has already been retransmitted via RTO,
// ssthresh MUST NOT be updated on a second RTO for that segment.
TEST_F(TcpSlowStartTest, SsthreshHeldConstantOnConsecutiveRto)
{
    do_handshake();
    const auto smss = send_mss();

    send_one_segment();

    // First RTO — ssthresh is updated
    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    const auto ssthresh_after_first_rto = cong_ssthresh();

    // Second RTO (exponential backoff — rtt().rto() is already doubled)
    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // ssthresh MUST remain unchanged
    EXPECT_EQ(cong_ssthresh(), ssthresh_after_first_rto);
}

// Tests verifying cwnd is wired into the send path.
// These will be red until cwnd is factored into handle_send's usable window.

class TcpSlowStartSendTest : public TcpConnectionTest
{
protected:
    void advance_clock(const std::int64_t ms)
    {
        static_cast<FakeClock&>(get_clock()).advance(ms);
    }

    // Deliver a pure ACK from peer. No send expected (sends happen on on_tick only).
    void peer_ack(const std::uint32_t ackn, const std::uint16_t wnd = 65535)
    {
        auto ack = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN + 1,
            .ackn   = ackn,
            .window = wnd,
            .ack    = true,
        });
        const auto ack_d = ack.serialize();
        EXPECT_CALL(output(), send).Times(0);
        conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
        Mock::VerifyAndClearExpectations(&output());
    }
};

// Writing far more data than IW should result in exactly IW/SMSS segments sent,
// not the full buffer.
TEST_F(TcpSlowStartSendTest, CwndLimitsInitialBurst)
{
    do_handshake();
    const auto smss    = send_mss();
    const auto iw      = cong_cwnd();
    const auto iw_segs = static_cast<int>(iw / smss);

    std::vector<std::byte> data(iw * 3); // far more than IW
    write(data);

    EXPECT_CALL(output(), send)
        .Times(iw_segs)
        .WillRepeatedly(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

// Fill the pipe to exactly IW. ACK 1 segment — cwnd grows by SMSS, FlightSize
// drops by SMSS. Effective window opens by 2*SMSS. With 1 SMSS queued, 1 send.
TEST_F(TcpSlowStartSendTest, AckGrowsCwndAndUnblocksOneSend)
{
    do_handshake();
    const auto smss    = send_mss();
    const auto iw      = cong_cwnd();
    const auto iw_segs = static_cast<int>(iw / smss);

    // Fill pipe to IW
    std::vector<std::byte> data(iw);
    write(data);
    EXPECT_CALL(output(), send)
        .Times(iw_segs)
        .WillRepeatedly(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // ACK first segment:
    //   cwnd      = IW + SMSS
    //   FlightSize = IW - SMSS
    //   effective  = 2*SMSS
    const auto una_before = send_una();
    peer_ack(una_before + smss);

    // Queue exactly 1 SMSS of new data
    std::vector<std::byte> more(smss);
    write(more);

    // effective=2*SMSS but only 1 SMSS unsent → exactly 1 send
    EXPECT_CALL(output(), send)
        .Times(1)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

// After RTO: cwnd = SMSS, FlightSize = SMSS (retransmit in flight).
// Effective window = 0 → no new data should be sent.
TEST_F(TcpSlowStartSendTest, RtoResetCwndBlocksNewSends)
{
    do_handshake();
    const auto smss = send_mss();

    // Send 1 segment, leave unACKed
    {
        std::vector<std::byte> data(smss);
        EXPECT_CALL(output(), send)
            .WillOnce(Return(static_cast<ssize_t>(
                netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
        write(data);
        conn_.on_tick();
        Mock::VerifyAndClearExpectations(&output());
    }

    // RTO fires → retransmit, cwnd = SMSS (LW), FlightSize still = SMSS
    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    ASSERT_EQ(cong_cwnd(), static_cast<std::uint32_t>(smss));

    // Queue more data — effective window = cwnd - FlightSize = SMSS - SMSS = 0
    std::vector<std::byte> more(smss * 3);
    write(more);

    EXPECT_CALL(output(), send).Times(0);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

// After RTO, ACK the retransmit. cwnd grows to 2*SMSS, FlightSize = 0.
// Should now be able to send exactly 2 segments.
TEST_F(TcpSlowStartSendTest, AfterRtoAckReopensCwndToTwoSegments)
{
    do_handshake();
    const auto smss = send_mss();

    // Send 1 segment
    std::vector<std::byte> data(smss);
    write(data);
    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    const auto seq_after = get_send_nxt();
    Mock::VerifyAndClearExpectations(&output());

    // RTO fires → cwnd = SMSS
    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // ACK retransmit: FlightSize = 0, cwnd grows to 2*SMSS
    peer_ack(seq_after);
    ASSERT_EQ(cong_cwnd(), 2u * smss);

    // Queue 5 segments — only 2 should be sent (cwnd = 2*SMSS)
    std::vector<std::byte> more(smss * 5);
    write(more);

    EXPECT_CALL(output(), send)
        .Times(2)
        .WillRepeatedly(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

// ═══════════════════════════════════════════════════════════════════════════
// Congestion Avoidance (RFC 5681 §3.1)
// cwnd >= ssthresh: cwnd += SMSS*SMSS/cwnd per ACK (min 1 byte)
// ═══════════════════════════════════════════════════════════════════════════

class TcpCongAvoidTest : public TcpConnectionTest
{
protected:
    void advance_clock(const std::int64_t ms)
    {
        static_cast<FakeClock&>(get_clock()).advance(ms);
    }

    // Pure ACK from peer. Sends only happen in on_tick, not on_packet.
    void peer_ack(const std::uint32_t ackn, const std::uint16_t wnd = 65535)
    {
        auto ack = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN + 1,
            .ackn   = ackn,
            .window = wnd,
            .ack    = true,
        });
        const auto ack_d = ack.serialize();
        EXPECT_CALL(output(), send).Times(0);
        conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
        Mock::VerifyAndClearExpectations(&output());
    }

    std::uint32_t send_one_segment()
    {
        const auto smss = send_mss();
        std::vector<std::byte> data(smss);
        EXPECT_CALL(output(), send)
            .WillOnce(Return(static_cast<ssize_t>(
                netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
        write(data);
        conn_.on_tick();
        Mock::VerifyAndClearExpectations(&output());
        return get_send_nxt();
    }

    // Brings connection into CA state:
    //   RTO with 1 segment in flight → ssthresh = 2*SMSS, cwnd = SMSS
    //   ACK retransmit (SS) → cwnd = 2*SMSS = ssthresh
    //   Next ACK will use CA formula.
    void enter_congestion_avoidance()
    {
        const auto smss = send_mss();

        // Send 1 segment, leave unACKed
        {
            std::vector<std::byte> data(smss);
            EXPECT_CALL(output(), send)
                .WillOnce(Return(static_cast<ssize_t>(
                    netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
            write(data);
            conn_.on_tick();
            seq_after_initial_ = get_send_nxt();
            Mock::VerifyAndClearExpectations(&output());
        }

        // RTO: ssthresh = max(SMSS/2, 2*SMSS) = 2*SMSS, cwnd = SMSS
        EXPECT_CALL(output(), send)
            .WillOnce(Return(static_cast<ssize_t>(
                netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
        advance_clock(rtt().rto());
        conn_.on_tick();
        Mock::VerifyAndClearExpectations(&output());

        // ACK retransmit — SS: cwnd goes from SMSS → 2*SMSS = ssthresh
        peer_ack(seq_after_initial_);

        ASSERT_EQ(cong_cwnd(), 2u * smss);
        ASSERT_EQ(cong_ssthresh(), 2u * smss);
        // cwnd == ssthresh: next ACK triggers CA
    }

    std::uint32_t seq_after_initial_{0};
};

// ─── cwnd update ───────────────────────────────────────────────────────────

// cwnd += SMSS*SMSS/cwnd exactly.
TEST_F(TcpCongAvoidTest, CaIncrementMatchesFormula)
{
    do_handshake();
    enter_congestion_avoidance();

    const auto smss            = send_mss();
    const auto cwnd_before     = cong_cwnd(); // 2*SMSS
    const auto expected_inc    = std::max<std::uint32_t>(smss * smss / cwnd_before, 1);
    const auto expected_cwnd   = cwnd_before + expected_inc;

    const auto seq_after = send_one_segment();
    peer_ack(seq_after);

    EXPECT_EQ(cong_cwnd(), expected_cwnd);
}

// CA increment must be strictly less than SMSS (slower than slow start).
TEST_F(TcpCongAvoidTest, CaIncrementSlowerThanSlowStart)
{
    do_handshake();
    enter_congestion_avoidance();

    const auto smss        = send_mss();
    const auto cwnd_before = cong_cwnd();

    const auto seq_after = send_one_segment();
    peer_ack(seq_after);

    const auto increment = cong_cwnd() - cwnd_before;
    EXPECT_LT(increment, static_cast<std::uint32_t>(smss));
}

// Each successive CA increment should be <= the previous one (cwnd grows → divisor grows).
TEST_F(TcpCongAvoidTest, CaIncrementDecreasesOverTime)
{
    do_handshake();
    enter_congestion_avoidance();

    std::uint32_t prev_increment = std::numeric_limits<std::uint32_t>::max();

    for (int i = 0; i < 4; ++i) {
        const auto cwnd_before = cong_cwnd();
        const auto seq_after   = send_one_segment();
        peer_ack(seq_after);
        const auto increment = cong_cwnd() - cwnd_before;

        EXPECT_LE(increment, prev_increment) << "increment grew at step " << i;
        prev_increment = increment;
    }
}

// After N ACKs in CA, total cwnd growth must be less than N*SMSS
// (which would be the slow start growth for the same number of ACKs).
TEST_F(TcpCongAvoidTest, CaTotalGrowthLessThanSlowStart)
{
    do_handshake();
    enter_congestion_avoidance();

    const auto smss       = send_mss();
    const auto cwnd_start = cong_cwnd();
    constexpr int N       = 6;

    for (int i = 0; i < N; ++i) {
        const auto seq_after = send_one_segment();
        peer_ack(seq_after);
    }

    const auto total_growth = cong_cwnd() - cwnd_start;
    EXPECT_LT(total_growth, static_cast<std::uint32_t>(N) * smss);
}

// ─── ssthresh stability ────────────────────────────────────────────────────

// ssthresh must not change during normal CA operation.
TEST_F(TcpCongAvoidTest, SsthreshUnchangedDuringCa)
{
    do_handshake();
    enter_congestion_avoidance();

    const auto ssthresh_before = cong_ssthresh();

    for (int i = 0; i < 5; ++i) {
        const auto seq_after = send_one_segment();
        peer_ack(seq_after);
    }

    EXPECT_EQ(cong_ssthresh(), ssthresh_before);
}

// ─── RTO during CA ─────────────────────────────────────────────────────────

// RTO during CA: ssthresh = max(FlightSize/2, 2*SMSS), cwnd = LW = SMSS.
TEST_F(TcpCongAvoidTest, RtoDuringCaSetsSsthreshAndResetsCwnd)
{
    do_handshake();
    enter_congestion_avoidance();

    const auto smss = send_mss();

    // A few ACKs to grow cwnd past 2*SMSS
    for (int i = 0; i < 3; ++i) {
        const auto seq = send_one_segment();
        peer_ack(seq);
    }

    // Send and leave unACKed so FlightSize > 0
    send_one_segment();
    const std::uint32_t flight_size       = get_send_nxt() - send_una();
    const std::uint32_t expected_ssthresh = std::max(flight_size / 2, 2u * smss);

    EXPECT_CALL(output(), send)
        .WillOnce(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    advance_clock(rtt().rto());
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(cong_ssthresh(), expected_ssthresh);
    EXPECT_EQ(cong_cwnd(), static_cast<std::uint32_t>(smss));
}

// ─── send path ─────────────────────────────────────────────────────────────

// In CA, cwnd = 2*SMSS limits sends to 2 segments even if more data is queued.
TEST_F(TcpCongAvoidTest, CaCwndLimitsSends)
{
    do_handshake();
    enter_congestion_avoidance();

    const auto smss = send_mss();
    // cwnd = 2*SMSS, FlightSize = 0 → effective = 2*SMSS → 2 segments max

    std::vector<std::byte> data(smss * 6);
    write(data);

    EXPECT_CALL(output(), send)
        .Times(2)
        .WillRepeatedly(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

// After one CA ACK, cwnd grew by SMSS*SMSS/cwnd.
// The send path must reflect the new (larger) cwnd.
TEST_F(TcpCongAvoidTest, CaCwndGrowthUnblocksExactlyOneMoreSegment)
{
    do_handshake();
    enter_congestion_avoidance();

    const auto smss = send_mss();

    // Fill pipe to cwnd (2*SMSS)
    std::vector<std::byte> fill(2 * smss);
    write(fill);
    EXPECT_CALL(output(), send)
        .Times(2)
        .WillRepeatedly(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // ACK 1 segment: cwnd grows by SMSS*SMSS/cwnd, FlightSize drops by SMSS
    const auto una_before = send_una();
    peer_ack(una_before + smss);

    // New effective = new_cwnd - FlightSize
    // cwnd grew by < SMSS, so effective < 2*SMSS — not enough for 2 more
    // but effective > 0 — enough for at least the partial window
    const auto new_cwnd     = cong_cwnd();
    const auto flight       = get_send_nxt() - send_una();
    const auto effective    = new_cwnd > flight ? new_cwnd - flight : 0u;
    const auto expected_sends = static_cast<int>(
        (effective + smss - 1) / smss  // ceiling division
    );

    std::vector<std::byte> more(smss * 4);
    write(more);

    EXPECT_CALL(output(), send)
        .Times(expected_sends)
        .WillRepeatedly(Return(static_cast<ssize_t>(
            netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE + smss)));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}