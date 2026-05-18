//
// Tests for TCP Timestamps option (RFC 7323):
//   - Negotiation (SYN/SYN-ACK)
//   - RTT measurement via TSecr
//   - PAWS (Protection Against Wrapped Sequences)
//   - TS.Recent / Last.ACK.sent update logic
//   - Karn's algorithm with timestamps
//
// Requires tcp_common.hpp to have tsval/tsecr/has_ts fields in TcpArgs
// and tcph.options().timestamp(tsval, tsecr) called in make_tcp when has_ts=true.
//
#include <gmock/gmock.h>
#include "include/tcp_common.hpp"
#include <cassert>

class TcpConnectionTimestampTest : public TcpConnectionTest
{
protected:
    // Passive-open handshake with TSopt negotiated on both sides.
    // Returns the TSval stamped on our SYN-ACK (= clock value at that point).
    std::uint32_t do_handshake_ts(
        const std::uint16_t send_wnd = std::numeric_limits<std::uint16_t>::max())
    {
        const auto syn_tsval = static_cast<std::uint32_t>(get_clock().now());

        EXPECT_CALL(output(), send).WillOnce(Return(44));
        auto iph = helpers::make_ip({.src = PEER_IP, .dst = LOCAL_IP});
        auto syn = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN,
            .window = send_wnd,
            .syn    = true,
            .tsval  = syn_tsval, .tsecr = 0, .has_ts = true,
        });
        auto iph_d = iph.serialize();
        auto syn_d = syn.serialize();
        passive_open(netparser::IpHeaderView{iph_d}, netparser::TcpHeaderView{syn_d});
        Mock::VerifyAndClearExpectations(&output());

        EXPECT_CALL(output(), send).Times(0);
        auto ack = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN + 1,
            .ackn   = get_send_iss() + 1,
            .window = send_wnd,
            .ack    = true,
            .tsval  = syn_tsval + 1, .tsecr = syn_tsval, .has_ts = true,
        });
        auto ack_d = ack.serialize();
        conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
        Mock::VerifyAndClearExpectations(&output());

        // ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);

        return syn_tsval;
    }

    // Send 100 bytes, advance clock by delay_ms, then ACK with correct TSecr.
    void send_and_ack_ts(const std::uint32_t delay_ms)
    {
        std::vector<std::byte> data(100);
        EXPECT_CALL(output(), send).WillOnce(Return(44));
        write(data);
        conn_.on_tick();
        const auto seq_after  = get_send_nxt();
        const auto tsval_sent = static_cast<std::uint32_t>(get_clock().now());
        Mock::VerifyAndClearExpectations(&output());

        static_cast<FakeClock&>(get_clock()).advance(delay_ms);

        auto ack = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN + 1,
            .ackn   = seq_after,
            .window = 65535,
            .ack    = true,
            .tsval  = tsval_sent + delay_ms,
            .tsecr  = tsval_sent,
            .has_ts = true,
        });
        auto ack_d = ack.serialize();
        EXPECT_CALL(output(), send).Times(0);
        conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
        Mock::VerifyAndClearExpectations(&output());
    }
};

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

TEST_F(TcpConnectionTimestampTest, NegotiationEnabledWhenSynHasTs)
{
    do_handshake_ts();
    EXPECT_TRUE(is_tsopt());
}

TEST_F(TcpConnectionTimestampTest, NegotiationDisabledWhenSynHasNoTs)
{
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    auto iph = helpers::make_ip({.src = PEER_IP, .dst = LOCAL_IP});
    auto syn = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN, .window = 65535, .syn = true,
    });
    auto iph_d = iph.serialize();
    auto syn_d = syn.serialize();
    passive_open(netparser::IpHeaderView{iph_d}, netparser::TcpHeaderView{syn_d});
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_FALSE(is_tsopt());
}

// ---------------------------------------------------------------------------
// TS.Recent initialisation
// ---------------------------------------------------------------------------

TEST_F(TcpConnectionTimestampTest, TsRecentInitialisedFromSyn)
{
    constexpr std::uint32_t SYN_TSVAL = 12345;

    EXPECT_CALL(output(), send).WillOnce(Return(44));
    auto iph = helpers::make_ip({.src = PEER_IP, .dst = LOCAL_IP});
    auto syn = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN, .window = 65535, .syn = true,
        .tsval  = SYN_TSVAL, .tsecr = 0, .has_ts = true,
    });
    auto iph_d = iph.serialize();
    auto syn_d = syn.serialize();

    passive_open(netparser::IpHeaderView{iph_d}, netparser::TcpHeaderView{syn_d});
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(ts_recent(), SYN_TSVAL);
}

// ---------------------------------------------------------------------------
// RTT measurement via TSecr
// ---------------------------------------------------------------------------

TEST_F(TcpConnectionTimestampTest, FirstRttMeasurementViaTs)
{
    do_handshake_ts();
    send_and_ack_ts(400);
    // srtt=400, rttvar=200, rto=400+4*200=1200
    EXPECT_EQ(rtt().rto(), 1200u);
}

TEST_F(TcpConnectionTimestampTest, RttClampedToMinimumViaTs)
{
    do_handshake_ts();
    for (int i = 0; i < 10; ++i)
        send_and_ack_ts(50);
    EXPECT_GE(rtt().rto(), 1000u);
}

TEST_F(TcpConnectionTimestampTest, SecondMeasurementConvergesViaTs)
{
    do_handshake_ts();
    send_and_ack_ts(400); // srtt=400, rttvar=200, rto=1200
    send_and_ack_ts(400); // rttvar=150, rto=1000
    EXPECT_EQ(rtt().rto(), 1000u);
}

TEST_F(TcpConnectionTimestampTest, RtoIncreasesOnJumpingRttViaTs)
{
    do_handshake_ts();
    send_and_ack_ts(400);
    const auto rto_after_first = rtt().rto();
    send_and_ack_ts(800);
    EXPECT_GT(rtt().rto(), rto_after_first);
}

TEST_F(TcpConnectionTimestampTest, RtoDecreasesOnFallingRttViaTs)
{
    do_handshake_ts();
    send_and_ack_ts(800);
    const auto rto_after_first = rtt().rto();
    send_and_ack_ts(400);
    EXPECT_LT(rtt().rto(), rto_after_first);
}

// ACK that does not advance SND.UNA must NOT update RTT
TEST_F(TcpConnectionTimestampTest, DuplicateAckDoesNotUpdateRtt)
{
    do_handshake_ts();
    send_and_ack_ts(400);
    const auto rto_after_first = rtt().rto();

    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    const auto tsval_sent = static_cast<std::uint32_t>(get_clock().now());
    const auto seq_after  = get_send_nxt();
    Mock::VerifyAndClearExpectations(&output());

    static_cast<FakeClock&>(get_clock()).advance(200);

    auto dup_ack = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = seq_after - 101, // old seq — SND.UNA does not advance
        .window = 65535,
        .ack    = true,
        .tsval  = tsval_sent + 200, .tsecr = tsval_sent, .has_ts = true,
    });
    auto dup_d = dup_ack.serialize();
    EXPECT_CALL(output(), send).Times(AnyNumber());
    conn_.on_packet(netparser::TcpHeaderView{dup_d}, {});
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(rtt().rto(), rto_after_first);
}

// ---------------------------------------------------------------------------
// Karn's algorithm with timestamps
// ---------------------------------------------------------------------------

TEST_F(TcpConnectionTimestampTest, KarnsAlgorithmWithTs)
{
    do_handshake_ts();

    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    const auto seq_after  = get_send_nxt();
    const auto tsval_sent = static_cast<std::uint32_t>(get_clock().now());
    Mock::VerifyAndClearExpectations(&output());

    const auto rto_before = rtt().rto();

    // RTO expires → retransmit
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(rto_before);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // Ambiguous ACK: TSecr still points at original TSval
    auto ack = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = seq_after,
        .window = 65535,
        .ack    = true,
        .tsval  = tsval_sent + rto_before + 50,
        .tsecr  = tsval_sent,
        .has_ts = true,
    });
    auto ack_d = ack.serialize();
    EXPECT_CALL(output(), send).Times(0);
    conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
    Mock::VerifyAndClearExpectations(&output());

    // Must be doubled RTO, not a fresh sample
    EXPECT_GT(rtt().rto(), rto_before);
}

// ---------------------------------------------------------------------------
// PAWS
// ---------------------------------------------------------------------------

TEST_F(TcpConnectionTimestampTest, PawsDropsOldDuplicate)
{
    do_handshake_ts();
    send_and_ack_ts(100); // drive TS.Recent forward
    const auto ts_recent_now = ts_recent();
    const auto old_recv_nxt  = recv_nxt();

    std::vector<std::byte> payload(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44)); // challenge ACK
    auto stale = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = get_send_nxt(),
        .window = 65535,
        .ack    = true,
        .tsval  = ts_recent_now - 1, .tsecr = 0, .has_ts = true,
    });
    auto stale_d = stale.serialize();
    conn_.on_packet(netparser::TcpHeaderView{stale_d}, payload);
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(recv_nxt(), old_recv_nxt);
}

TEST_F(TcpConnectionTimestampTest, PawsAcceptsEqualTimestamp)
{
    do_handshake_ts();
    const auto ts_recent_now = ts_recent();
    const auto old_recv_nxt  = recv_nxt();
    std::vector<std::byte> payload(100);

    EXPECT_CALL(output(), send).Times(AnyNumber());
    auto seg = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = get_send_nxt(),
        .window = 65535,
        .ack    = true,
        .tsval  = ts_recent_now, .tsecr = 0, .has_ts = true,
    });
    auto seg_d = seg.serialize();
    conn_.on_packet(netparser::TcpHeaderView{seg_d}, payload);
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_GT(recv_nxt(), old_recv_nxt);
}

// ---------------------------------------------------------------------------
// TS.Recent update logic
// ---------------------------------------------------------------------------

// Out-of-order segment must NOT update TS.Recent
TEST_F(TcpConnectionTimestampTest, TsRecentNotUpdatedByOutOfOrderSegment)
{
    do_handshake_ts();

    // Deliver segment A (in order)
    constexpr std::uint32_t TSVAL_A = 500;
    std::vector<std::byte> payload_a(100);
    EXPECT_CALL(output(), send).Times(AnyNumber());
    auto seg_a = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = get_send_nxt(),
        .window = 65535,
        .ack    = true,
        .tsval  = TSVAL_A, .tsecr = 0, .has_ts = true,
    });
    auto seg_a_d = seg_a.serialize();
    conn_.on_packet(netparser::TcpHeaderView{seg_a_d}, payload_a);
    Mock::VerifyAndClearExpectations(&output());

    const auto ts_recent_after_a = ts_recent();

    // Deliver segment C out of order (B is missing)
    constexpr std::uint32_t TSVAL_C = 700;
    std::vector<std::byte> payload_c(100);
    EXPECT_CALL(output(), send).Times(AnyNumber());
    auto seg_c = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1 + 200, // gap where B would be
        .ackn   = get_send_nxt(),
        .window = 65535,
        .ack    = true,
        .tsval  = TSVAL_C, .tsecr = 0, .has_ts = true,
    });
    auto seg_c_d = seg_c.serialize();
    conn_.on_packet(netparser::TcpHeaderView{seg_c_d}, payload_c);
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_EQ(ts_recent(), ts_recent_after_a);
}