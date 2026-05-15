//
// Created by klewy on 5/15/26.
//
#include <gmock/gmock.h>
#include "include/tcp_common.hpp"

class TcpConnectionRtoTest : public TcpConnectionTest
{
protected:
    // Send data, advance clock by delay_ms, then ACK it
    void send_and_ack(const std::uint32_t delay_ms)
    {
        std::vector<std::byte> data(100);
        EXPECT_CALL(output(), send).WillOnce(Return(44));
        write(data);
        conn_.on_tick();
        const std::uint32_t seq_after = get_send_nxt();
        Mock::VerifyAndClearExpectations(&output());

        static_cast<FakeClock&>(get_clock()).advance(delay_ms);

        auto ack = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = PEER_ISN + 1,
            .ackn   = seq_after,
            .window = 65535,
            .ack    = true,
        });
        auto ack_d = ack.serialize();
        EXPECT_CALL(output(), send).Times(0);
        conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
        Mock::VerifyAndClearExpectations(&output());
    }
};

// Default RTO before any measurement
TEST_F(TcpConnectionRtoTest, DefaultRto)
{
    do_handshake();
    EXPECT_EQ(rtt().rto(), 1000u);
}

// First RTT measurement: srtt=R, rttvar=R/2, rto=srtt+4*rttvar=3R, but min 1000
TEST_F(TcpConnectionRtoTest, FirstMeasurement)
{
    do_handshake();
    send_and_ack(200); // RTT = 200ms

    // srtt=200, rttvar=100, rto=200+4*100=600 -> clamped to 1000
    EXPECT_EQ(rtt().rto(), 1000u);
}

TEST_F(TcpConnectionRtoTest, FirstMeasurementLargeRtt)
{
    do_handshake();
    send_and_ack(400); // RTT = 400ms

    // srtt=400, rttvar=200, rto=400+4*200=1200 -> above minimum
    EXPECT_EQ(rtt().rto(), 1200u);
}

// Second measurement updates srtt/rttvar via EWMA
TEST_F(TcpConnectionRtoTest, SecondMeasurementConverges)
{
    do_handshake();
    send_and_ack(400); // first: srtt=400, rttvar=200, rto=1200
    send_and_ack(400); // second: same RTT, rttvar shrinks toward 0

    // rttvar = 0.75*200 + 0.25*|400-400| = 150
    // srtt   = 0.875*400 + 0.125*400     = 400
    // rto    = 400 + 4*150 = 1000
    EXPECT_EQ(rtt().rto(), 1000u);
}

TEST_F(TcpConnectionRtoTest, RtoIncreasesOnHigherRtt)
{
    do_handshake();
    send_and_ack(400);
    const std::uint32_t rto_after_first = rtt().rto();
    send_and_ack(800); // RTT jumps

    EXPECT_GT(rtt().rto(), rto_after_first);
}

TEST_F(TcpConnectionRtoTest, RtoDecreasesOnLowerRtt)
{
    do_handshake();
    send_and_ack(800);
    const std::uint32_t rto_after_first = rtt().rto();
    send_and_ack(400);

    EXPECT_LT(rtt().rto(), rto_after_first);
}

// RTO never goes below 1000ms
TEST_F(TcpConnectionRtoTest, RtoNeverBelowMinimum)
{
    do_handshake();
    for (int i = 0; i < 10; ++i)
        send_and_ack(50); // very low RTT

    EXPECT_GE(rtt().rto(), 1000u);
}

// Retransmit fires exactly at RTO boundary
TEST_F(TcpConnectionRtoTest, RetransmitFiresAtRto)
{
    do_handshake();
    send_and_ack(400); // rto=1200ms now

    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    const std::uint32_t current_rto = rtt().rto();

    // Just before RTO — no retransmit
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(current_rto - 1);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // At RTO — retransmit fires
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(1);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

// No RTT sample taken on retransmitted segment (Karn's algorithm)
TEST_F(TcpConnectionRtoTest, NoRttSampleOnRetransmit)
{
    do_handshake();

    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    const std::uint32_t seq_after = get_send_nxt();
    Mock::VerifyAndClearExpectations(&output());

    const std::uint32_t rto_before = rtt().rto();

    // Let RTO expire -> retransmit
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(rto_before);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // ACK arrives — should NOT update RTO (ambiguous ACK)
    auto ack = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = seq_after,
        .window = 65535,
        .ack    = true,
    });
    auto ack_d = ack.serialize();
    EXPECT_CALL(output(), send).Times(0);
    conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
    Mock::VerifyAndClearExpectations(&output());

    // RTO должен быть удвоен (exponential backoff), а не пересчитан по RTT
    EXPECT_GT(rtt().rto(), rto_before);
}