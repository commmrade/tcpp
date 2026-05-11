//
// Created by klewy on 5/11/26.
//
#include "include/tcp_common.hpp"
#include <gmock/gmock.h>

class TcpConnActiveTeardown : public TcpConnectionTest {};
class TcpConnPassiveTeardown : public TcpConnectionTest {};

// Active close: we initiate
// us: close() → on_tick() → FIN → peer ACKs → peer FIN+ACK → us ACK → TIME_WAIT
TEST_F(TcpConnActiveTeardown, FullSequence)
{
    do_handshake();

    EXPECT_CALL(output(), send(
        ResultOf([](const TcpSegment& s){ return s.fin(); }, true),
        _, _
    )).WillOnce(Return(44));
    conn_.close();
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
    ASSERT_EQ(conn_.get_state(), TcpState::FIN_WAIT_1);

    EXPECT_CALL(output(), send).Times(0);
    auto peer_ack = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN + 1,
        .ackn  = get_send_nxt(),
        .ack   = true,
    });
    auto peer_ack_d = peer_ack.serialize();
    conn_.on_packet(netparser::TcpHeaderView{peer_ack_d}, {});
    Mock::VerifyAndClearExpectations(&output());
    ASSERT_EQ(conn_.get_state(), TcpState::FIN_WAIT_2);

    EXPECT_CALL(output(), send(
        ResultOf([](const TcpSegment& s){ return s.ack() && !s.fin(); }, true),
        _, _
    )).Times(AnyNumber()).WillRepeatedly(Return(44));
    // FIXME: I wanna use WilLOnce return here, but now i cant because it delays ack for fin
    auto peer_fin = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN + 1,
        .ackn  = get_send_nxt(),
        .ack   = true,
        .fin   = true,
    });
    auto peer_fin_d = peer_fin.serialize();
    std::println("LAST ON PACKET-----");
    conn_.on_packet(netparser::TcpHeaderView{peer_fin_d}, {});

    ASSERT_EQ(conn_.get_state(), TcpState::TIME_WAIT);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 2);
}

// Passive close: peer initiates
// peer FIN+ACK → us ACK → us close() → on_tick() → FIN → peer ACKs → CLOSED
TEST_F(TcpConnPassiveTeardown, FullSequence)
{
    do_handshake();

    EXPECT_CALL(output(), send(
        ResultOf([](const TcpSegment& s){ return s.ack() && !s.fin(); }, true),
        _, _
    )).Times(AnyNumber()).WillRepeatedly(Return(44));
    // FIXME: I wanna use WilLOnce return here, but now i cant because it delays ack for fin
    auto peer_fin = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN + 1,
        .ackn  = get_send_nxt(),
        .ack   = true,
        .fin   = true,
    });
    auto peer_fin_d = peer_fin.serialize();
    conn_.on_packet(netparser::TcpHeaderView{peer_fin_d}, {});
    Mock::VerifyAndClearExpectations(&output());
    ASSERT_EQ(conn_.get_state(), TcpState::CLOSE_WAIT);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 2);

    EXPECT_CALL(output(), send(
        ResultOf([](const TcpSegment& s){ return s.fin(); }, true),
        _, _
    )).Times(AnyNumber()).WillRepeatedly(Return(44));
    // FIXME: I wanna use WilLOnce return here, but now i cant because it delays ack for fin
    conn_.close();
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
    ASSERT_EQ(conn_.get_state(), TcpState::LAST_ACK);

    EXPECT_CALL(output(), send).Times(0);
    auto peer_ack = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN + 2,
        .ackn  = get_send_nxt(),
        .ack   = true,
    });
    auto peer_ack_d = peer_ack.serialize();
    conn_.on_packet(netparser::TcpHeaderView{peer_ack_d}, {});

    ASSERT_EQ(conn_.get_state(), TcpState::CLOSED);
}