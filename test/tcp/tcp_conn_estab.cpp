// test_handshake.cpp
#include "include/tcp_common.hpp"
#include <gmock/gmock.h>

using namespace testing;

class TcpConnHandshake : public TcpConnectionTest {};

// Mirrors TestTcpConnEstab: peer sends SYN, we respond with SYN-ACK, peer ACKs.
TEST_F(TcpConnHandshake, PassiveOpen_SynAckSent)
{
    // Expect exactly one SYN-ACK to be sent
    EXPECT_CALL(output(), send(
        AllOf(
            ResultOf([](const TcpSegment& s){ return s.syn(); }, true),
            ResultOf([](const TcpSegment& s){ return s.ack(); }, true)
        ),
        _, _
    )).WillOnce(Return(44));

    auto iph  = helpers::make_ip({.src = PEER_IP, .dst = LOCAL_IP});
    auto syn  = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN,
        .syn   = true,
    });

    auto iph_d  = iph.serialize();
    auto tcph_d = syn.serialize();
    passive_open(netparser::IpHeaderView{iph_d}, netparser::TcpHeaderView{tcph_d});

    ASSERT_EQ(conn_.get_state(), TcpState::SYN_RCVD);
}

TEST_F(TcpConnHandshake, PassiveOpen_HandshakeCompletes)
{
    // SYN-ACK goes out during open_passive
    EXPECT_CALL(output(), send).WillOnce(Return(44));

    auto iph    = helpers::make_ip({.src = PEER_IP, .dst = LOCAL_IP});
    auto syn    = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN,
        .syn   = true,
    });
    auto iph_d  = iph.serialize();
    auto syn_d  = syn.serialize();
    passive_open(netparser::IpHeaderView{iph_d}, netparser::TcpHeaderView{syn_d});
    Mock::VerifyAndClearExpectations(&output());

    // No output expected on final ACK
    EXPECT_CALL(output(), send).Times(0);

    auto ack = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN + 1,
        .ackn  = get_send_iss() + 1,
        .ack   = true,
    });
    auto ack_d = ack.serialize();
    conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});

    ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1);  // consumed the SYN
}

class TcpConnActiveOpen : public TcpConnectionTest {};

TEST_F(TcpConnActiveOpen, SendsSyn)
{
    EXPECT_CALL(output(), send(
        AllOf(
            ResultOf([](const TcpSegment& s){ return s.syn(); }, true),
            ResultOf([](const TcpSegment& s){ return s.ack(); }, false)
        ),
        _, _
    )).WillOnce(Return(44));

    active_open(LOCAL_IP, LOCAL_PORT, PEER_IP, PEER_PORT);

    ASSERT_EQ(conn_.get_state(), TcpState::SYN_SENT);
}

TEST_F(TcpConnActiveOpen, HandshakeCompletes)
{
    EXPECT_CALL(output(), send).WillOnce(Return(44));

    active_open(LOCAL_IP, LOCAL_PORT, PEER_IP, PEER_PORT);
    const std::uint32_t our_isn = get_send_iss();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_CALL(output(), send(
        ResultOf([](const TcpSegment& s){ return s.ack() && !s.syn(); }, true),
        _, _
    )).WillOnce(Return(44));

    auto synack = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN,
        .ackn  = our_isn + 1,
        .syn   = true,
        .ack   = true,
    });
    auto synack_d = synack.serialize();
    conn_.on_packet(netparser::TcpHeaderView{synack_d}, {});

    ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1);
    ASSERT_EQ(send_una(), our_isn + 1);
}