//
// Created by klewy on 5/11/26.
//
#include "include/tcp_common.hpp"
#include <gmock/gmock.h>

class TcpConnRetransmit : public TcpConnectionTest {};

TEST_F(TcpConnRetransmit, RetransmitsAfterRto)
{
    do_handshake();

    // Write data — goes into send buffer
    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // RTO hasn't elapsed yet — no retransmit
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(500);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // RTO elapses (~1000ms default) — first retransmit
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(600); // total 1100ms
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // RTO doubled (~2000ms) — no retransmit at 1500ms after first
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(1500);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // RTO doubled fires — second retransmit
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(600); // total ~2100ms after first retransmit
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

TEST_F(TcpConnRetransmit, RtoResetsAfterAck)
{
    do_handshake();

    // Round 1: send, let it retransmit once, then ACK
    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    const std::uint32_t seq_after_first = get_send_nxt();
    Mock::VerifyAndClearExpectations(&output());

    // First retransmit fires
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(1100);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // ACK the data — clears retransmit queue, resets RTO
    EXPECT_CALL(output(), send).Times(AnyNumber()).WillRepeatedly(Return(44));
    auto ack = helpers::make_tcp({
        .sport = PEER_PORT, .dport = LOCAL_PORT,
        .seqn  = PEER_ISN + 1,
        .ackn  = seq_after_first,
        .ack   = true,
    });
    auto ack_d = ack.serialize();
    conn_.on_packet(netparser::TcpHeaderView{ack_d}, {});
    Mock::VerifyAndClearExpectations(&output());

    // Round 2: send again, RTO should be back to base (~1000ms), not doubled
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // Should NOT retransmit before base RTO
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(500);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // Should retransmit at base RTO, not doubled
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(600);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}