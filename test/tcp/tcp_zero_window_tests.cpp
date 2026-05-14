//
// Created by klewy on 5/15/26.
//
#include <gmock/gmock.h>
#include "include/tcp_common.hpp"

class TcpConnZeroWindow : public TcpConnectionTest {};

// Fill receive buffer until advertised window hits zero
TEST_F(TcpConnZeroWindow, WindowClosesWhenBufferFull)
{
    conn_.set_option(ConnectionOption::QUICKACK, true);
    conn_.set_option(ConnectionOption::NODELAY, true);
    do_handshake();

    // Send data until window closes
    std::uint32_t peer_seq = PEER_ISN + 1;
    std::uint32_t bytes_sent = 0;
    const std::uint32_t initial_wnd = get_recv_win();

    while (get_recv_win() > 0) {
        const std::size_t chunk = std::min<std::size_t>(recv_mss(), get_recv_win());
        std::vector<std::byte> payload(chunk);

        EXPECT_CALL(output(), send).WillOnce(Return(44));

        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = peer_seq,
            .ackn   = get_send_nxt(),
            .window = 65535,
            .ack    = true,
        });
        auto seg_d = seg.serialize();
        conn_.on_packet(netparser::TcpHeaderView{seg_d}, payload);
        Mock::VerifyAndClearExpectations(&output());

        peer_seq  += chunk;
        bytes_sent += chunk;
    }

    ASSERT_EQ(get_recv_win(), 0u);
    ASSERT_GT(bytes_sent, 0u);
}

// Stack must ACK zero-window probes (1-byte segments) even when window is zero
TEST_F(TcpConnZeroWindow, AcksProbesWhenWindowClosed)
{
    conn_.set_option(ConnectionOption::QUICKACK, true);
    conn_.set_option(ConnectionOption::NODELAY, true);
    do_handshake();

    // Fill receive buffer
    std::uint32_t peer_seq = PEER_ISN + 1;
    while (get_recv_win() > 0) {
        const std::size_t chunk = std::min<std::size_t>(recv_mss(), get_recv_win());
        std::vector<std::byte> payload(chunk);

        EXPECT_CALL(output(), send).WillOnce(Return(44));
        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = peer_seq,
            .ackn   = get_send_nxt(),
            .window = 65535,
            .ack    = true,
        });
        auto seg_d = seg.serialize();
        conn_.on_packet(netparser::TcpHeaderView{seg_d}, payload);
        Mock::VerifyAndClearExpectations(&output());
        peer_seq += chunk;
    }

    ASSERT_EQ(get_recv_win(), 0u);

    // Send 3 probes — each must elicit an ACK with window=0
    for (int i = 0; i < 3; ++i) {
        std::vector<std::byte> probe_payload(1);

        EXPECT_CALL(output(), send(
            AllOf(
                ResultOf([](const TcpSegment& s){ return s.ack(); }, true),
                ResultOf([](const TcpSegment& s){ return s.ackn(); }, peer_seq)
            ),
            _, 0u  // advertised window must be zero
        )).WillOnce(Return(44));

        auto probe = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = peer_seq - 1,
            .ackn   = get_send_nxt(),
            .window = 65535,
            .ack    = true,
        });
        auto probe_d = probe.serialize();
        conn_.on_packet(netparser::TcpHeaderView{probe_d}, probe_payload);
        Mock::VerifyAndClearExpectations(&output());
    }
}

// Window reopens after application reads data
TEST_F(TcpConnZeroWindow, WindowReopensAfterRead)
{
    conn_.set_option(ConnectionOption::QUICKACK, true);
    conn_.set_option(ConnectionOption::NODELAY, true);
    do_handshake();

    // Fill receive buffer
    std::uint32_t peer_seq = PEER_ISN + 1;
    while (get_recv_win() > 0) {
        const std::size_t chunk = std::min<std::size_t>(recv_mss(), get_recv_win());
        std::vector<std::byte> payload(chunk);

        EXPECT_CALL(output(), send).WillOnce(Return(44));
        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT, .dport = LOCAL_PORT,
            .seqn   = peer_seq,
            .ackn   = get_send_nxt(),
            .window = 65535,
            .ack    = true,
        });
        auto seg_d = seg.serialize();
        conn_.on_packet(netparser::TcpHeaderView{seg_d}, payload);
        Mock::VerifyAndClearExpectations(&output());
        peer_seq += chunk;
    }

    ASSERT_EQ(get_recv_win(), 0u);

    // Application reads data — window should reopen
    std::vector<std::byte> read_buf(recv_mss() * 2);
    const ssize_t n = conn_.read(read_buf.data(), read_buf.size());
    ASSERT_GT(n, 0);

    upd_recv_win();
    ASSERT_GT(get_recv_win(), 0u);

    // Probe arrives — ACK should now advertise non-zero window
    std::vector<std::byte> probe_payload(1);
    EXPECT_CALL(output(), send(
        ResultOf([](const TcpSegment& s){ return s.ack(); }, true),
        _, Gt(0u)  // window must be > 0
    )).WillOnce(Return(44));

    auto probe = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = peer_seq,
        .ackn   = get_send_nxt(),
        .window = 65535,
        .ack    = true,
    });
    auto probe_d = probe.serialize();
    conn_.on_packet(netparser::TcpHeaderView{probe_d}, probe_payload);
}

