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

// ====================================

class TcpConnSenderZwp : public TcpConnectionTest {};

// Peer closes window — stack starts ZWP after RTO, backs off exponentially
TEST_F(TcpConnSenderZwp, ProbesWithBackoff)
{
    conn_.set_option(ConnectionOption::QUICKACK, true);
    conn_.set_option(ConnectionOption::NODELAY, true);
    do_handshake();

    // Write data and send it
    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    const std::uint32_t seq_after = get_send_nxt();
    Mock::VerifyAndClearExpectations(&output());

    // Peer ACKs data but advertises window=0
    EXPECT_CALL(output(), send).Times(0);
    auto wnd_close = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = seq_after,
        .window = 0,
        .ack    = true,
    });

    write(data); // Add data to Sender ZWP is started because it isn't started if send buffer is empty

    auto wnd_close_d = wnd_close.serialize();
    conn_.on_packet(netparser::TcpHeaderView{wnd_close_d}, {});
    Mock::VerifyAndClearExpectations(&output());

    // Write more data — queued but not sent (window=0)


    // ZWP not fired yet
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(500);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // First ZWP fires — 1 byte probe
    EXPECT_CALL(output(), send(
        _, 1u, _  // max_size_pl == 1 means probe
    )).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(600); // ~1000ms total
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // Peer ACKs probe but window still 0
    auto probe_ack = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = seq_after,
        .window = 0,
        .ack    = true,
    });
    auto probe_ack_d = probe_ack.serialize();
    conn_.on_packet(netparser::TcpHeaderView{probe_ack_d}, {});

    // Second ZWP — RTO doubled ~2000ms, not yet
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(1500);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_CALL(output(), send(
        _, 1u, _  // max_size_pl == 1 means probe
    )).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(600); // ~2000ms after first
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // Peer ACKs probe but window still 0
    conn_.on_packet(netparser::TcpHeaderView{probe_ack_d}, {});

    // Third ZWP — RTO doubled ~4000ms, not yet
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(3500);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    EXPECT_CALL(output(), send(
    _, 1u, _  // max_size_pl == 1 means probe
    )).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(600); // ~4000ms after second
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}

// Window reopens after ZWP — stack resumes sending data
TEST_F(TcpConnSenderZwp, ResumesAfterWindowReopens)
{
    conn_.set_option(ConnectionOption::QUICKACK, true);
    conn_.set_option(ConnectionOption::NODELAY, true);
    do_handshake();

    // Write and send data
    std::vector<std::byte> data(100);
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    write(data);
    conn_.on_tick();
    const std::uint32_t seq_after = get_send_nxt();
    Mock::VerifyAndClearExpectations(&output());

    // Peer closes window
    auto wnd_close = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = seq_after,
        .window = 0,
        .ack    = true,
    });
    auto wnd_close_d = wnd_close.serialize();

    // Queue more data
    write(data); // Add data to Sender ZWP is started because it isn't started if send buffer is empty

    conn_.on_packet(netparser::TcpHeaderView{wnd_close_d}, {});

    // First ZWP fires
    EXPECT_CALL(output(), send).WillOnce(Return(44));
    static_cast<FakeClock&>(get_clock()).advance(1100);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());

    // Peer reopens window
    EXPECT_CALL(output(), send(
        ResultOf([](const TcpSegment& s){ return s.payload_size() > 0 && !s.fin(); }, true),
        _, Gt(0u)
    )).WillOnce(Return(44));

    auto wnd_open = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = seq_after,
        .window = 65535,
        .ack    = true,
    });
    auto wnd_open_d = wnd_open.serialize();
    conn_.on_packet(netparser::TcpHeaderView{wnd_open_d}, {});
    conn_.on_tick(); // flush queued data. r_timer is started here!!

    // ACK the flushed data
    auto ack_data = helpers::make_tcp({
        .sport  = PEER_PORT, .dport = LOCAL_PORT,
        .seqn   = PEER_ISN + 1,
        .ackn   = get_send_nxt(), // ACKs everything sent so far
        .window = 65535,
        .ack    = true,
    });
    auto ack_data_d = ack_data.serialize();
    conn_.on_packet(netparser::TcpHeaderView{ack_data_d}, {});

    // ZWP timer must be stopped
    EXPECT_CALL(output(), send).Times(0);
    static_cast<FakeClock&>(get_clock()).advance(5000);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&output());
}