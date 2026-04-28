//
// Created by klewy on 4/13/26.
//

#include "tcp_conn_test.hpp"
#include <limits>

using namespace testing;

class TcpConnectionSenderSwsTest : public TcpConnectionTest {};

class TcpConnectionReceiverSwsTest : public TcpConnectionTest {};


// Below threshold: no window update
TEST_F(TcpConnectionReceiverSwsTest, BelowThreshold_NoWindowUpdate)
{
    do_handshake();
    send_data_to_conn(1539); // fill buffer with 1539 bytes
    const auto wnd_before = get_recv_win();

    std::array<char, 64000> rd_buf{};
    conn_.read(rd_buf.data(), 1539); // consume all: free_space grows by 1539, increment = 1539 < 1540

    conn_.on_tick();
    upd_recv_win();

    ASSERT_EQ(get_recv_win(), wnd_before); // no update
}

// Exactly at threshold: window update fires
TEST_F(TcpConnectionReceiverSwsTest, AtThreshold_WindowUpdated)
{
    do_handshake();
    send_data_to_conn(1540);
    const auto wnd_before = get_recv_win();

    std::array<char, 64000> rd_buf{};
    conn_.read(rd_buf.data(), 1540); // increment == 1540 == threshold
    conn_.on_tick();
    upd_recv_win();

    ASSERT_GT(get_recv_win(), wnd_before);
}

// Above threshold: window update fires
TEST_F(TcpConnectionReceiverSwsTest, AboveThreshold_WindowUpdated)
{
    do_handshake();
    send_data_to_conn(2000);
    const auto wnd_before = get_recv_win();

    std::array<char, 64000> rd_buf{};
    conn_.read(rd_buf.data(), 2000);
    conn_.on_tick();
    upd_recv_win();

    ASSERT_GT(get_recv_win(), wnd_before);
}

// Partial read below threshold: no update
TEST_F(TcpConnectionReceiverSwsTest, PartialRead_BelowThreshold_NoUpdate)
{
    do_handshake();
    send_data_to_conn(2000);
    const auto wnd_before = get_recv_win();

    std::array<char, 64000> rd_buf{};
    conn_.read(rd_buf.data(), 500); // only 500 consumed, increment < 1540
    conn_.on_tick();
    upd_recv_win();

    ASSERT_EQ(get_recv_win(), wnd_before);
}

// Buffer half-size threshold: when buf/2 < MSS, threshold = buf/2
// Not applicable here since buf/2 = 32767 > MSS = 1540, so MSS always wins.
// But test it anyway if buf size is ever changed.

// Window already reflects free space (wnd_size == free_space): increment = 0, no update
TEST_F(TcpConnectionReceiverSwsTest, NoConsumption_NoUpdate)
{
    do_handshake();
    send_data_to_conn(1540);
    conn_.on_tick();
    upd_recv_win();
    const auto wnd_after_recv = get_recv_win();

    // No read, tick again
    conn_.on_tick();
    upd_recv_win();

    ASSERT_EQ(get_recv_win(), wnd_after_recv);
}

TEST_F(TcpConnectionSenderSwsTest, Cond1)
{
    do_handshake();
    std::array<std::byte, 536> buf{};
    [[maybe_unused]] const auto written = conn_.write(buf);
    const auto send_size = sizeof(buf) + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // So payload + iph + tcph is sent and returned
    // 1. MIN(D,U) => (536 >= Send MSS) => true
    EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionSenderSwsTest, Cond2)
{
    do_handshake(400);
    std::array<std::byte, 200> buf{};
    const auto written = conn_.write(buf);
    const auto send_size = sizeof(buf) + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // 1. MIN(D,U) => (200 < Send MSS) => false
    // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (200) <= USABLE_WND (400)) => true
    EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionSenderSwsTest, SenderSws3)
{
    // send_wnd_max_ = 500, Fs * max = 0.5 * 500 = 250
    do_handshake(500);
    std::array<std::byte, 600> buf{};
    const auto sent = conn_.write(buf);
    const auto send_size = 500 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // 1. MIN(D,U) => (200 < Send MSS) => false
    // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (600) > USABLE_WND (500)) => false
    // 3. ([SND.NXT = SND.UNA] && min(D, U) (500) >= (1/2 * MAX_WND_SIZE) (250) => true
    EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}
//
// TEST_F(TcpConnectionSenderSwsTest, SenderSws4)
// {
//     do_handshake(500);
//     std::array<std::byte, 900> buf{};
//     const auto written = conn_.write(std::span{buf.data(), 500});
//     const auto send_size = 500 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
//     // 1. MIN(D,U) => (500 < Send MSS) => false
//     // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (500) <= USABLE_WND (500)) => true
//     EXPECT_CALL(mock_io_, write(_)).WillOnce(Return(send_size));
//     conn_.on_tick();
//     Mock::VerifyAndClearExpectations(&mock_io_);
//     auto ack = helpers::make_tcp({
//         .sport = PEER_PORT, .dport = LOCAL_PORT,
//         .seqn = PEER_ISN + 1,
//         .ackn = get_send_iss() + 500,// size of packet we sent
//         .window = 100,
//         .ack = true,
//         .mss = 0,
//     });
//     const auto ack_data = ack.serialize();
//     const netparser::TcpHeaderView ack_view{ ack_data };
//     conn_.on_packet(ack_view, {});
//     const auto sent = conn_.write(std::span{buf.data(), 200});
//     const auto send_size2 = 200 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
//     // Make sure write isnt even called, since timer is supposed to start
//     // 1. MIN(D,U) => (100 < Send MSS) => false
//     // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (200) > USABLE_WND (100)) => false
//     // 3. ([SND.NXT = SND.UNA] && min(D, U) (100) >= (1/2 * MAX_WND_SIZE) (250) => false
//     // 4. Timer starts
//     EXPECT_CALL(mock_io_, write(_)).Times(0);
//     conn_.on_tick();
//     Mock::VerifyAndClearExpectations(&mock_io_);
//
//     // Make sure it fires after SWS_OVERRIDE_MS.
//     static_cast<FakeClock &>(get_clock()).advance(RttMeasurement::SWS_OVERRIDE_MS / 2);
//     EXPECT_CALL(mock_io_, write).Times(0);
//     conn_.on_tick();
//     Mock::VerifyAndClearExpectations(&mock_io_);
//
//     static_cast<FakeClock &>(get_clock()).advance(RttMeasurement::SWS_OVERRIDE_MS / 2);
//     EXPECT_CALL(mock_io_, write).Times(1).WillOnce(Return(139));
//     conn_.on_tick();
//     Mock::VerifyAndClearExpectations(&mock_io_);
// }