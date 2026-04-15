//
// Created by klewy on 4/13/26.
//

#include "tcp_conn_test.hpp"
#include <limits>

using namespace testing;

class TcpConnectionSenderSwsTest : public TcpConnectionTest {};
class TcpConnectionReceiverSwsTest : public TcpConnectionTest {};

TEST_F(TcpConnectionReceiverSwsTest, NotCond1) {
    do_handshake();

    auto data_seg = helpers::make_tcp({
                    .sport = PEER_PORT, .dport = LOCAL_PORT,
                    .seqn  = PEER_ISN + 1,
                    .ackn  = get_send_iss(),
                    .window = 65535,
                    .ack   = true,
                    .mss = 0,
            });
    const auto data_seg_d = data_seg.serialize();
    const netparser::TcpHeaderView data_seg_view{data_seg_d};
    std::array<std::byte, 500> payload{};
    conn_.on_packet(data_seg_view, payload);
    ASSERT_EQ(get_recv_win(), std::numeric_limits<std::uint16_t>::max() - payload.size());
    // should not move the right edge
    const auto right_edge_old = right_edge();
    const auto rd = conn_.read(payload.data(), 20);
    ASSERT_EQ(rd, 20);

    conn_.on_tick();
    upd_recv_win();
    ASSERT_EQ(get_recv_win(), std::numeric_limits<std::uint16_t>::max() - payload.size());

}

TEST_F(TcpConnectionReceiverSwsTest, Cond1) {
    do_handshake();

    auto data_seg = helpers::make_tcp({
                    .sport = PEER_PORT, .dport = LOCAL_PORT,
                    .seqn  = PEER_ISN + 1,
                    .ackn  = get_send_iss(),
                    .window = 65535,
                    .ack   = true,
                    .mss = 0,
            });
    const auto data_seg_d = data_seg.serialize();
    const netparser::TcpHeaderView data_seg_view{data_seg_d};
    std::array<std::byte, 500> payload{};
    conn_.on_packet(data_seg_view, payload);
    ASSERT_EQ(get_recv_win(), std::numeric_limits<std::uint16_t>::max() - payload.size());
    // should not move the right edge
    const auto rd = conn_.read(payload.data(), 500);
    ASSERT_EQ(rd, 500);

    conn_.on_tick();
    upd_recv_win();
    ASSERT_NE(get_recv_win(), std::numeric_limits<std::uint16_t>::max());
}


TEST_F(TcpConnectionSenderSwsTest, Cond1)
{
    do_handshake();
    std::array<char, 536> buf{};
    [[maybe_unused]] const auto written = conn_.write(buf.data(), buf.size());
    const auto send_size = sizeof(buf) + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE; // So payload + iph + tcph is sent and returned
    // 1. MIN(D,U) => (536 >= Send MSS) => true
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionSenderSwsTest, Cond2)
{
    do_handshake(400);
    std::array<char, 200> buf{};
    const auto written = conn_.write(buf.data(), buf.size());
    const auto send_size = sizeof(buf) + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // 1. MIN(D,U) => (200 < Send MSS) => false
    // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (200) <= USABLE_WND (400)) => true
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionSenderSwsTest, SenderSws3)
{
    // send_wnd_max_ = 500, Fs * max = 0.5 * 500 = 250
    do_handshake(500);
    std::array<char, 600> buf{};
    const auto sent = conn_.write(buf.data(), buf.size());
    const auto send_size = 500 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // 1. MIN(D,U) => (200 < Send MSS) => false
    // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (600) > USABLE_WND (500)) => false
    // 3. ([SND.NXT = SND.UNA] && min(D, U) (500) >= (1/2 * MAX_WND_SIZE) (250) => true
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionSenderSwsTest, SenderSws4)
{
    do_handshake(500);
    std::array<char, 900> buf{};
    const auto written = conn_.write(buf.data(), 500);
    const auto send_size = 500 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // 1. MIN(D,U) => (500 < Send MSS) => false
    // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (500) <= USABLE_WND (500)) => true
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
    auto ack = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN + 1,
            .ackn  = get_send_iss() + 500, // size of packet we sent
            .window = 100,
            .ack   = true,
            .mss = 0,
    });
    const auto ack_data = ack.serialize();
    const netparser::TcpHeaderView ack_view{ack_data};
    conn_.on_packet(ack_view, {});
    const auto sent = conn_.write(buf.data(), 200);
    const auto send_size2 = 200 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // Make sure write isnt even called, since timer is supposed to start
    // 1. MIN(D,U) => (100 < Send MSS) => false
    // 2. ([SND.NXT = SND.UNA] PUSHED && DATA_QUEUE_SIZE (200) > USABLE_WND (100)) => false
    // 3. ([SND.NXT = SND.UNA] && min(D, U) (100) >= (1/2 * MAX_WND_SIZE) (250) => false
    // 4. Timer starts
    EXPECT_CALL(mock_io_, write(_, _)).Times(0);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);

    // Make sure it fires after SWS_OVERRIDE_MS.
    static_cast<FakeClock&>(get_clock()).advance(RttMeasurement::SWS_OVERRIDE_MS / 2);
    EXPECT_CALL(mock_io_, write).Times(0);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);

    static_cast<FakeClock&>(get_clock()).advance(RttMeasurement::SWS_OVERRIDE_MS / 2);
    EXPECT_CALL(mock_io_, write).Times(1);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}
