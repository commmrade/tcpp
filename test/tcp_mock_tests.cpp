//
// Created by klewy on 4/13/26.
//

// #include "../src/tcpp/clock.hpp"
#include "../src/tcpp/clock.hpp"
#include "../src/tcpp/tun.hpp"
#include "../src/tcpp/net/conn.hpp"
#include <gmock/gmock.h>

using namespace testing;

class MockTun : public IOInterface
{
public:
    virtual ~MockTun() = default;
    MOCK_METHOD(ssize_t, write, (const void* buf, const std::size_t buf_size), (override));
};

class FakeClock : public ClockInterface
{
public:
    virtual ~FakeClock() = default;
    std::int64_t now() const override { return now_ms_; }
    void advance(const std::int64_t adv_ms)
    {
        now_ms_ += adv_ms;
    }
private:
    int64_t now_ms_{0};
};

namespace helpers {
    struct IpArgs {
        std::uint32_t src;
        std::uint32_t dst;
        std::uint8_t  ttl     = 64;
        std::uint16_t total_len = netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    };

    struct TcpArgs {
        std::uint16_t sport;
        std::uint16_t dport;
        std::uint32_t seqn    = 0;
        std::uint32_t ackn    = 0;
        std::uint16_t window  = 65535;
        bool          syn     = false;
        bool          ack     = false;
        bool          fin     = false;
        bool          rst     = false;
        std::uint16_t mss     = 0;       // 0 = don't add MSS option
    };

    netparser::IpHeader make_ip(const IpArgs& a) {
        netparser::IpHeader iph{};
        iph.version(4);
        iph.ihl(5);
        iph.type_of_service(0);
        iph.total_len(a.total_len);
        iph.id(0);
        iph.dont_fragment(true);
        iph.more_fragments(false);
        iph.frag_offset(0);
        iph.ttl(a.ttl);
        iph.protocol(IPPROTO_TCP);
        iph.source_addr(a.src);
        iph.dest_addr(a.dst);
        iph.calculate_checksum();
        return iph;
    }

    netparser::TcpHeader make_tcp(const TcpArgs& a) {
        netparser::TcpHeader tcph{};
        tcph.source_port(a.sport);
        tcph.dest_port(a.dport);
        tcph.seqn(a.seqn);
        tcph.ackn(a.ackn);
        tcph.syn(a.syn);
        tcph.ack(a.ack);
        tcph.fin(a.fin);
        tcph.rst(a.rst);
        tcph.window(a.window);
        tcph.urg(false);
        tcph.urg_ptr(0);
        if (a.mss != 0) {
            tcph.options().mss(a.mss);
        }
        const auto hdr_size = netparser::TCPH_MIN_SIZE + tcph.options().options_size();
        tcph.data_off(static_cast<std::uint8_t>(hdr_size / 4));
        tcph.calculate_checksum(make_ip({a.sport, a.dport}), {});  // placeholder, real checksum done in send()
        return tcph;
    }

} // namespace helpers

class TcpConnectionTest : public testing::Test
{
protected:
    static constexpr std::uint32_t PEER_IP  = 0x0A000001; // 10.0.0.1
    static constexpr std::uint32_t LOCAL_IP = 0x0A000002; // 10.0.0.2
    static constexpr std::uint16_t PEER_PORT  = 12345;
    static constexpr std::uint16_t LOCAL_PORT = 8090;
    static constexpr std::uint32_t PEER_ISN  = 1000;
    MockTun mock_io_;
    TcpConnection conn_{mock_io_, std::make_unique<Clock>()};

    void do_handshake(const std::uint16_t send_wnd_size)
    {
        EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(44));

        auto iph = helpers::make_ip({.src = PEER_IP, .dst = LOCAL_IP});
        auto syn  = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN,
            .syn   = true,
            .window = send_wnd_size,
        });

        auto iph_data = iph.serialize();
        auto tcph_data = syn.serialize();

        netparser::IpHeaderView iph_view{iph_data};
        netparser::TcpHeaderView tcph_view{tcph_data};
        conn_.accept(iph_view, tcph_view);
        Mock::VerifyAndClearExpectations(&mock_io_);

        EXPECT_CALL(mock_io_, write(_, _)).Times(0);
        auto ack = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN + 1,
            .ackn  = conn_.send_.iss + 1,
            .ack   = true,
            .window = send_wnd_size
        });
        auto ack_data = ack.serialize();
        netparser::TcpHeaderView ack_view{ack_data};
        conn_.on_packet(ack_view, {});
        Mock::VerifyAndClearExpectations(&mock_io_);

        ASSERT_EQ(conn_.send_.wnd, send_wnd_size);
    }
};

TEST_F(TcpConnectionTest, HandshakeMock)
{
    do_handshake(65535);
    ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);
}

TEST_F(TcpConnectionTest, SenderSws1)
{
    do_handshake(65535);
    ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);

    char buf[536]{};
    std::memset(buf, 'c', sizeof(buf));
    // Now we shall expect, that the first SWS sender condition will fire
    const auto written = conn_.write(buf, sizeof(buf));
    // At this point, a maximum sized segment can be sent, (536 is default)

    const auto send_size = sizeof(buf) + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE; // So payload + iph + tcph is sent and returned
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionTest, SenderSws2)
{
    do_handshake(400);
    // FIXME: Factor out this assert to do_handshake()
    ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);

    char buf[200]{};
    std::memset(buf, 'c', sizeof(buf));
    const auto written = conn_.write(buf, sizeof(buf));
    // Second condition should fire, because (nagle)[SND.NXT == SND.UNA] && QUEUED_DATA_N <= USABLE_WINDOW_N and first cond min(D,U) < SEND_MSS (5360
    const auto send_size = sizeof(buf) + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionTest, SenderSws3)
{
    // send_wnd_max_ = 500, Fs * max = 0.5 * 500 = 250
    do_handshake(500);
    ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);

    // First fails, since Min(d,u) is 500 and this < send.mss
    // Second fails, because data_n > unsent_n
    // Third works, because min(d,u) (500) >= 1/2 * 500 (250)
    char buf[600]{};
    std::memset(buf, 'c', sizeof(buf));
    const auto sent = conn_.write(buf, sizeof(buf));

    const auto send_size = 500 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionTest, SenderSws4)
{
    do_handshake(500);
    // FIXME: Factor out this assert to do_handshake()
    ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);

    char buf[900]{};
    std::memset(buf, 'c', sizeof(buf));
    const auto written = conn_.write(buf, 500);
    // First fails, since Min(d,u) is 500 and this < send.mss
    // Second doesn't fail, because data_n <= usable_wnd
    // Third fails, because min(d,u) (300) < 1/2 * 300 (150)
    const auto send_size = 500 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);

    auto ack = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN + 1,
            .ackn  = conn_.get_send_iss() + 500, // size of packet we sent
            .ack   = true,
            .window = 100
    });
    const auto ack_data = ack.serialize();
    const netparser::TcpHeaderView ack_view{ack_data};
    conn_.on_packet(ack_view, {});

    const auto sent = conn_.write(buf, 200);
    const auto send_size2 = 200 + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE;
    // First fails, since Min(d,u) is 100 and this < send.mss
    // Second fails, because data_n > usable_wnd
    // Third fails, because min(d,u) (100) < 1/2 * 500 (250)

    // Make sure write isnt even called, since timer is supposed to start
    EXPECT_CALL(mock_io_, write(_, _)).Times(0);
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}