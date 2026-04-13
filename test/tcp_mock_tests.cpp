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

class TcpConnectionSenderSwsTest : public testing::Test
{
protected:
    static constexpr std::uint32_t PEER_IP  = 0x0A000001; // 10.0.0.1
    static constexpr std::uint32_t LOCAL_IP = 0x0A000002; // 10.0.0.2
    static constexpr std::uint16_t PEER_PORT  = 12345;
    static constexpr std::uint16_t LOCAL_PORT = 8090;
    static constexpr std::uint32_t PEER_ISN  = 1000;
    MockTun mock_io_;
    TcpConnection conn_{mock_io_, std::make_unique<FakeClock>()};

    void do_handshake(const std::uint16_t send_wnd_size = std::numeric_limits<std::uint16_t>::max())
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
        ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);
    }

    std::uint32_t get_send_iss() const
    {
        return conn_.send_.iss;
    }
    ClockInterface& get_clock()
    {
        return *conn_.clock_.get();
    }
};

TEST_F(TcpConnectionSenderSwsTest, Cond1)
{
    do_handshake();
    char buf[536]{};
    const auto written = conn_.write(buf, sizeof(buf));
    const auto send_size = sizeof(buf) + netparser::IPV4H_MIN_SIZE + netparser::TCPH_MIN_SIZE; // So payload + iph + tcph is sent and returned
    // 1. MIN(D,U) => (536 >= Send MSS) => true
    EXPECT_CALL(mock_io_, write(_, _)).WillOnce(Return(send_size));
    conn_.on_tick();
    Mock::VerifyAndClearExpectations(&mock_io_);
}

TEST_F(TcpConnectionSenderSwsTest, Cond2)
{
    do_handshake(400);
    char buf[200]{};
    const auto written = conn_.write(buf, sizeof(buf));
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
    char buf[600]{};
    const auto sent = conn_.write(buf, sizeof(buf));
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
    char buf[900]{};
    const auto written = conn_.write(buf, 500);
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
            .ack   = true,
            .window = 100
    });
    const auto ack_data = ack.serialize();
    const netparser::TcpHeaderView ack_view{ack_data};
    conn_.on_packet(ack_view, {});
    const auto sent = conn_.write(buf, 200);
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
    // FIXME: I MAY NEED TO IMPL. TIMERS OTEHR WAY, SINCE SWS AND RETRANS SHOULD NOT BE SHARED
    // static_cast<FakeClock&>(get_clock()).advance(RttMeasurement::SWS_OVERRIDE_MS);
    // EXPECT_CALL(mock_io_, write(_, _)).Times(1);
    // conn_.on_tick();
    // Mock::VerifyAndClearExpectations(&mock_io_);
}