

#include "../../../src/tcpp/clock.hpp"
#include "../../../src/tcpp/tun.hpp"
#include "../../../src/tcpp/net/conn.hpp"
#include <gmock/gmock.h>

using namespace testing;

class MockTun : public IOInterface
{
public:
    MOCK_METHOD(ssize_t, write, (std::span<const std::byte> payload), (override));
};

class MockOutput : public OutputInterface
{
public:
    MOCK_METHOD(ssize_t, send, (const TcpSegment& seg, const std::size_t max_size_pl, const std::uint32_t rwnd), (override));
    void init([[maybe_unused]] const std::uint32_t src_addr, [[maybe_unused]] const std::uint32_t dst_addr, [[maybe_unused]] const std::uint16_t src_port, [[maybe_unused]] const std::uint16_t dst_port) override
    {}
};

class FakeClock : public ClockInterface
{
public:
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
        std::uint32_t tsval   = 0;
        std::uint32_t tsecr   = 0;
        bool          has_ts  = false;  // explicit flag; needed when tsval==0 is intentional (e.g. SYN)
    };

    inline netparser::IpHeader make_ip(const IpArgs& a) {
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

    inline netparser::TcpHeader make_tcp(const TcpArgs& a) {
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
        if (a.has_ts) {
            tcph.options().timestamp(a.tsval, a.tsecr);
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
    TcpConnection conn_{std::make_unique<MockOutput>(), std::make_unique<FakeClock>()};

    MockOutput& output()
    {
        return static_cast<MockOutput&>(*conn_.output_);
    }

    void do_handshake(const std::uint16_t send_wnd_size = std::numeric_limits<std::uint16_t>::max())
    {
        EXPECT_CALL(output(), send).WillOnce(Return(44));

        auto iph = helpers::make_ip({.src = PEER_IP, .dst = LOCAL_IP});
        auto syn  = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN,
            .window = send_wnd_size,
            .syn   = true,
        });

        auto iph_data = iph.serialize();
        auto tcph_data = syn.serialize();

        netparser::IpHeaderView iph_view{iph_data};
        netparser::TcpHeaderView tcph_view{tcph_data};
        conn_.open_passive(iph_view, tcph_view);
        Mock::VerifyAndClearExpectations(&output());

        EXPECT_CALL(output(), send).Times(0);
        auto ack = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN + 1,
            .ackn  = conn_.send_.iss() + 1,
            .window = send_wnd_size,
            .ack   = true
        });
        auto ack_data = ack.serialize();
        netparser::TcpHeaderView ack_view{ack_data};
        conn_.on_packet(ack_view, {});
        Mock::VerifyAndClearExpectations(&output());

        ASSERT_EQ(conn_.send_.wnd(), send_wnd_size);
        ASSERT_EQ(conn_.get_state(), TcpState::ESTAB);
    }

    void passive_open(const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
    {
        conn_.open_passive(iph, tcph);
    }

    void active_open(const std::uint32_t saddr,
    const std::uint16_t sport,
    const std::uint32_t daddr,
    const std::uint16_t dport)
    {
        conn_.open_active(saddr, sport, daddr, dport);
    }

    void send_data_to_conn(const std::size_t size)
    {
        std::vector<std::byte> payload(size);

        auto seg = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN + 1,
            .ackn  = get_send_iss() + 1,
            .window = 65535,
            .ack   = true,
            .mss   = 0,
        });
        const auto seg_d = seg.serialize();
        const netparser::TcpHeaderView seg_view{ seg_d };

        EXPECT_CALL(output(), send).WillOnce(Return(netparser::TCPH_MIN_SIZE + netparser::IPV4H_MIN_SIZE));
        conn_.on_packet(seg_view, payload);
        Mock::VerifyAndClearExpectations(&output());
    }

    void send_data_to_conn_noack(const std::size_t size)
    {
        std::vector<std::byte> payload(size);
        auto seg = helpers::make_tcp({
            .sport = PEER_PORT, .dport = LOCAL_PORT,
            .seqn  = PEER_ISN + 1,
            .ackn  = get_send_iss() + 1,
            .window = 65535,
            .ack   = true,
        });
        const auto seg_d = seg.serialize();
        const netparser::TcpHeaderView seg_view{seg_d};
        EXPECT_CALL(output(), send).Times(AnyNumber());
        conn_.on_packet(seg_view, payload);
        Mock::VerifyAndClearExpectations(&output());
    }

    std::uint16_t send_mss() const
    {
        return conn_.send_mss_;
    }

    std::uint32_t send_una() const
    {
        return conn_.send_.una();
    }

    std::uint32_t get_send_nxt() const
    {
        return conn_.send_.nxt();
    }

    ssize_t write(std::span<const std::byte> payload)
    {
        return conn_.write(payload);
    }

    std::size_t send_buf_size_segs() const
    {
        return conn_.send_buf_.size_segs();
    }
    std::size_t send_buf_pl_size() const
    {
        return conn_.send_buf_.size_payload_bytes();
    }

    std::uint32_t get_send_iss() const
    {
        return conn_.send_.iss();
    }
    ClockInterface& get_clock()
    {
        return *conn_.clock_.get();
    }
    std::uint32_t recv_nxt() const
    {
        return conn_.recv_.nxt();
    }
    std::uint32_t right_edge() const {
        return conn_.right_wnd_edge_;
    }
    void upd_recv_win() {
        conn_.update_recv_window();
    }
    std::uint32_t get_recv_win() const {
        return conn_.recv_.wnd();
    }
    void set_recv_wnd(const std::uint16_t wnd) {
        conn_.recv_.set_wnd(wnd);
    }

    std::uint16_t recv_mss() const
    {
        return conn_.recv_mss_;
    }

    auto& rtt()
    {
        return conn_.rtt_measurement_;
    }

    bool is_tsopt() const
    {
        return conn_.is_tsopt;
    }

    std::uint32_t ts_recent() const
    {
        return conn_.recv_.ts_recent();
    }
};
