//
// Created by klewy on 4/13/26.
//

// #include "../src/tcpp/clock.hpp"
#include "../src/tcpp/clock.hpp"
#include "../src/tcpp/tun.hpp"
#include "../src/tcpp/net/conn.hpp"
#include <gmock/gmock.h>

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
    // TODO: Helpers to build TCP/IP headers
} // namespace helpers

class TcpConnectionTest : public testing::Test
{
protected:
    MockTun mock_io_;
    TcpConnection conn_{mock_io_, std::make_unique<FakeClock>()};
    void f()
    {
    }
};

TEST_F(TcpConnectionTest, HandshakeMock)
{
    // TODO: cant access private why?
}