//
// Created by klewy on 4/28/26.
//
#include "tcp_conn_test.hpp"
#include <gmock/gmock.h>

class TcpConnectionSendBufTest : public TcpConnectionTest
{

};

TEST_F(TcpConnectionSendBufTest, InsertSeveralUnderMss)
{
    do_handshake();

    std::array<std::byte, 4> buf{};
    std::memset(buf.data(), 'c', buf.size());

    write(buf);
    write(buf);
    write(buf);
    ASSERT_EQ(send_buf_size_segs(), 1);
    ASSERT_EQ(send_buf_pl_size(), 4 * 3);
}

TEST_F(TcpConnectionSendBufTest, InsertSeveralOverMss)
{
    do_handshake();

    const auto send_mss_ = send_mss();
    std::vector<std::byte> buf;
    buf.resize(send_mss_);
    std::memset(buf.data(), 'c', buf.size());

    write(std::span<const std::byte>{buf.data(), static_cast<std::size_t>(send_mss_ - 10)});
    write(buf);
    ASSERT_EQ(send_buf_size_segs(), 2);
    ASSERT_EQ(send_buf_pl_size(), send_mss_ - 10 + buf.size());
}

TEST_F(TcpConnectionSendBufTest, InsertSeveralMss)
{
    do_handshake();

    const auto send_mss_ = send_mss();
    std::vector<std::byte> buf;
    buf.resize(send_mss_ * 3);
    std::memset(buf.data(), 'c', buf.size());

    write(buf);
    ASSERT_EQ(send_buf_size_segs(), 3);
    ASSERT_EQ(send_buf_pl_size(), buf.size());
}