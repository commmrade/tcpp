//
// Created by klewy on 3/6/26.
//

#ifndef TCPP_TUN_HPP
#define TCPP_TUN_HPP
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <print>
#include <stdexcept>
#include <string_view>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

class IOInterface
{
public:
    virtual ~IOInterface() = default;
    virtual ssize_t write(std::span<const std::byte> payload) = 0;
};

class Tun final : public IOInterface
{
private:
    int tun_fd_{};
    int tun_sock_fd_{};
    std::string dev_name_;
public:
    explicit Tun(std::string_view dev_name);

    ~Tun() override { close(); }

    Tun(const Tun&) = delete;

    Tun& operator=(const Tun&) = delete;

    Tun(Tun&& rhs) noexcept
    {
        std::swap(tun_fd_, rhs.tun_fd_);
        std::swap(dev_name_, rhs.dev_name_);
    }

    Tun& operator=(Tun&& rhs) noexcept
    {
        std::swap(tun_fd_, rhs.tun_fd_);
        std::swap(dev_name_, rhs.dev_name_);
        return *this;
    }

    int raw_fd() const { return tun_fd_; }

    void set_addr(const std::string_view addr);

    void set_mask(const std::string_view mask);

    void set_flags(short int flags);

    void open(std::string_view dev_name);

    void close();

    ssize_t write(std::span<const std::byte> payload) override // NOLINT
    {
        return ::write(tun_fd_, static_cast<const void*>(payload.data()), payload.size());
    }

    [[nodiscard]] ssize_t read(void *buf, const std::size_t buf_len) const { return ::read(tun_fd_, buf, buf_len); }

    template<typename T, std::size_t N> [[nodiscard]] ssize_t read(std::array<T, N> &buf) const
    {
        return read(buf.data(), N);
    }
};


#endif //TCPP_TUN_HPP
