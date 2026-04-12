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

class TunInterface
{
public:
    virtual ~TunInterface() = default;
    virtual ssize_t write(const void* buf, const std::size_t buf_len) = 0;
};

class Tun final : public TunInterface
{
private:
    int tun_fd{};
    std::string dev_name_;
public:
    explicit Tun(std::string_view dev_name);

    ~Tun() override { close(); }

    Tun(const Tun&) = delete;

    Tun& operator=(const Tun&) = delete;

    Tun(Tun&& rhs) noexcept
    {
        std::swap(tun_fd, rhs.tun_fd);
        std::swap(dev_name_, rhs.dev_name_);
    }

    Tun& operator=(Tun&& rhs) noexcept
    {
        std::swap(tun_fd, rhs.tun_fd);
        std::swap(dev_name_, rhs.dev_name_);
        return *this;
    }

    int raw_fd() const { return tun_fd; }

    void set_addr(const std::string_view addr);

    void set_mask(const std::string_view mask);

    void set_flags(short int flags);

    void open(std::string_view dev_name);

    void close() { ::close(tun_fd); }

    ssize_t write(const void *buf, const std::size_t buf_len) override // NOLINT
    {
        return ::write(tun_fd, buf, buf_len);
    }

    [[nodiscard]] ssize_t read(void *buf, const std::size_t buf_len) const { return ::read(tun_fd, buf, buf_len); }

    template<typename T, std::size_t N> [[nodiscard]] ssize_t read(std::array<T, N> &buf) const
    {
        return read(buf.data(), N);
    }
};


#endif //TCPP_TUN_HPP