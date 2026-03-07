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

class tun
{
private:
    int tun_fd{};
    std::string dev_name_;

public:
    explicit tun(std::string_view dev_name)
        : dev_name_(dev_name)
    {
        tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) { throw std::runtime_error("Could not open /dev/net/tun"); }

        ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        if (!dev_name.empty()) { strcpy(ifr.ifr_name, dev_name.data()); }

        if (const int r = ioctl(tun_fd, TUNSETIFF, static_cast<void *>(&ifr)); r < 0) {
            throw std::runtime_error(std::format("Could not setup TUN interface: {}", std::strerror(errno)));
        }
    }

    int raw_fd() const { return tun_fd; }

    void set_addr(const std::string_view addr)
    {
        int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

        struct ifreq ifr{};
        strncpy(ifr.ifr_name, dev_name_.data(), dev_name_.size());

        auto *sock_addr = reinterpret_cast<sockaddr_in *>(&ifr.ifr_addr);
        sock_addr->sin_family = AF_INET;
        int ret = inet_pton(AF_INET, addr.data(), &sock_addr->sin_addr);
        if (ret <= 0) {
            throw std::runtime_error(std::format("Failed to convert addr: {}", std::strerror(errno)));// NOLINT
        }
        ret = ioctl(sock_fd, SIOCSIFADDR, &ifr);// NOLINT
        if (ret < 0) {
            throw std::runtime_error(std::format("Failed to set addr: {}", std::strerror(errno)));// NOLINT
        }
    }

    void set_mask(const std::string_view mask)
    {
        int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

        struct ifreq ifr{};
        strncpy(ifr.ifr_name, dev_name_.data(), dev_name_.size());

        auto *sock_addr = reinterpret_cast<sockaddr_in *>(&ifr.ifr_addr);
        sock_addr->sin_family = AF_INET;
        int ret = inet_pton(AF_INET, mask.data(), &sock_addr->sin_addr);
        if (ret <= 0) {
            throw std::runtime_error(std::format("Failed to convert mask: {}", std::strerror(errno)));// NOLINT
        }
        ret = ioctl(sock_fd,SIOCSIFNETMASK, &ifr);// NOLINT
        if (ret < 0) {
            throw std::runtime_error(std::format("Failed to set mask: {}", std::strerror(errno)));// NOLINT
        }
    }

    void set_flags(short int flags)
    {
        int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

        struct ifreq ifr{};
        strncpy(ifr.ifr_name, dev_name_.data(), dev_name_.size());

        int ret = ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
        if (ret < 0) {
            throw std::runtime_error(std::format("Failed to get flags: {}", std::strerror(errno))); // NOLINT
        }

        ifr.ifr_flags |= flags;
        ret = ioctl(sock_fd, SIOCSIFFLAGS, &ifr);// NOLINT
        if (ret < 0) {
            throw std::runtime_error(std::format("Failed to set flags: {}", std::strerror(errno)));// NOLINT
        }
    }

    ~tun() { close(); }

    void close() { ::close(tun_fd); }

    void write(const void *buf, const std::size_t buf_len)// NOLINT
    {
        ::write(tun_fd, buf, buf_len);
    }

    [[nodiscard]] ssize_t read(void *buf, const std::size_t buf_len) const { return ::read(tun_fd, buf, buf_len); }

    template<typename T, std::size_t N> [[nodiscard]] ssize_t read(std::array<T, N> &buf) const
    {
        return read(buf.data(), N);
    }
};


#endif //TCPP_TUN_HPP