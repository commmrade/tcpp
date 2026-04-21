//
// Created by klewy on 3/6/26.
//

#include "tun.hpp"

Tun::Tun(std::string_view dev_name)
    : dev_name_(dev_name)
{
    open(dev_name);
}

void Tun::set_addr(const std::string_view addr)
{
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev_name_.data(), dev_name_.size());

    auto *sock_addr = reinterpret_cast<sockaddr_in *>(&ifr.ifr_addr);
    sock_addr->sin_family = AF_INET;
    int ret = inet_pton(AF_INET, addr.data(), &sock_addr->sin_addr);
    if (ret <= 0) {
        throw std::runtime_error(std::format("Failed to convert addr: {}", std::strerror(errno)));// NOLINT
    }
    ret = ioctl(tun_sock_fd_, SIOCSIFADDR, &ifr);// NOLINT
    if (ret < 0) {
        throw std::runtime_error(std::format("Failed to set addr: {}", std::strerror(errno)));// NOLINT
    }
}

void Tun::set_mask(const std::string_view mask)
{
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev_name_.data(), dev_name_.size());

    auto *sock_addr = reinterpret_cast<sockaddr_in *>(&ifr.ifr_addr);
    sock_addr->sin_family = AF_INET;
    int ret = inet_pton(AF_INET, mask.data(), &sock_addr->sin_addr);
    if (ret <= 0) {
        throw std::runtime_error(std::format("Failed to convert mask: {}", std::strerror(errno)));// NOLINT
    }
    ret = ioctl(tun_sock_fd_,SIOCSIFNETMASK, &ifr);// NOLINT
    if (ret < 0) {
        throw std::runtime_error(std::format("Failed to set mask: {}", std::strerror(errno)));// NOLINT
    }
}

void Tun::set_flags(short int flags)
{
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev_name_.data(), dev_name_.size());

    int ret = ioctl(tun_sock_fd_, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        throw std::runtime_error(std::format("Failed to get flags: {}", std::strerror(errno)));// NOLINT
    }

    ifr.ifr_flags |= flags;
    ret = ioctl(tun_sock_fd_, SIOCSIFFLAGS, &ifr);// NOLINT
    if (ret < 0) {
        throw std::runtime_error(std::format("Failed to set flags: {}", std::strerror(errno)));// NOLINT
    }
}

void Tun::open(std::string_view dev_name)
{
    tun_fd_ = ::open("/dev/net/tun", O_RDWR);
    if (tun_fd_ < 0) { throw std::runtime_error("Could not open /dev/net/tun"); }

    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (!dev_name.empty()) { strcpy(ifr.ifr_name, dev_name.data()); }

    if (const int r = ioctl(tun_fd_, TUNSETIFF, static_cast<void *>(&ifr)); r < 0) {
        throw std::runtime_error(std::format("Could not setup TUN interface: {}", std::strerror(errno)));
    }

    // Need to create a socket to dispatch ioctl properly, since TUN is just a char. device.
    // SOCK_DGRAM is cheapest to create
    tun_sock_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (tun_sock_fd_ < 0) {
        close();
        throw std::runtime_error(std::format("Could not create a TUN socket: {}", std::strerror(errno)));
    }
}

void Tun::close()
{
    ::close(tun_fd_);
    ::close(tun_sock_fd_);
}
