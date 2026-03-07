//
// Created by klewy on 3/6/26.
//

#ifndef TCPP_TUN_HPP
#define TCPP_TUN_HPP
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <stdexcept>
#include <string_view>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <unistd.h>

class tun
{
private:
    int tun_fd{};
public:
    explicit tun(std::string_view dev_name)
    {
        tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            throw std::runtime_error("Could not open /dev/net/tun");
        }

        ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        if (!dev_name.empty()) {
            strcpy(ifr.ifr_name, dev_name.data());
        }

        if (const int r = ioctl(tun_fd, TUNSETIFF, static_cast<void*>(&ifr)); r < 0) {
            throw std::runtime_error(std::format("Could not setup TUN interface: {}", std::strerror(errno)));
        }
    }

    void add_addr()
    {

    }

    void add_route()
    {

    }

    ~tun()
    {
        close();
    }

    void close()
    {
        ::close(tun_fd);
    }

    void write(const void* buf, const std::size_t buf_len) // NOLINT
    {
        ::write(tun_fd, buf, buf_len);
    }
    [[nodiscard]] ssize_t read(void* buf, const std::size_t buf_len) const
    {
        return ::read(tun_fd, buf, buf_len);
    }

    template<typename T, std::size_t N>
    [[nodiscard]] ssize_t read(std::array<T, N>& buf) const
    {
        return read(buf.data(), N);
    }
};


#endif //TCPP_TUN_HPP