#include <print>
#include "netparser.hpp"
//
// Created by klewy on 3/6/26.
//
namespace netparser {

IpHeaderView::IpHeaderView(const std::span<const std::byte> bytes) : bytes_(bytes)
{
    if (bytes.size() < IPV4H_MIN_SIZE) {
        throw std::logic_error{"Array must be 20 bytes> for IP header"};
    }
}

[[nodiscard]] unsigned char IpHeaderView::protocol() const
{
    return std::to_integer<unsigned char>(bytes_[IPV4H_PROTO_OFFSET]);
}

[[nodiscard]] std::array<std::byte, 4> IpHeaderView::source_addr() const
{
    std::array<std::byte, 4> ret{};
    std::memcpy(ret.data(), &bytes_[IPV4H_SRC_ADDR_OFFSET], ret.size());
    return ret;
}
[[nodiscard]] std::array<std::byte, 4> IpHeaderView::dest_addr() const
{
    std::array<std::byte, 4> ret{};
    std::memcpy(ret.data(), &bytes_[IPV4H_DST_ADDR_OFFSET], ret.size());
    return ret;
}

} // namespace netparser