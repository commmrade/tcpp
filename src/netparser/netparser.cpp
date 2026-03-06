#include <print>
#include "netparser.hpp"
#include <arpa/inet.h>
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

[[nodiscard]] std::uint8_t IpHeaderView::version() const
{
    return std::to_integer<std::uint8_t>(bytes_[IPV4H_VER_OFFSET] >> 4);
}

[[nodiscard]] std::uint8_t IpHeaderView::ihl() const
{
    return std::to_integer<std::uint8_t>(bytes_[IPV4H_IHL_OFFSET]) & 0x0F;
}

// TODO: Make it work propely
std::uint8_t IpHeaderView::type_of_service() const
{
    return std::to_integer<std::uint8_t>(bytes_[IPV4H_TYPE_OF_SERVICE_OFFSET]);
}

std::uint16_t IpHeaderView::total_len() const
{
    std::uint16_t tot_len{};
    std::memcpy(&tot_len, bytes_.data() + IPV4H_TOT_LEN_OFFSET, sizeof(tot_len));
    return ntohs(tot_len);
}

std::uint16_t IpHeaderView::id() const
{
    std::uint16_t ident{};
    std::memcpy(&ident, bytes_.data() + IPV4H_ID_OFFSET, sizeof(ident));
    return ntohs(ident);
}

bool IpHeaderView::dont_fragment() const
{
    const std::byte flags = bytes_[IPV4H_FLAGS_OFFSET];
    return (std::to_integer<std::uint8_t>(flags) & 0b01000000) >> 6; // NOLINT
}

bool IpHeaderView::more_fragments() const
{
    const std::byte flags = bytes_[IPV4H_FLAGS_OFFSET];
    return (std::to_integer<std::uint8_t>(flags) & 0b00100000) >> 5; // NOLINT
}

[[nodiscard]] std::uint8_t IpHeaderView::protocol() const
{
    return std::to_integer<std::uint8_t>(bytes_[IPV4H_PROTO_OFFSET]);
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