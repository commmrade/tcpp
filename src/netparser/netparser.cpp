#include <print>
#include "netparser.hpp"
#include <arpa/inet.h>
//
// Created by klewy on 3/6/26.
//
namespace netparser {

IpHeaderView::IpHeaderView(const std::span<const std::byte> bytes)
    : bytes_(bytes)
{
    if (bytes.size() < IPV4H_MIN_SIZE) { throw std::logic_error{ "Array must be 20 bytes> for IP header" }; }
}

[[nodiscard]] std::uint8_t IpHeaderView::version() const
{
    return std::to_integer<std::uint8_t>(bytes_[IPV4H_VER_OFFSET] >> 4);
}

[[nodiscard]] std::uint8_t IpHeaderView::ihl() const
{
    return std::to_integer<std::uint8_t>(bytes_[IPV4H_IHL_OFFSET]) & 0x0F;// NOLINT
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
    return (std::to_integer<std::uint8_t>(flags) & 0b01000000) >> 6;// NOLINT
}

bool IpHeaderView::more_fragments() const
{
    const std::byte flags = bytes_[IPV4H_FLAGS_OFFSET];
    return (std::to_integer<std::uint8_t>(flags) & 0b00100000) >> 5;// NOLINT
}

std::uint16_t IpHeaderView::frag_offset() const
{
    std::uint16_t frag_off{};
    std::memcpy(&frag_off, bytes_.data() + IPV4H_FRAG_OFFSET, sizeof(frag_off));
    frag_off = ntohs(frag_off);
    frag_off = frag_off & 0x1FFFU;// NOLINT
    return frag_off;
}

std::uint8_t IpHeaderView::ttl() const
{
    const auto time_to_live = std::to_integer<std::uint8_t>(bytes_[IPV4H_TTL_OFFSET]);
    return time_to_live;
}

std::uint16_t IpHeaderView::checksum() const
{
    std::uint16_t sum{};
    std::memcpy(&sum, bytes_.data() + IPV4H_HDR_CHECKSUM_OFFSET, sizeof(sum));
    return ntohs(sum);
}

[[nodiscard]] std::uint8_t IpHeaderView::protocol() const
{
    return std::to_integer<std::uint8_t>(bytes_[IPV4H_PROTO_OFFSET]);
}

[[nodiscard]] std::uint32_t IpHeaderView::source_addr() const
{
    std::uint32_t addr{};
    std::memcpy(&addr, bytes_.data() + IPV4H_SRC_ADDR_OFFSET, sizeof(addr));
    return addr;
}

[[nodiscard]] std::uint32_t IpHeaderView::dest_addr() const
{
    std::uint32_t addr{};
    std::memcpy(&addr, bytes_.data() + IPV4H_DST_ADDR_OFFSET, sizeof(addr));
    return addr;
}

std::span<const std::byte> IpHeaderView::data() const { return bytes_; }

/// Owned IP Header
IpHeader::IpHeader(const IpHeaderView &iph)
{
    const auto bytes = iph.data();
    std::memcpy(&hdr_, bytes.data(), bytes.size());
}

std::uint8_t IpHeader::version() const { return hdr_.version; }

void IpHeader::version(const std::uint8_t ver) { hdr_.version = ver; }

void IpHeader::ihl(const std::uint8_t ihl) { hdr_.ihl = ihl; }

void IpHeader::type_of_service(const std::uint8_t tos) { hdr_.tos = tos; }

void IpHeader::total_len(const std::uint16_t len) { hdr_.tot_len = htons(len); }

void IpHeader::id(const std::uint16_t ident) { hdr_.id = htons(ident); }

void IpHeader::dont_fragment(bool val)
{
    constexpr std::uint16_t DF_BIT = (1U << 14U);
    std::uint16_t frag_off = ntohs(hdr_.frag_off);
    if (val) {
        frag_off |= DF_BIT;
    } else {
        frag_off &= ~DF_BIT;// NOLINT
    }
    hdr_.frag_off = htons(frag_off); // NOLINT
}

void IpHeader::more_fragments(bool val)
{
    constexpr std::uint16_t MF_BIT = (1U << 13U);
    std::uint16_t frag_off = ntohs(hdr_.frag_off);
    if (val) {
        frag_off |= MF_BIT;
    } else {
        frag_off &= ~MF_BIT;// NOLINT
    }
    hdr_.frag_off = htons(frag_off); // NOLINT
}

void IpHeader::frag_offset(const std::uint16_t frag_off)
{
    std::uint16_t off = ntohs(hdr_.frag_off);
    off = (off & 0xE000U) | (frag_off & 0x1FFFU); // NOLINT
    hdr_.frag_off = htons(off);
}

void IpHeader::ttl(const std::uint8_t val) { hdr_.ttl = val; }

void IpHeader::checksum(const std::uint16_t cksum) { hdr_.check = htons(cksum); }

void IpHeader::protocol(const std::uint8_t proto) { hdr_.protocol = proto; }

void IpHeader::source_addr(const std::uint32_t addr) { hdr_.saddr = addr; }

void IpHeader::dest_addr(const std::uint32_t addr) { hdr_.daddr = addr; }

std::vector<std::byte> IpHeader::serialize() const
{
    std::vector<std::byte> data;
    data.resize(sizeof(hdr_));
    std::memcpy(data.data(), &hdr_, sizeof(hdr_));
    return data;
}

std::uint8_t IpHeader::ihl() const { return hdr_.ihl; }

std::uint8_t IpHeader::type_of_service() const { return hdr_.tos; }

std::uint16_t IpHeader::total_len() const { return ntohs(hdr_.tot_len); }

std::uint16_t IpHeader::id() const { return ntohs(hdr_.id); }

bool IpHeader::dont_fragment() const
{
    const bool frag = ntohs(hdr_.frag_off) & (1U << 14U);// NOLINT
    return static_cast<bool>(frag);
}

bool IpHeader::more_fragments() const
{
    const bool frag = ntohs(hdr_.frag_off) & (1U << 13U);// NOLINT
    return static_cast<bool>(frag);
}

std::uint16_t IpHeader::frag_offset() const
{
    const std::uint16_t frag_off = htons(hdr_.frag_off) & 0x1FFFU;
    return frag_off;
}

std::uint8_t IpHeader::ttl() const { return hdr_.ttl; }

std::uint16_t IpHeader::checksum() const { return ntohs(hdr_.check); }

std::uint8_t IpHeader::protocol() const { return hdr_.protocol; }

std::uint32_t IpHeader::source_addr() const { return hdr_.saddr; }

std::uint32_t IpHeader::dest_addr() const { return hdr_.daddr; }
}// namespace netparser