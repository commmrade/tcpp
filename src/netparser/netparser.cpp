#include <print>
#include "netparser.hpp"

#include <assert.h>
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

TcpHeaderView::TcpHeaderView(const std::span<const std::byte> bytes) : bytes_(bytes)
{
    if (bytes_.size() < TCPH_MIN_SIZE) {
        throw std::runtime_error("Bytes is too small for a tcp header");
    }
}

std::uint16_t TcpHeaderView::src_port() const
{
    std::uint16_t port{};
    std::memcpy(&port, bytes_.data() + TCPH_SRC_PORT_OFFSET, sizeof(port));
    return ntohs(port);
}

std::uint16_t TcpHeaderView::dest_port() const
{
    std::uint16_t port{};
    std::memcpy(&port, bytes_.data() + TCPH_DEST_PORT_OFFSET, sizeof(port));
    return ntohs(port);
}

std::uint32_t TcpHeaderView::seqn() const
{
    std::uint32_t seq{};
    std::memcpy(&seq, bytes_.data() + TCPH_SEQN_OFFSET, sizeof(seq));
    return ntohl(seq);
}

std::uint32_t TcpHeaderView::ackn() const
{
    std::uint32_t ackn{};
    std::memcpy(&ackn, bytes_.data() + TCPH_ACKN_OFFSET, sizeof(ackn));
    return ntohl(ackn);
}

std::uint8_t TcpHeaderView::data_off() const
{
    const std::uint8_t byte = std::to_integer<std::uint8_t>(bytes_[TCPH_DOFF_OFFSET]) >> 4U;
    return byte;
}

bool TcpHeaderView::cwr() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool cwr = flags & (1U << 7U); // NOLINT
    return cwr;
}

bool TcpHeaderView::ece() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool ece = flags & (1U << 6U); // NOLINT
    return ece;
}

bool TcpHeaderView::urg() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool urg = flags & (1U << 5U); // NOLINT
    return urg;
}

bool TcpHeaderView::ack() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool ack = flags & (1U << 4U); // NOLINT
    return ack;
}

bool TcpHeaderView::psh() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool psh = flags & (1U << 3U); // NOLINT
    return psh;
}

bool TcpHeaderView::rst() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool rst = flags & (1U << 2U); // NOLINT
    return rst;
}

bool TcpHeaderView::syn() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool syn = flags & (1U << 1U); // NOLINT
    return syn;
}

bool TcpHeaderView::fin() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool fin = flags & 1U; // NOLINT
    return fin;
}

std::uint16_t TcpHeaderView::window() const
{
    std::uint16_t wnd{};
    std::memcpy(&wnd, bytes_.data() + TCPH_WIN_OFFSET, sizeof(wnd));
    return ntohs(wnd);
}

std::uint16_t TcpHeaderView::checksum() const
{
    std::uint16_t cksum{};
    std::memcpy(&cksum, bytes_.data() + TCPH_CKSUM_OFFSET, sizeof(cksum));
    return ntohs(cksum);
}

std::uint16_t TcpHeaderView::urg_ptr() const
{
    std::uint16_t urgptr{};
    std::memcpy(&urgptr, bytes_.data() + TCPH_URGPTR_OFFSET, sizeof(urgptr));
    return ntohs(urgptr);
}

TcpHeader::TcpHeader(const TcpHeaderView &tcph)
{
    const auto data = tcph.data();
    assert(sizeof(hdr_) >= data.size());
    std::memcpy(&hdr_, data.data(), sizeof(hdr_));
}

std::uint16_t TcpHeader::src_port() const
{
    return ntohs(hdr_.source);
}

void TcpHeader::src_port(const std::uint16_t port)
{
    hdr_.source = htons(port);
}

std::uint16_t TcpHeader::dest_port() const
{
    return ntohs(hdr_.dest);
}

void TcpHeader::dest_port(const std::uint16_t port)
{
    hdr_.dest = htons(port);
}

std::uint32_t TcpHeader::seqn() const
{
    return ntohl(hdr_.seq);
}

void TcpHeader::seqn(const std::uint32_t num)
{
    hdr_.seq = htonl(num);
}

std::uint32_t TcpHeader::ackn() const
{
    return ntohl(hdr_.ack_seq);
}

void TcpHeader::ackn(const std::uint32_t num)
{
    hdr_.ack_seq = htonl(num);
}

std::uint8_t TcpHeader::data_off() const
{
    return hdr_.doff;
}

void TcpHeader::data_off(const std::uint8_t val)
{
    hdr_.doff = val;
}

bool TcpHeader::cwr() const
{
    return hdr_.cwr;
}

void TcpHeader::cwr(const bool val)
{
    hdr_.cwr = val;
}

bool TcpHeader::ece() const
{
    return hdr_.ece;
}

void TcpHeader::ece(const bool val)
{
    hdr_.ece = val;
}

bool TcpHeader::urg() const
{
    return hdr_.urg;
}

void TcpHeader::urg(const bool val)
{
    hdr_.urg = val;
}

bool TcpHeader::ack() const
{
    return hdr_.ack;
}

void TcpHeader::ack(const bool val)
{
    hdr_.ack = val;
}

bool TcpHeader::psh() const
{
    return hdr_.psh;
}

void TcpHeader::psh(const bool val)
{
    hdr_.psh = val;
}

bool TcpHeader::rst() const
{
    return hdr_.rst;
}

void TcpHeader::rst(const bool val)
{
    hdr_.rst = val;
}

bool TcpHeader::syn() const
{
    return hdr_.syn;
}

void TcpHeader::syn(const bool val)
{
    hdr_.syn = val;
}

bool TcpHeader::fin() const
{
    return hdr_.fin;
}

void TcpHeader::fin(const bool val)
{
    hdr_.fin = val;
}

std::uint16_t TcpHeader::window() const
{
    return ntohs(hdr_.window);
}

void TcpHeader::window(const std::uint16_t wnd_size)
{
    hdr_.window = htons(wnd_size);
}

std::uint16_t TcpHeader::checksum() const
{
    return ntohs(hdr_.check);
}

void TcpHeader::checksum(const std::uint16_t cksum)
{
    hdr_.check = htons(cksum);
}

std::uint16_t TcpHeader::urg_ptr() const
{
    return ntohs(hdr_.urg_ptr);
}

void TcpHeader::urg_ptr(const std::uint16_t ptr)
{
    hdr_.urg_ptr = htons(ptr);
}

std::vector<std::byte> TcpHeader::serialize() const
{
    std::vector<std::byte> res{};
    res.resize(sizeof(hdr_)); // TODO: MAKE IT INCLUDE OPTIONS
    std::memcpy(res.data(), &hdr_, sizeof(hdr_));
    return res;
}

}// namespace netparser