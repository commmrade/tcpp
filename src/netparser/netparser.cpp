#include "netparser.hpp"
#include <print>
#include <iterator>
#include <arpa/inet.h>
#include <cassert>
#include <stdexcept>
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
    if (val) { frag_off |= DF_BIT; } else {
        frag_off &= ~DF_BIT;// NOLINT
    }
    hdr_.frag_off = htons(frag_off);// NOLINT
}

void IpHeader::more_fragments(bool val)
{
    constexpr std::uint16_t MF_BIT = (1U << 13U);
    std::uint16_t frag_off = ntohs(hdr_.frag_off);
    if (val) { frag_off |= MF_BIT; } else {
        frag_off &= ~MF_BIT;// NOLINT
    }
    hdr_.frag_off = htons(frag_off);// NOLINT
}

void IpHeader::frag_offset(const std::uint16_t frag_off)
{
    std::uint16_t off = ntohs(hdr_.frag_off);
    off = (off & 0xE000U) | (frag_off & 0x1FFFU);// NOLINT
    hdr_.frag_off = htons(off);
}

void IpHeader::ttl(const std::uint8_t val) { hdr_.ttl = val; }

void IpHeader::checksum(const std::uint16_t cksum) { hdr_.check = htons(cksum); }

void IpHeader::protocol(const std::uint8_t proto) { hdr_.protocol = proto; }

void IpHeader::calculate_checksum()
{
    // Zero out existing checksum before calculating
    hdr_.check = 0;

    uint32_t sum = 0;
    const uint16_t *ptr = reinterpret_cast<const uint16_t *>(&hdr_);
    int length = hdr_.ihl * 4;// IHL field is in 32-bit words

    // Sum all 16-bit words in the header
    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    // If odd byte remains, pad with zero and add
    if (length == 1) { sum += *reinterpret_cast<const uint8_t *>(ptr); }

    // Fold 32-bit sum into 16 bits by adding carry bits
    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }

    // One's complement
    hdr_.check = static_cast<uint16_t>(~sum);
}

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
    const std::uint16_t frag_off = ntohs(hdr_.frag_off) & 0x1FFFU;
    return frag_off;
}

std::uint8_t IpHeader::ttl() const { return hdr_.ttl; }

std::uint16_t IpHeader::checksum() const { return ntohs(hdr_.check); }

std::uint8_t IpHeader::protocol() const { return hdr_.protocol; }

std::uint32_t IpHeader::source_addr() const { return hdr_.saddr; }

std::uint32_t IpHeader::dest_addr() const { return hdr_.daddr; }

TcpHeaderView::TcpHeaderView(const std::span<const std::byte> bytes)
    : bytes_(bytes)
{
    if (bytes_.size() < TCPH_MIN_SIZE) { throw std::runtime_error("Bytes is too small for a tcp header"); }
}

std::uint16_t TcpHeaderView::source_port() const
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
    const bool cwr = flags & (1U << 7U);// NOLINT
    return cwr;
}

bool TcpHeaderView::ece() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool ece = flags & (1U << 6U);// NOLINT
    return ece;
}

bool TcpHeaderView::urg() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool urg = flags & (1U << 5U);// NOLINT
    return urg;
}

bool TcpHeaderView::ack() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool ack = flags & (1U << 4U);// NOLINT
    return ack;
}

bool TcpHeaderView::psh() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool psh = flags & (1U << 3U);// NOLINT
    return psh;
}

bool TcpHeaderView::rst() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool rst = flags & (1U << 2U);// NOLINT
    return rst;
}

bool TcpHeaderView::syn() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool syn = flags & (1U << 1U);// NOLINT
    return syn;
}

bool TcpHeaderView::fin() const
{
    const auto flags = std::to_integer<std::uint8_t>(bytes_[TCPH_FLAGS_OFFSET]);
    const bool fin = flags & 1U;// NOLINT
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

bool TcpHeaderView::has_option(const TcpOptionKind kind) const
{
    auto [has, _] = has_option_inner(kind);
    return has;
}

std::optional<TcpMssOption> TcpHeaderView::mss() const
{
    return option<TcpMssOption, details::TcpMssOptionInner, TcpOptionKind::MSS>();
}

std::optional<TcpSackPermOption> TcpHeaderView::sack_perm() const
{
    return option<TcpSackPermOption, details::TcpSackPermOptionInner, TcpOptionKind::SACK_PERM>();
}

std::optional<TcpTimestampOption> TcpHeaderView::timestamp() const
{
    return option<TcpTimestampOption, details::TcpTimestampOptionInner, TcpOptionKind::TIMESTAMP>();
}

std::optional<TcpWinScaleOption> TcpHeaderView::win_scale() const
{
    return option<TcpWinScaleOption, details::TcpWinScaleOptionInner, TcpOptionKind::WIN_SCALE>();
}

std::pair<bool, std::size_t> TcpHeaderView::has_option_inner(const TcpOptionKind kind) const
{
    // iterate each kind and see if its there
    const auto options_size = bytes_.size() - TCPH_MIN_SIZE;
    const std::span<const std::byte> options_bytes{ std::next(bytes_.data(), TCPH_MIN_SIZE),
                                                    options_size };

    std::size_t offset = 0;
    while (offset < options_bytes.size()) {
        auto kind_byte = options_bytes[offset];
        if (static_cast<TcpOptionKind>(kind_byte) == kind) { return { true, offset }; }

        if (static_cast<int>(kind_byte) == 0 || static_cast<int>(kind_byte) == 1) { offset += 1; } else {
            offset += 1;
            if (offset >= options_bytes.size()) { break; }
            std::uint8_t size{};
            std::memcpy(&size, std::next(options_bytes.data(), static_cast<std::ptrdiff_t>(offset)), sizeof(size));
            offset += sizeof(size) + (size - sizeof(kind_byte) - sizeof(size));
        }
    }
    return { false, 0 };
}

TcpOptions::TcpOptions(const std::span<const std::byte> options_bytes) { parse(options_bytes); }

void TcpOptions::parse(const std::span<const std::byte> options_bytes)
{
    std::size_t offset = 0;
    while (offset < options_bytes.size()) {
        auto kind_byte = options_bytes[offset];
        switch (kind_byte) {
        case static_cast<std::byte>(TcpOptionKind::WIN_SCALE): {
            const auto subp = options_bytes.subspan(offset);
            details::TcpWinScaleOptionInner wnscl{};
            if (subp.size() < sizeof(wnscl)) { throw std::runtime_error("Tcp options is ill-formed"); }
            std::memcpy(&wnscl, subp.data(), sizeof(wnscl));

            win_scale_option_.emplace();
            auto &temp_win_scale = win_scale_option_.value();
            temp_win_scale.kind = wnscl.kind;
            temp_win_scale.size = wnscl.size;
            temp_win_scale.shift_cnt = wnscl.shift_cnt;

            offset += sizeof(wnscl);
            break;
        }
        case static_cast<std::byte>(TcpOptionKind::MSS): {
            const auto subsp = options_bytes.subspan(offset);
            details::TcpMssOptionInner mss{};
            if (subsp.size() < sizeof(mss)) { throw std::runtime_error("Tcp options is ill-formed"); }
            std::memcpy(&mss, subsp.data(), sizeof(mss));

            mss_option_.emplace();
            auto &temp_mss = mss_option_.value();
            temp_mss.kind = mss.kind;
            temp_mss.size = mss.size;
            temp_mss.mss = ntohs(mss.mss);

            offset += sizeof(mss);
            break;
        }
        case static_cast<std::byte>(TcpOptionKind::NO_OP): {
            offset += sizeof(kind_byte);
            break;
        }
        case static_cast<std::byte>(TcpOptionKind::SACK_PERM): {
            const auto subsp = options_bytes.subspan(offset);
            details::TcpSackPermOptionInner sack{};
            if (subsp.size() < sizeof(sack)) { throw std::runtime_error("Tcp options is ill-formed"); }
            std::memcpy(&sack, subsp.data(), sizeof(sack));

            sack_perm_option_.emplace();
            auto &temp_s = sack_perm_option_.value();
            temp_s.size = sack.size;
            temp_s.kind = sack.kind;

            offset += sizeof(sack);
            break;
        }
        case static_cast<std::byte>(TcpOptionKind::TIMESTAMP): {
            const auto subsp = options_bytes.subspan(offset);
            details::TcpTimestampOptionInner ts{};
            if (subsp.size() < sizeof(ts)) { throw std::runtime_error("Tcp options is ill-formed"); }
            std::memcpy(&ts, subsp.data(), sizeof(ts));

            timestamp_option_.emplace();
            auto &temp_ts = timestamp_option_.value();
            temp_ts.kind = ts.kind;
            temp_ts.size = ts.size;
            temp_ts.tv = ntohl(ts.tv);
            temp_ts.tr = ntohl(ts.tr);

            offset += sizeof(ts);
            break;
        }
        case static_cast<std::byte>(TcpOptionKind::END_OF_LIST): {
            // Stop parsing
            offset = std::numeric_limits<std::size_t>::max();
            break;
        }
        default: {
            // TODO: skip this based on SIZE field
            throw std::runtime_error("Not impl option. idk what to do");
        }
        }
    }
}

std::vector<std::byte> TcpOptions::serialize() const
{
    const auto opts_size = options_size();
    std::vector<std::byte> bytes;
    bytes.resize(opts_size);
    // std::memset(bytes.data(), 0x01, opts_size); // In case there is padding, if there is not, it will be overwritten with options

    std::ptrdiff_t offset = 0;
    if (mss_option_.has_value()) {
        const auto &mss = mss_option_.value();
        const details::TcpMssOptionInner inner{ mss.kind, mss.size, htons(mss.mss) };
        std::memcpy(bytes.data(), &inner, sizeof(inner));
        offset += sizeof(inner);
    }
    if (win_scale_option_.has_value()) {
        const auto &wnscl = win_scale_option_.value();
        const details::TcpWinScaleOptionInner inner{ wnscl.kind, wnscl.size, wnscl.shift_cnt };
        std::memcpy(std::next(bytes.data(), offset), &inner, sizeof(inner));
        offset += sizeof(inner);
    }
    if (sack_perm_option_.has_value()) {
        const auto &sackperm = sack_perm_option_.value();
        const details::TcpSackPermOptionInner inner{ sackperm.kind, sackperm.size };
        std::memcpy(std::next(bytes.data(), offset), &inner, sizeof(inner));
        offset += sizeof(inner);
    }
    if (timestamp_option_.has_value()) {
        const auto &timestamp = timestamp_option_.value();
        const details::TcpTimestampOptionInner inner{ timestamp.kind, timestamp.size, htonl(timestamp.tv), htonl(timestamp.tr) };
        std::memcpy(std::next(bytes.data(), offset), &inner, sizeof(inner));
        offset += sizeof(inner);
    }

    if (offset % 4 != 0) {
        const std::size_t to_fill_n = 4 - (static_cast<std::size_t>(offset) % 4);
        std::memset(std::next(bytes.data(), offset), 0x01, to_fill_n);// Pad with NO-OP options
    }

    return bytes;
}

std::size_t TcpOptions::options_size() const
{
    std::size_t res = 0;
    if (mss_option_.has_value()) { res += sizeof(details::TcpMssOptionInner); }
    if (win_scale_option_.has_value()) { res += sizeof(details::TcpWinScaleOptionInner); }
    if (sack_perm_option_.has_value()) { res += sizeof(details::TcpSackPermOptionInner); }
    if (timestamp_option_.has_value()) { res += sizeof(details::TcpTimestampOptionInner); }
    if (res % 4 != 0) {
        res += 4 - (res % 4);
    }
    return res;
}

TcpHeader::TcpHeader(const TcpHeaderView &tcph)
{
    const auto data = tcph.data();
    assert(!data.empty());
    std::memcpy(&hdr_, data.data(), TCPH_MIN_SIZE);

    auto options_size = data_off() * 4 - TCPH_MIN_SIZE;
    const auto options_data = data.subspan(TCPH_MIN_SIZE, options_size);
    if (!options_data.empty()) { options_.parse(options_data); }
}

std::uint16_t TcpHeader::source_port() const { return ntohs(hdr_.source); }

void TcpHeader::source_port(const std::uint16_t port) { hdr_.source = htons(port); }

std::uint16_t TcpHeader::dest_port() const { return ntohs(hdr_.dest); }

void TcpHeader::dest_port(const std::uint16_t port) { hdr_.dest = htons(port); }

std::uint32_t TcpHeader::seqn() const { return ntohl(hdr_.seq); }

void TcpHeader::seqn(const std::uint32_t num) { hdr_.seq = htonl(num); }

std::uint32_t TcpHeader::ackn() const { return ntohl(hdr_.ack_seq); }

void TcpHeader::ackn(const std::uint32_t num) { hdr_.ack_seq = htonl(num); }

std::uint8_t TcpHeader::data_off() const { return hdr_.doff; }

void TcpHeader::data_off(const std::uint8_t val) { hdr_.doff = val; }

bool TcpHeader::cwr() const { return hdr_.cwr; }

void TcpHeader::cwr(const bool val) { hdr_.cwr = val; }

bool TcpHeader::ece() const { return hdr_.ece; }

void TcpHeader::ece(const bool val) { hdr_.ece = val; }

bool TcpHeader::urg() const { return hdr_.urg; }

void TcpHeader::urg(const bool val) { hdr_.urg = val; }

bool TcpHeader::ack() const { return hdr_.ack; }

void TcpHeader::ack(const bool val) { hdr_.ack = val; }

bool TcpHeader::psh() const { return hdr_.psh; }

void TcpHeader::psh(const bool val) { hdr_.psh = val; }

bool TcpHeader::rst() const { return hdr_.rst; }

void TcpHeader::rst(const bool val) { hdr_.rst = val; }

bool TcpHeader::syn() const { return hdr_.syn; }

void TcpHeader::syn(const bool val) { hdr_.syn = val; }

bool TcpHeader::fin() const { return hdr_.fin; }

void TcpHeader::fin(const bool val) { hdr_.fin = val; }

std::uint16_t TcpHeader::window() const { return ntohs(hdr_.window); }

void TcpHeader::window(const std::uint16_t wnd_size) { hdr_.window = htons(wnd_size); }

std::uint16_t TcpHeader::checksum() const { return ntohs(hdr_.check); }

void TcpHeader::checksum(const std::uint16_t cksum) { hdr_.check = htons(cksum); }

void TcpHeader::calculate_checksum(const netparser::IpHeader &iph, std::span<const std::byte> payload)
{
    // Zero out existing checksum before calculating
    hdr_.check = 0;

    // Build pseudo header
    struct PseudoHeader
    {
        std::uint32_t src_addr;
        std::uint32_t dst_addr;
        std::uint8_t zero;
        std::uint8_t protocol;
        std::uint16_t tcp_length;
    } pseudo{};

    pseudo.src_addr = iph.source_addr();
    pseudo.dst_addr = iph.dest_addr();
    pseudo.zero = 0;
    pseudo.protocol = iph.protocol();
    const auto tcph_size = static_cast<std::uint16_t>(TCPH_MIN_SIZE + options_.options_size());
    pseudo.tcp_length = htons(tcph_size + static_cast<std::uint16_t>(payload.size()));// NOLINT

    uint32_t sum = 0;

    // Helper: accumulate 16-bit words from a raw buffer
    auto accumulate = [&sum](const void *data, std::size_t length) {
        const auto *ptr = static_cast<const uint16_t *>(data);

        while (length > 1) {
            sum += *ptr++;
            length -= 2;
        }

        // Odd trailing byte — pad with zero
        if (length == 1) { sum += *reinterpret_cast<const uint8_t *>(ptr); }
    };

    const auto opt_bytes = options_.serialize();
    accumulate(&pseudo, sizeof(pseudo));
    accumulate(&hdr_, sizeof(tcphdr));
    accumulate(opt_bytes.data(), opt_bytes.size());
    std::println("payload size: {}", payload.size());
    accumulate(payload.data(), payload.size());

    // Fold carries
    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }

    // One's complement
    hdr_.check = static_cast<uint16_t>(~sum);
}

std::uint16_t TcpHeader::urg_ptr() const { return ntohs(hdr_.urg_ptr); }

void TcpHeader::urg_ptr(const std::uint16_t ptr) { hdr_.urg_ptr = htons(ptr); }

std::vector<std::byte> TcpHeader::serialize()
{
    std::vector<std::byte> res{};
    const auto options_bytes = options_.serialize();
    res.resize(TCPH_MIN_SIZE + options_bytes.size());

    assert((TCPH_MIN_SIZE + options_bytes.size()) % 4 == 0);

    std::ptrdiff_t offset = 0;
    std::memcpy(res.data(), &hdr_, TCPH_MIN_SIZE);
    offset += TCPH_MIN_SIZE;
    if (!options_bytes.empty()) {
        std::memcpy(std::next(res.data(), offset), options_bytes.data(), options_bytes.size());
        offset += options_bytes.size();
    }

    return res;
}

}// namespace netparser