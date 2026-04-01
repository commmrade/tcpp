//
// Created by klewy on 3/6/26.
//
#ifndef TCPP_NETPARSER_H
#define TCPP_NETPARSER_H
#include <spdlog/spdlog.h>

#include <any>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <span>
#include <unordered_map>
#include <variant>
#include <vector>
#include <netinet/in.h>


namespace netparser {

namespace details {

#pragma pack(push, 1)
    struct TcpMssOptionInner
    {
        std::uint8_t kind;
        std::uint8_t size;
        std::uint16_t mss;
    };

    struct TcpSackPermOptionInner
    {
        std::uint8_t kind;
        std::uint8_t size;
    };

    struct TcpTimestampOptionInner
    {
        std::uint8_t kind;
        std::uint8_t size;
        std::uint32_t tv;
        std::uint32_t tr;
    };

    struct TcpWinScaleOptionInner
    {
        std::uint8_t kind;
        std::uint8_t size;
        std::uint8_t shift_cnt;
    };
#pragma pack(pop)
}


static constexpr std::size_t IPV4H_MIN_SIZE = 20;
static constexpr std::size_t IPV4H_PROTO_OFFSET = 9;
static constexpr std::size_t IPV4H_SRC_ADDR_OFFSET = 12;
static constexpr std::size_t IPV4H_DST_ADDR_OFFSET = 16;
static constexpr std::size_t IPV4H_VER_OFFSET = 0;
static constexpr std::size_t IPV4H_IHL_OFFSET = 0;
static constexpr std::size_t IPV4H_TYPE_OF_SERVICE_OFFSET = 1;
static constexpr std::size_t IPV4H_TOT_LEN_OFFSET = 2;
static constexpr std::size_t IPV4H_ID_OFFSET = 4;
static constexpr std::size_t IPV4H_FLAGS_OFFSET = 6;
static constexpr std::size_t IPV4H_FRAG_OFFSET = 6;
static constexpr std::size_t IPV4H_TTL_OFFSET = 8;
static constexpr std::size_t IPV4H_HDR_CHECKSUM_OFFSET = 10;


/// Non-owning IP Header
class IpHeaderView
{
private:
    std::span<const std::byte> bytes_;

public:
    explicit IpHeaderView(const std::span<const std::byte> bytes);
    // TOOD: all constructors/desctructors
    // TODO: ONLY IMPL WHAT I NEED FOR TCPP

    [[nodiscard]] std::uint8_t version() const;
    [[nodiscard]] std::uint8_t ihl() const;

    [[nodiscard]] std::uint8_t type_of_service() const;

    [[nodiscard]] std::uint16_t total_len() const;
    [[nodiscard]] std::uint16_t id() const;
    [[nodiscard]] bool dont_fragment() const;
    [[nodiscard]] bool more_fragments() const;
    [[nodiscard]] std::uint16_t frag_offset() const;
    [[nodiscard]] std::uint8_t ttl() const;
    [[nodiscard]] std::uint16_t checksum() const;
    [[nodiscard]] std::uint8_t protocol() const;

    [[nodiscard]] std::uint32_t source_addr() const;
    [[nodiscard]] std::uint32_t dest_addr() const;

    [[nodiscard]] std::span<const std::byte> data() const;
    // No options yet
};

/// Owning IP Header
class IpHeader
{
private:
    iphdr hdr_{};

public:
    IpHeader() = default;
    explicit IpHeader(const IpHeaderView &iph);

    [[nodiscard]] std::uint8_t version() const;
    void version(const std::uint8_t ver);
    [[nodiscard]] std::uint8_t ihl() const;
    void ihl(const std::uint8_t ihl);

    [[nodiscard]] std::uint8_t type_of_service() const;
    void type_of_service(const std::uint8_t tos);

    [[nodiscard]] std::uint16_t total_len() const;
    /// Pass argument in HOST Byte Order
    void total_len(const std::uint16_t len);
    [[nodiscard]] std::uint16_t id() const;
    /// Pass argument in HOST Byte Order
    void id(const std::uint16_t ident);

    [[nodiscard]] bool dont_fragment() const;
    void dont_fragment(bool val);

    [[nodiscard]] bool more_fragments() const;
    void more_fragments(bool val);

    [[nodiscard]] std::uint16_t frag_offset() const;
    /// Pass argument in HOST Byte Order
    void frag_offset(const std::uint16_t frag_off);

    [[nodiscard]] std::uint8_t ttl() const;
    void ttl(const std::uint8_t val);

    [[nodiscard]] std::uint16_t checksum() const;
    /// Pass argument in HOST Byte Order
    void checksum(const std::uint16_t cksum);

    [[nodiscard]] std::uint8_t protocol() const;
    void protocol(const std::uint8_t proto);

    void calculate_checksum();

    /// Returns IPV4 addr. in NETWORK order
    [[nodiscard]] std::uint32_t source_addr() const;
    /// Pass argument in Network Byte Order
    void source_addr(const std::uint32_t addr);

    /// Returns IPV4 addr. in NETWORK order
    [[nodiscard]] std::uint32_t dest_addr() const;
    /// Pass argument in Network Byte Order
    void dest_addr(const std::uint32_t addr);

    std::vector<std::byte> serialize() const;
};


// Specifies the size of the TCP header in 32-bit words. The minimum size header is 5 words and the maximum is 15 words thus giving the minimum size of 20 bytes and maximum of 60 bytes
static constexpr std::size_t TCPH_MIN_SIZE = sizeof(tcphdr);
static constexpr std::size_t TCPH_MAX_SIZE = 60;
static constexpr std::size_t TCPH_SRC_PORT_OFFSET = 0;
static constexpr std::size_t TCPH_DEST_PORT_OFFSET = 2;
static constexpr std::size_t TCPH_SEQN_OFFSET = 4;
static constexpr std::size_t TCPH_ACKN_OFFSET = 8;
static constexpr std::size_t TCPH_DOFF_OFFSET = 12;
static constexpr std::size_t TCPH_FLAGS_OFFSET = 13;
static constexpr std::size_t TCPH_WIN_OFFSET = 14;
static constexpr std::size_t TCPH_CKSUM_OFFSET = 16;
static constexpr std::size_t TCPH_URGPTR_OFFSET = 18;

enum class TcpOptionKind
{
    END_OF_LIST = 0,
    NO_OP = 1,
    MSS = 2,
    WIN_SCALE = 3,
    SACK_PERM = 4,
    TIMESTAMP = 8,
};

struct TcpMssOption
{
    TcpMssOption() = default;

    explicit TcpMssOption(const details::TcpMssOptionInner inner)
        : kind(inner.kind), size(inner.size), mss(ntohs(inner.mss)) {}

    std::uint8_t kind{ 2 };
    std::uint8_t size{ 4 };
    std::uint16_t mss{};
};


struct TcpSackPermOption
{
    TcpSackPermOption() = default;

    explicit TcpSackPermOption(const details::TcpSackPermOptionInner inner)
        : kind(inner.kind), size(inner.size) {}

    std::uint8_t kind{ 4 };
    std::uint8_t size{ 2 };
};

struct TcpTimestampOption
{
    TcpTimestampOption() = default;

    explicit TcpTimestampOption(const details::TcpTimestampOptionInner inner)
        : kind(inner.kind), size(inner.size), tv(ntohl(inner.tv)), tr(ntohl(inner.tr)) {}

    std::uint8_t kind{ 8 };
    std::uint8_t size{ 10 };
    std::uint32_t tv;
    std::uint32_t tr;
};

struct TcpWinScaleOption
{
    TcpWinScaleOption() = default;

    explicit TcpWinScaleOption(const details::TcpWinScaleOptionInner inner)
        : kind(inner.kind), size(inner.size), shift_cnt(inner.shift_cnt) {}

    std::uint8_t kind{ 3 };
    std::uint8_t size{ 3 };
    std::uint8_t shift_cnt;
};

class TcpHeaderView
{
    const std::span<const std::byte> bytes_;

public:
    TcpHeaderView() = default;
    explicit TcpHeaderView(const std::span<const std::byte> bytes);

    [[nodiscard]] std::uint16_t source_port() const;
    [[nodiscard]] std::uint16_t dest_port() const;

    [[nodiscard]] std::uint32_t seqn() const;
    [[nodiscard]] std::uint32_t ackn() const;

    [[nodiscard]] std::uint8_t data_off() const;

    // Flags
    [[nodiscard]] bool cwr() const;
    [[nodiscard]] bool ece() const;
    [[nodiscard]] bool urg() const;
    [[nodiscard]] bool ack() const;
    [[nodiscard]] bool psh() const;
    [[nodiscard]] bool rst() const;
    [[nodiscard]] bool syn() const;
    [[nodiscard]] bool fin() const;

    [[nodiscard]] std::uint16_t window() const;
    [[nodiscard]] std::uint16_t checksum() const;
    [[nodiscard]] std::uint16_t urg_ptr() const;

    [[nodiscard]] std::span<const std::byte> data() const { return bytes_; }

    bool has_option(const TcpOptionKind kind) const;
    [[nodiscard]] std::optional<TcpMssOption> mss() const;
    [[nodiscard]] std::optional<TcpSackPermOption> sack_perm() const;
    [[nodiscard]] std::optional<TcpTimestampOption> timestamp() const;
    [[nodiscard]] std::optional<TcpWinScaleOption> win_scale() const;

private:
    [[nodiscard]] std::pair<bool, std::size_t> has_option_inner(const TcpOptionKind kind) const;

    template<typename T, typename T_INNER, TcpOptionKind KIND> requires std::constructible_from<T, T_INNER>
    [[nodiscard]] std::optional<T> option() const
    {
        auto [has, pos] = has_option_inner(KIND);
        if (!has) { return std::nullopt; }

        const auto options_size = bytes_.size() - TCPH_MIN_SIZE;
        const std::span<const std::byte> options_bytes{ std::next(bytes_.data(), TCPH_MIN_SIZE),
                                                        options_size };

        const auto subsp = options_bytes.subspan(pos);
        if (subsp.size() < sizeof(T_INNER)) {
            spdlog::warn("{} TCP option is ill-formed", static_cast<int>(KIND));
            return std::nullopt;
        }

        T_INNER opt{};
        std::memcpy(&opt, subsp.data(), sizeof(T_INNER));

        std::optional<T> res;
        res.emplace(opt);
        return res;
    }
};

class TcpOptions
{
private:
    std::optional<TcpMssOption> mss_option_;
    std::optional<TcpWinScaleOption> win_scale_option_;
    std::optional<TcpSackPermOption> sack_perm_option_;
    std::optional<TcpTimestampOption> timestamp_option_;

public:
    TcpOptions() = default;
    explicit TcpOptions(const std::span<const std::byte> options_bytes);
    void parse(const std::span<const std::byte> options_bytes);

    [[nodiscard]] std::vector<std::byte> serialize() const;

    [[nodiscard]] std::size_t options_size() const;

    void clear()
    {
        mss_option_.reset();
        win_scale_option_.reset();
        sack_perm_option_.reset();
        timestamp_option_.reset();
    }

    [[nodiscard]] bool has_option(const TcpOptionKind kind) const
    {
        switch (kind) {
        case TcpOptionKind::WIN_SCALE: { return win_scale_option_.has_value(); }
        case TcpOptionKind::MSS: { return mss_option_.has_value(); }
        case TcpOptionKind::TIMESTAMP: { return timestamp_option_.has_value(); }
        case TcpOptionKind::SACK_PERM: { return sack_perm_option_.has_value(); }
        default:
            return false;
        }
    }

    [[nodiscard]] std::optional<TcpWinScaleOption> win_scale() const { return win_scale_option_; }

    void win_scale(const std::uint8_t shift)
    {
        TcpWinScaleOption opt{};
        opt.shift_cnt = shift;
        win_scale_option_ = std::move(opt);
    }

    [[nodiscard]] std::optional<TcpMssOption> mss() const { return mss_option_; }

    void mss(const std::uint16_t mss)
    {
        TcpMssOption opt;
        opt.mss = mss;
        mss_option_ = std::move(opt);
    }

    [[nodiscard]] std::optional<TcpSackPermOption> sack_perm() const { return sack_perm_option_; }

    void set_sack_perm()
    {
        TcpSackPermOption opt{};
        sack_perm_option_ = std::move(opt);
    }

    [[nodiscard]] std::optional<TcpTimestampOption> timestamp() const { return timestamp_option_; }

    void timestamp(const std::uint32_t tv, const std::uint32_t tr)
    {
        TcpTimestampOption opt{};
        opt.tv = tv;
        opt.tr = tr;
        timestamp_option_ = std::move(opt);
    }
};

class TcpHeader
{
private:
    tcphdr hdr_{};
    TcpOptions options_;
public:
    TcpHeader() = default;
    explicit TcpHeader(const TcpHeaderView &tcph);

    /// Everything is set/returned in Host Byte Order
    [[nodiscard]] std::uint16_t source_port() const;
    void source_port(const std::uint16_t port);

    [[nodiscard]] std::uint16_t dest_port() const;
    void dest_port(const std::uint16_t port);

    [[nodiscard]] std::uint32_t seqn() const;
    void seqn(const std::uint32_t num);

    [[nodiscard]] std::uint32_t ackn() const;
    void ackn(const std::uint32_t num);

    [[nodiscard]] std::uint8_t data_off() const;
    void data_off(const std::uint8_t val);

    // Flags
    [[nodiscard]] bool cwr() const;
    void cwr(const bool val);

    [[nodiscard]] bool ece() const;
    void ece(const bool val);

    [[nodiscard]] bool urg() const;
    void urg(const bool val);

    [[nodiscard]] bool ack() const;
    void ack(const bool val);

    [[nodiscard]] bool psh() const;
    void psh(const bool val);

    [[nodiscard]] bool rst() const;
    void rst(const bool val);

    [[nodiscard]] bool syn() const;
    void syn(const bool val);

    [[nodiscard]] bool fin() const;
    void fin(const bool val);

    [[nodiscard]] std::uint16_t window() const;
    void window(const std::uint16_t wnd_size);

    [[nodiscard]] std::uint16_t checksum() const;
    void checksum(const std::uint16_t cksum);

    void calculate_checksum(const netparser::IpHeader &iph, std::span<const std::byte> payload);

    [[nodiscard]] std::uint16_t urg_ptr() const;
    void urg_ptr(const std::uint16_t ptr);

    [[nodiscard]] std::vector<std::byte> serialize();

    [[nodiscard]] TcpOptions &options() { return options_; }
    [[nodiscard]] const TcpOptions &options() const { return options_; }
};
}// namespace netparser

#endif //TCPP_NETPARSER_H
