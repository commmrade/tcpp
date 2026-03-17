//
// Created by klewy on 3/6/26.
//
#ifndef TCPP_NETPARSER_H
#define TCPP_NETPARSER_H
#include <any>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <span>
#include <unordered_map>
#include <variant>
#include <vector>


namespace netparser {
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
    explicit IpHeader(const IpHeaderView& iph);

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


static constexpr std::size_t TCPH_MIN_SIZE = 20;
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
    SACK_PERM = 4,
    TIMESTAMP = 8,
};

struct TcpMssOption
{
    std::uint8_t kind;
    std::uint8_t size;
    std::uint16_t mss;
};

struct TcpNoOpOption
{
    std::uint8_t kind;
};

struct TcpSackPermOption
{
    std::uint8_t kind;
    std::uint8_t size;
};

struct TcpTimestampOption
{
    std::uint8_t kind;
    std::uint8_t size;
    std::uint32_t tv;
    std::uint32_t tr;
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

    [[nodiscard]] std::span<const std::byte> data() const
    {
        return bytes_;
    }

    bool has_option(const TcpOptionKind kind) const;
    // TODO: Options
};

class TcpOptions
{
private:
    std::unordered_map<TcpOptionKind, std::any> options_;
public:
    explicit TcpOptions(const std::span<const std::byte> options_bytes)
    {
        std::size_t offset = 0;
        while (offset < options_bytes.size()) {
            auto kind_byte = options_bytes[offset];
            switch (kind_byte) {
            case static_cast<std::byte>(TcpOptionKind::MSS): {
                if (offset + 1 >= options_bytes.size()) {
                    break;
                }
                const auto kind = static_cast<std::uint8_t>(kind_byte);
                std::uint8_t size{};
                std::memcpy(&size, std::next(options_bytes.data(), static_cast<std::ptrdiff_t>(offset + 1)), sizeof(size));
                options_.emplace(TcpOptionKind::MSS, std::make_any<TcpMssOption>(kind, size));

                offset += sizeof(kind) + sizeof(size);
                break;
            }
            case static_cast<std::byte>(TcpOptionKind::NO_OP): {
                const auto kind = static_cast<std::uint8_t>(kind_byte);
                options_.emplace(TcpOptionKind::NO_OP, std::make_any<TcpNoOpOption>(kind));

                offset += sizeof(kind);
                break;
            }
            case static_cast<std::byte>(TcpOptionKind::SACK_PERM): {
                if (offset + 1 >= options_bytes.size()) {
                    break;
                }
                const auto kind = static_cast<std::uint8_t>(kind_byte);
                std::uint8_t size{};
                std::memcpy(&size, std::next(options_bytes.data(), static_cast<std::ptrdiff_t>(offset + 1)), sizeof(size));
                options_.emplace(TcpOptionKind::SACK_PERM, std::make_any<TcpSackPerm>(kind, size));

                offset += sizeof(kind) + sizeof(size);
                break;
            }
            case static_cast<std::byte>(TcpOptionKind::TIMESTAMP): {
                if (offset + 1 + 4 + 4 >= options_bytes.size()) {
                    break;
                }

                const auto kind = static_cast<std::uint8_t>(kind_byte);
                std::uint8_t size{};
                std::uint32_t tv{};
                std::uint32_t tr{};

                // TODO: finish parsing this, default
                // 2. Write methods to get options in TcpView

                std::memcpy(&size, std::next(options_bytes.data(), offset), sizeof(size));

                break;
            }
            case static_cast<std::byte>(TcpOptionKind::END_OF_LIST): {
                // Stop parsing
                break;
            }
            }
        }
    }
};

class TcpHeader
{
private:
    tcphdr hdr_{};
public:
    TcpHeader() = default;
    explicit TcpHeader(const TcpHeaderView& tcph);

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

    void calculate_checksum(const netparser::IpHeader& iph, std::span<const std::byte> payload);

    [[nodiscard]] std::uint16_t urg_ptr() const;
    void urg_ptr(const std::uint16_t ptr);

    std::vector<std::byte> serialize() const;

    // TODO: options
};

} // namespace netparser

#endif //TCPP_NETPARSER_H