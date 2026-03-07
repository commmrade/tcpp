//
// Created by klewy on 3/6/26.
//
#ifndef TCPP_NETPARSER_H
#define TCPP_NETPARSER_H
#include <cstring>
#include <vector>
#include <linux/ip.h>
#include <span>
#include <cstdint>
#include <cstddef>


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


class TcpHeaderView
{
    const std::span<const std::byte> bytes_;
public:
    explicit TcpHeaderView(std::span<std::byte> bytes) : bytes_(bytes)
    {
    }
};


} // namespace netparser

#endif //TCPP_NETPARSER_H