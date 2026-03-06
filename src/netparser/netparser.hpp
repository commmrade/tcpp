//
// Created by klewy on 3/6/26.
//
#include <cstring>

#ifndef TCPP_NETPARSER_H
#define TCPP_NETPARSER_H

namespace netparser {
static constexpr std::size_t IPV4H_MIN_SIZE = 20;
static constexpr std::size_t IPV4H_PROTO_OFFSET = 9;
static constexpr std::size_t IPV4H_SRC_ADDR_OFFSET = 12;
static constexpr std::size_t IPV4H_DST_ADDR_OFFSET = 16;

/// Non-owning IP Header
class IpHeaderView
{
private:
    std::span<const std::byte> bytes_;
public:
    explicit IpHeaderView(const std::span<const std::byte> bytes);
    // TOOD: all constructors/desctructors
    // TODO: ONLY IMPL WHAT I NEED FOR TCPP

    [[nodiscard]] unsigned char protocol() const;

    [[nodiscard]] std::array<std::byte, 4> source_addr() const;
    [[nodiscard]] std::array<std::byte, 4> dest_addr() const;
    // Etc...
};

/// Owning IP Header
class IpHeader
{
private:
    std::byte ver_ihl_{0x45};
    std::byte type_of_service_{};
    unsigned short total_len_{};
    // Etc...
public:
    IpHeader() = default;
    // todo all construcotrs and destructors
    // TODO: ONLY IMPL WHAT I NEED FOR TCPP PROJECT
    explicit IpHeader(const IpHeaderView& iph)
    {
        // construct IpHeader from view
    }
};


class TcpHeaderView
{
    const std::span<const std::byte> bytes_;
public:
    explicit TcpHeaderView(std::span<std::byte> bytes) : bytes_(bytes)
    {
        std::println("been given bytes of size: {}", bytes_.size());
    }
};


} // namespace netparser

#endif //TCPP_NETPARSER_H