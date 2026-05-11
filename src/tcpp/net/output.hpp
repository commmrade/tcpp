//
// Created by klewy on 4/27/26.
//

#ifndef TCPP_OUTPUT_HPP
#define TCPP_OUTPUT_HPP
#include "../tun.hpp"
#include "../../netparser/netparser.hpp"
#include "buffer.hpp"

struct HeadersInitData
{
    std::uint32_t src_addr;
    std::uint32_t dst_addr;

    std::uint16_t src_port;
    std::uint16_t dst_port;
};

class OutputInterface
{
public:
    virtual ~OutputInterface() = default;
    virtual ssize_t send(const TcpSegment& seg, const std::size_t max_size_pl, const std::uint32_t rwnd) = 0;
    virtual void init_headers(const std::uint32_t src_addr, const std::uint32_t dst_addr, const std::uint16_t src_port, const std::uint16_t dst_port) = 0;
    virtual void set_mss(const std::uint16_t mss) = 0;
    virtual void clear_options() = 0;
};
// Class responsible for constructing network-level segments and sending them out
class SegmentOutput final : public OutputInterface
{
public:
    explicit SegmentOutput(IOInterface& io) : io_(io) {}

    ssize_t send(const TcpSegment& seg, const std::size_t max_size_pl, const std::uint32_t rwnd) override;
    void init_headers(const std::uint32_t src_addr, const std::uint32_t dst_addr, const std::uint16_t src_port, const std::uint16_t dst_port) override;
    void set_mss(const std::uint16_t mss) override;
    void clear_options() override;
private:
    IOInterface& io_;
    netparser::IpHeader iph_;
    netparser::TcpHeader tcph_;
};

#endif //TCPP_OUTPUT_HPP
