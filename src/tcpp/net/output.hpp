//
// Created by klewy on 4/27/26.
//

#ifndef TCPP_OUTPUT_HPP
#define TCPP_OUTPUT_HPP
#include "../tun.hpp"
#include "../../netparser/netparser.hpp"
#include "buffer.hpp"

class OutputInterface
{
    // TODO: write it later
};

struct HeadersInitData
{
    std::uint32_t src_addr;
    std::uint32_t dst_addr;

    std::uint16_t src_port;
    std::uint16_t dst_port;
};

// Class responsible for constructing network-level segments and sending them out
class SegmentOutput
{
public:
    SegmentOutput(IOInterface& io) : io_(io) {}

    ssize_t send(const TcpSegment& seg, const std::size_t max_size_pl, const std::uint32_t rwnd);

    void init_headers(const std::uint32_t src_addr, const std::uint32_t dst_addr, const std::uint16_t src_port, const std::uint16_t dst_port);

    void set_mss(const std::uint16_t mss);

    void clear_options();

private:
    IOInterface& io_;

    netparser::IpHeader iph_;
    netparser::TcpHeader tcph_;
};

#endif //TCPP_OUTPUT_HPP