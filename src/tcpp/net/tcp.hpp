//
// Created by klewy on 3/11/26.
//

#ifndef TCPP_TCP_HPP
#define TCPP_TCP_HPP

#include "../../netparser/netparser.hpp"
#include <memory>
#include <deque>
#include "common.hpp"
#include "conn.hpp"
#include "../tun.hpp"

class Tcp
{
    using PortType = std::uint16_t;
    std::unordered_map<Quad, std::unique_ptr<TcpConnection>> connections;
    // Sockets that are ready to be accepted. When they are accepted, they are removed from this queue.
    std::unordered_map<PortType, std::deque<Quad>> pending;
    std::condition_variable accept_var_;

    // Accept a SYN packet
    void accept(Tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph);

public:
    void process_packet(Tun &tun);

    std::condition_variable &get_accept_var() { return accept_var_; }

    TcpConnection &get_connection(const Quad &quad)
    {
        assert(connections.contains(quad));
        return *connections.find(quad)->second;
    }

    bool has_pending(const std::uint16_t port) const { return pending.contains(port); }
    bool is_pending_empty(const std::uint16_t port) const { return pending.find(port)->second.empty(); }
    Quad pop_pending(const std::uint16_t port);

    // "USERSPACE" functions
    void bind(const std::uint16_t port);
    Quad connect(Tun &tun, const std::uint32_t daddr, const std::uint16_t dport);
};

#endif //TCPP_TCP_HPP