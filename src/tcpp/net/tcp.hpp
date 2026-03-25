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
public:
    void process_packet(Tun &tun);

    std::condition_variable &get_accept_var() { return accept_var_; }

    TcpConnection &get_connection(const Quad &quad)
    {
        assert(established_connections_.contains(quad) && established_connections_.find(quad)->second);
        return *established_connections_.find(quad)->second;
    }

    bool has_conn_on_port(const std::uint16_t port) const
    {
        return !bound_.find(port)->second.empty();
    }
    Quad pop_conn(const std::uint16_t port)
    {
        auto iter = bound_.find(port);

        auto quad = iter->second.front();
        iter->second.pop_front();
        return quad;
    }

    // "USERSPACE" functions
    void bind(const std::uint16_t port);
    Quad connect(Tun &tun, const std::uint32_t daddr, const std::uint16_t dport);

private:
    // Accept a SYN packet
    void dispatch_packet(Tun& tun, const std::span<const std::byte> buf);

    // A set of ports that are bound and unaccepted conns
    std::unordered_map<std::uint16_t, std::deque<Quad>> bound_;

    // Connections that are in SYN_RCVD state
    std::unordered_map<Quad, std::unique_ptr<TcpConnection>> syn_recv_connections_{};
    // Established and "active-opened" connections
    std::unordered_map<Quad, std::unique_ptr<TcpConnection>> established_connections_{};
    std::condition_variable accept_var_;
};

#endif //TCPP_TCP_HPP