//
// Created by klewy on 3/11/26.
//

#ifndef TCPP_TCP_HPP
#define TCPP_TCP_HPP

#include <memory>
#include <deque>
#include "common.hpp"
#include "conn.hpp"
#include "../tun.hpp"

constexpr std::string_view SRC_IP = "10.0.0.2";

class Tcp
{
public:
    explicit Tcp(std::string_view dev_name)
        : tun_(dev_name)
    {
        tun_.set_addr("10.0.0.1");
        tun_.set_mask("255.255.255.0");
        tun_.set_flags(IFF_UP | IFF_RUNNING);
    }

    void process_packet();

    std::condition_variable &get_accept_var() { return accept_var_; }

    TcpConnection &get_connection(const Quad &quad);

    bool has_conn_on_port(const std::uint16_t port) const;
    Quad pop_conn(const std::uint16_t port);

    // "USERSPACE" functions
    void bind(const std::uint16_t port);
    Quad connect(const std::uint32_t daddr, const std::uint16_t dport);

private:
    // Accept a SYN packet
    void dispatch_packet(const std::span<const std::byte> buf);

    // A set of ports that are bound and unaccepted conns (that are in "syn_recv_connections_")
    std::unordered_map<std::uint16_t, std::deque<Quad>> bound_;

    // Connections that are in SYN_RCVD state
    std::unordered_map<Quad, std::unique_ptr<TcpConnection>> syn_recv_connections_;
    // Established and "active-opened" connections
    std::unordered_map<Quad, std::unique_ptr<TcpConnection>> established_connections_;
    std::condition_variable accept_var_;

    // I guess TCP should store TUN, because I don't need it outside of this class
    Tun tun_;
};

#endif //TCPP_TCP_HPP
