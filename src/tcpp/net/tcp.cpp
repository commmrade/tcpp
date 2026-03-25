//
// Created by klewy on 3/11/26.
//

#include "tcp.hpp"

void Tcp::dispatch_packet(Tun &tun, const std::span<const std::byte> buf)
{
    std::ptrdiff_t rd_offset = 0;
    const netparser::IpHeaderView iph{
        std::span<const std::byte>{ buf.data(), buf.size() - static_cast<std::size_t>(rd_offset) } };
    rd_offset += iph.ihl() * 4UL;
    if (iph.protocol() == IPPROTO_TCP) {// NOLINT
        // TODO: calculate ipv4h and tcph proper

        const netparser::TcpHeaderView tcph{
            std::span<const std::byte>{ std::next(buf.data(), rd_offset),
                                        buf.size() - static_cast<std::size_t>(rd_offset) } };

        rd_offset += tcph.data_off() * 4UL;
        const Quad quad{ .src_addr = iph.source_addr(), .src_port = tcph.source_port(), .dst_addr = iph.dest_addr(),
                         .dst_port = tcph.dest_port() };


        if (auto eiter = established_connections_.find(quad); eiter != established_connections_.end()){
            auto &conn = eiter->second;
            const std::span<const std::byte> payload{ std::next(buf.data(), rd_offset),
                                                      buf.size() - static_cast<std::size_t>(rd_offset) };
            conn->on_packet(tun, iph, tcph, payload);
            if (conn->get_state() == TcpState::CLOSED) {
                std::println("DELETED CONNECTION");
                established_connections_.erase(eiter);
            }
        } else if (bound_.contains(quad.dst_port)) {
            if (auto riter = syn_recv_connections_.find(quad); riter != syn_recv_connections_.end()) {
                auto& conn = riter->second;
                conn->on_packet(tun, iph, tcph, {});
                if (conn->get_state() == TcpState::ESTAB) { // Now its fully estab conn, also check for any states besides "opening" states (is_synchronized)
                    established_connections_.emplace(quad, std::unique_ptr<TcpConnection>(conn.release()));
                    syn_recv_connections_.erase(riter);
                    bound_.find(quad.dst_port)->second.push_back(quad);
                    accept_var_.notify_all();
                }
            } else {
                auto [conn_iter, inserted] = syn_recv_connections_.emplace(quad, std::make_unique<TcpConnection>());
                assert(inserted);
                conn_iter->second->accept(tun, iph, tcph);
            }
        } else {
            // Send RST
        }
    }
}

void Tcp::process_packet(Tun &tun)
{
    std::array<std::byte, 1500> buf{};// NOLINT

    std::array<pollfd, 1> poll_fds;
    auto &fd = poll_fds[0];
    fd.fd = tun.raw_fd();
    fd.events = POLLIN;
    int ret = poll(poll_fds.data(), poll_fds.size(), 1);
    if (ret < 0) {
        perror("poll");
        throw std::runtime_error(std::format("poll failed: {}", std::strerror(errno)));// NOLINT
    }

    // It makes sence to call on_tick on syn_recv_conns, because they may retransmit SYNACK
    for (const auto &[quad, conn] : syn_recv_connections_) { conn->on_tick(tun); }
    for (const auto &[quad, conn] : established_connections_) { conn->on_tick(tun); }

    if (ret == 0) {
        return;// Nothing to read
    }

    const ssize_t rd_bytes = tun.read(buf);
    std::size_t rd_offset = 0;
    assert(rd_bytes);

    dispatch_packet(tun, std::span<const std::byte>(buf.data(), (size_t)rd_bytes));
}

TcpConnection & Tcp::get_connection(const Quad &quad) {
    assert(established_connections_.contains(quad) && established_connections_.find(quad)->second);
    return *established_connections_.find(quad)->second;
}

bool Tcp::has_conn_on_port(const std::uint16_t port) const {
    return !bound_.find(port)->second.empty();
}

Quad Tcp::pop_conn(const std::uint16_t port) {
    auto iter = bound_.find(port);

    auto quad = iter->second.front();
    iter->second.pop_front();
    return quad;
}


Quad Tcp::connect(Tun &tun, const std::uint32_t daddr, const std::uint16_t dport)
{
    std::uint32_t s_addr{};
    inet_pton(AF_INET, SRC_IP.data(), &s_addr);

    std::random_device rnd;
    std::mt19937 gen(rnd());
    std::uniform_int_distribution<std::uint16_t> dist(1024, std::numeric_limits<std::uint16_t>::max());
    std::uint16_t port = static_cast<std::uint16_t>(dist(gen));
    Quad quad{ daddr, dport, s_addr, port };

    auto [iter, inserted] = established_connections_.emplace(quad, std::make_unique<TcpConnection>());
    assert(inserted);
    auto &conn = iter->second;

    conn->connect(tun, s_addr, port, daddr, dport);
    return quad;
}

void Tcp::bind(const std::uint16_t port)
{
    if (bound_.contains(port)) { throw std::runtime_error("Already bound"); }
    bound_.emplace(port, std::deque<Quad>());
}