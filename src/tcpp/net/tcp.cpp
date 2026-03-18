//
// Created by klewy on 3/11/26.
//

#include "tcp.hpp"

void Tcp::accept(Tun &tun, const netparser::IpHeaderView &iph, const netparser::TcpHeaderView &tcph)
{
    Quad quad{ iph.source_addr(), tcph.source_port(), iph.dest_addr(), tcph.dest_port() };
    auto [iter, inserted] = connections.emplace(quad, std::make_unique<TcpConnection>());
    assert(inserted);
    auto &conn = iter->second;

    conn->accept(tun, iph, tcph);
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
        return;
    }

    for (const auto &[quad, conn] : connections) { conn->on_tick(tun); }

    if (ret == 0) {
        return;// Nothing to read
    }

    const ssize_t rd_bytes = tun.read(buf);
    std::size_t rd_offset = 0;
    assert(rd_bytes);

    const netparser::IpHeaderView iph{
        std::span<const std::byte>{ buf.data(), static_cast<std::size_t>(rd_bytes) - rd_offset } };
    rd_offset += iph.ihl() * 4UL;
    if (iph.protocol() == 6) {// NOLINT
        // TODO: calculate ipv4h and tcph proper

        const netparser::TcpHeaderView tcph{
            std::span<const std::byte>{ std::next(buf.data(), static_cast<std::ptrdiff_t>(rd_offset)),
                                        static_cast<std::size_t>(rd_bytes) - rd_offset } };

        rd_offset += tcph.data_off() * 4UL;
        const Quad quad{ .src_addr = iph.source_addr(), .src_port = tcph.source_port(), .dst_addr = iph.dest_addr(),
                         .dst_port = tcph.dest_port() };

        auto conn_iter = connections.find(quad);
        if (conn_iter != connections.end()) {
            const std::span<const std::byte> payload{ std::next(buf.data(), static_cast<std::ptrdiff_t>(rd_offset)),
                                                      static_cast<std::size_t>(rd_bytes) - rd_offset };
            conn_iter->second->on_packet(tun, iph, tcph, payload);
            if (conn_iter->second->state_ == TcpState::CLOSED) {
                std::println("Delete TCB");
                connections.erase(conn_iter);// TODO: this may cause problems when waiting on a cond var
            }
        } else {
            auto p_iter = pending.find(quad.dst_port);
            if (p_iter != pending.end()) {
                std::println("accepting");
                // Add this new connection to the list of pending connections, then notify userspace
                p_iter->second.push_back(quad);
                accept(tun, iph, tcph);

                accept_var_.notify_all();
            } else {
                // TODO: Send RST
            }
        }
    }
}

Quad Tcp::pop_pending(const std::uint16_t port)
{
    auto iter = pending.find(port);
    auto res = std::move(iter->second.front());
    iter->second.pop_front();
    return res;
}

Quad Tcp::connect(Tun &tun, const std::uint32_t daddr, const std::uint16_t dport)
{
    std::uint32_t s_addr{};
    // TODO: avoid hardcoding src_ip
    int ret = inet_pton(AF_INET, "10.0.0.2", &s_addr);
    assert(ret >= 0);// It can't really fail

    std::random_device rnd;
    std::mt19937 gen(rnd());
    std::uniform_int_distribution<std::uint16_t> dist(1024, std::numeric_limits<std::uint16_t>::max());
    std::uint16_t port = static_cast<std::uint16_t>(dist(gen));
    Quad quad{ daddr, dport, s_addr, port };

    auto [iter, inserted] = connections.emplace(quad, std::make_unique<TcpConnection>());
    assert(inserted);
    auto &conn = iter->second;

    conn->connect(tun, s_addr, port, daddr, dport);
    return quad;
}

void Tcp::bind(const std::uint16_t port)
{
    if (pending.contains(port)) { throw std::runtime_error("Already bound"); }
    pending.emplace(port, std::deque<Quad>{});
}