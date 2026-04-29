//
// Created by klewy on 4/27/26.
//

#include "output.hpp"

ssize_t SegmentOutput::send(const TcpSegment &seg, const std::size_t max_size_pl, const std::uint32_t rwnd) {
    // TODO: How to support options

    iph_.total_len(
        static_cast<std::uint16_t>(static_cast<std::size_t>(iph_.ihl() * 4) + (
                                       netparser::TCPH_MIN_SIZE + tcph_.options().options_size()) +
                                   seg.payload_size()));

    iph_.calculate_checksum();
    const auto ip_data = iph_.serialize();

    tcph_.seqn(seg.seq_start());
    tcph_.ackn(seg.ackn());

    // Extract params from seg and set into tcph_
    // TODO: Maybe code TcpSegment::serialize()??
    tcph_.ack(seg.ack());
    tcph_.syn(seg.syn());
    tcph_.fin(seg.fin());
    tcph_.rst(seg.rst());

    tcph_.window(static_cast<std::uint16_t>(rwnd));
    const auto tcph_size = static_cast<std::uint8_t>(netparser::TCPH_MIN_SIZE + tcph_.options().options_size());
    tcph_.data_off(tcph_size / 4);
    tcph_.calculate_checksum(iph_, seg.payload());

    const auto tcp_data = tcph_.serialize();

    std::vector<std::byte> buf{};
    buf.reserve(
        static_cast<std::size_t>(iph_.ihl() * 4) + static_cast<std::size_t>(tcph_.data_off() * 4) + seg.payload_size());

    std::copy(ip_data.begin(), ip_data.end(), std::back_inserter(buf));
    std::copy(tcp_data.begin(), tcp_data.end(), std::back_inserter(buf));

    const auto payload = seg.payload();
    if (!payload.empty()) {
        std::copy(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(max_size_pl), std::back_inserter(buf));
    }

    const auto written = io_.write(std::span<const std::byte>{buf.data(), buf.size()});
    if (written < 0) {
        throw std::runtime_error(std::format("Write failed: {}", std::strerror(errno)));
    }
    std::println("Written {} bytes, buf is {} bytes", written, buf.size());
    assert(static_cast<std::size_t>(written) == buf.size());

    return written;
}

void SegmentOutput::init_headers(const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port) {
    iph_.version(4);
    iph_.ihl(5);
    iph_.dont_fragment(true);
    iph_.more_fragments(false);
    iph_.ttl(64);
    iph_.protocol(IPPROTO_TCP);
    iph_.source_addr(src_addr);
    iph_.dest_addr(dst_addr);

    tcph_.source_port(src_port);
    tcph_.dest_port(dst_port);
}

void SegmentOutput::set_mss(const std::uint16_t mss) {
    tcph_.options().mss(mss);
}

void SegmentOutput::clear_options() {
    tcph_.options().clear();
}