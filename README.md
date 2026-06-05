# tcpp

[![ci](https://github.com/commmrade/tcpp/actions/workflows/ci.yml/badge.svg)](https://github.com/commmrade/tcpp/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/commmrade/tcpp/branch/main/graph/badge.svg)](https://codecov.io/gh/commmrade/tcpp)
[![CodeQL](https://github.com/commmrade/tcpp/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/commmrade/tcpp/actions/workflows/codeql-analysis.yml)

A userspace TCP/IP stack implementation in C++23, running over a Linux TUN interface. The stack implements the core TCP protocol from scratch, following the relevant RFCs, and exposes a simple socket-like API backed by a real OS network device.

## What Is This

tcpp processes raw IP packets read from a TUN interface, implements the TCP state machine, and writes response packets back through the same device. No kernel TCP is involved — everything from segment parsing to congestion control runs in userspace.

The project exists primarily as a learning exercise and portfolio piece, but the implementation is complete enough to interoperate with real TCP stacks (tested with Python's `socket` module and Scapy).

## Implemented Features

**Connection management**
- 3-way handshake (passive and active open)
- Full connection teardown (FIN/ACK exchange, `TIME_WAIT` with 2MSL timer)
- RST handling per RFC 793

**Reliability**
- Retransmission timer with exponential backoff (RFC 6298)
- RTT estimation: SRTT/RTTVAR/RTO per RFC 6298
- Karn's algorithm (no RTT sample on retransmitted segments)

**Flow control**
- Sliding window with receiver window advertisement
- Silly Window Syndrome avoidance — sender (Nagle algorithm) and receiver sides (RFC 1122)
- Zero-window probing with exponential backoff

**Congestion control** (RFC 5681)
- Slow start
- Congestion avoidance
- Fast retransmit (3 duplicate ACKs)
- Fast recovery

**TCP options**
- MSS negotiation
- TCP Timestamps (RFC 7323) with PAWS (Protection Against Wrapped Sequences)
- SACK-Permitted
- Window Scale

**Protocol correctness**
- Sequence number validation and wraparound handling
- Out-of-order segment buffering and gap tracking
- Delayed ACK (up to 200ms, or immediate on second full-sized segment)

## Architecture

```
┌─────────────────────────────────────────┐
│             Application layer           │
│   TcpListener / TcpSocket (main.cpp)    │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│                  Tcp                    │  tcp.hpp/cpp
│  - packet dispatch                      │
│  - connection map (quad → TcpConnection)│
│  - bind / connect / accept              │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│            TcpConnection                │  conn.hpp/cpp
│  - TCP state machine (RFC 793/9293)     │
│  - segment_arrived_* handlers           │
│  - on_tick() for timer events           │
│  - read() / write() for app I/O         │
│                                         │
│  ┌──────────────┐  ┌───────────────┐    │
│  │ TcpSenderBuf │  │ TcpReceiverBuf│    │  buffer.hpp/cpp
│  └──────────────┘  └───────────────┘    │
│  ┌──────────────┐  ┌───────────────┐    │
│  │CongestionCtrl│  │ RttMeasurement│    │  cong_control.hpp, timer.hpp
│  └──────────────┘  └───────────────┘    │
│  ┌──────────────────────────────────┐   │
│  │  RetransTimer / ZwpTimer / ...   │   │  timer.hpp/cpp
│  └──────────────────────────────────┘   │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│           SegmentOutput                 │  output.hpp/cpp
│  - builds IP + TCP headers              │
│  - computes checksums                   │
│  - serializes and writes to TUN         │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│              netparser                  │  src/netparser/
│  - IpHeaderView / IpHeader              │
│  - TcpHeaderView / TcpHeader            │
│  - TcpOptions (MSS, TS, SACK, WScale)   │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│                 Tun                     │  tun.hpp/cpp
│  - /dev/net/tun interface               │
│  - read() / write() raw IP packets      │
└─────────────────────────────────────────┘
```

### Key Components

`src/netparser/` — Zero-copy packet parsing. `IpHeaderView` and `TcpHeaderView` are non-owning views over raw byte spans. `IpHeader` and `TcpHeader` are owning counterparts with setters for constructing outgoing packets.

`src/tcpp/net/conn.cpp` — The TCP state machine. All RFC 793/9293 state transitions live here, split into `segment_arrived_syn_sent()` (SYN_SENT state) and `segment_arrived_other()` (all synchronized states). `on_tick()` drives timer events and the send path.

`src/tcpp/net/buffer.hpp` — `TcpBuffer` is a sorted linked list of `TcpSegment` nodes keyed by sequence number. `TcpSenderBuffer` adds `append_back()` for coalescing small writes. `TcpReceiverBuffer` adds `read()` and `check_gaps()` for reassembly.

`src/tcpp/net/cong_control.cpp` — Self-contained congestion control object. Tracks cwnd, ssthresh, and duplicate ACK count. Called from `conn.cpp` on each ACK.

`src/tcpp/timer.hpp` — A hierarchy of timer types (`RetransTimer`, `ZwpTimer`, `SwsTimer`, `ExpireTimer`) all deriving from `Timer`. `RttMeasurement` handles SRTT/RTTVAR/RTO and integrates with both timestamp-based and sequence-number-based measurement.

## Project Structure

```
tcpp/
├── src/
│   ├── netparser/          # IP/TCP header parsing library
│   │   ├── netparser.hpp
│   │   └── netparser.cpp
│   └── tcpp/               # TCP stack executable
│       ├── main.cpp         # Application entry point + socket-like API
│       ├── tun.hpp/cpp      # TUN device wrapper
│       ├── clock.hpp        # Clock abstraction (testable)
│       ├── timer.hpp/cpp    # All timer types + RTT measurement
│       ├── util.hpp         # Wrapping sequence number arithmetic
│       └── net/
│           ├── tcp.hpp/cpp          # Top-level dispatcher
│           ├── conn.hpp/cpp         # TCP connection state machine
│           ├── buffer.hpp/cpp       # Send/receive segment buffers
│           ├── output.hpp/cpp       # Packet serialisation + TUN write
│           ├── cong_control.hpp/cpp # Congestion control
│           ├── sequence.hpp         # SendSequence / ReceiveSequence
│           └── common.hpp           # Shared types (Quad, TcpState, ...)
├── test/
│   ├── parsing/             # IP/TCP header round-trip tests
│   └── tcp/
│       ├── include/tcp_common.hpp   # TcpConnectionTest fixture, MockOutput, FakeClock
│       ├── tcp_conn_estab.cpp
│       ├── tcp_conn_teardown.cpp
│       ├── tcp_retransmit_data_tests.cpp
│       ├── tcp_rto_calc_tests.cpp
│       ├── tcp_congestion_tests.cpp
│       ├── tcp_delayed_ack_tests.cpp
│       ├── tcp_zero_window_tests.cpp
│       ├── tcp_sws_tests.cpp
│       ├── tcp_timestamp_opt_tests.cpp
│       ├── tcp_msl_timeout_tests.cpp
│       └── tcp_buffer_tests.cpp
├── CMakeLists.txt
├── Dependencies.cmake
├── ProjectOptions.cmake
└── run.sh
```

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| [fmtlib/fmt](https://github.com/fmtlib/fmt) | 12.1.0 | String formatting |
| [gabime/spdlog](https://github.com/gabime/spdlog) | 1.17.0 | Logging |
| [google/googletest](https://github.com/google/googletest) | 1.14.0 | Unit testing |

All dependencies are fetched automatically at configure time via [CPM.cmake](https://github.com/cpm-cmake/CPM.cmake). No manual installation required.

**Build requirements:**
- CMake ≥ 3.29
- C++23-capable compiler: GCC ≥ 14 or Clang ≥ 19
- Linux (runtime: TUN interface requires `CAP_NET_ADMIN` or root)
- Ninja (recommended) or Make

## Building

```bash
# Out-of-source build (required)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

With a specific compiler:

```bash
CC=clang CXX=clang++ cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

Using a preset:

```bash
cmake . --preset unixlike-gcc-debug
cmake --build out/build/unixlike-gcc-debug
```

## Running

The stack needs `CAP_NET_ADMIN` to create and configure the TUN device. The easiest path is the provided script:

```bash
cmake --build build --target setcap   # grants CAP_NET_ADMIN to the binary (requires sudo once)
./run.sh                              # starts the stack and configures the TUN interface
```

What `run.sh` does:

1. Starts `main` in the background (creates `tun1`, stack listens on `10.0.0.2`)
2. Assigns `10.0.0.1/24` to `tun1` from the host side
3. Brings the interface up

After that, connecting to `10.0.0.2:8090` from the host exercises the stack. The default `main.cpp` listens on port 8090 and echoes data back.

**Network layout:**

```
Host                  tcpp stack
10.0.0.1  ←─ tun1 ─→  10.0.0.2
```

## Testing

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
cd build && ctest -C Debug
```

The test suite uses Google Test and GMock with two key test utilities:

`MockOutput` — a GMock mock of `OutputInterface` that intercepts all outgoing segments, allowing tests to assert on what the stack sends without a real network device.

`FakeClock` — a deterministic clock whose time advances only when `advance(ms)` is called explicitly, enabling precise timer tests without `sleep()`.

Test coverage includes:

- IP and TCP header parsing and serialization round-trips
- Passive and active 3-way handshake
- Active and passive connection teardown, `TIME_WAIT` expiry
- Retransmission with exponential backoff, Karn's algorithm
- RTT measurement convergence
- Slow start, congestion avoidance, fast retransmit and fast recovery
- Delayed ACK (timer-based and segment-count-based)
- Sender and receiver Silly Window Syndrome avoidance
- Zero-window probing with exponential backoff and window re-open
- TCP Timestamps negotiation, RTT measurement via TSecr, PAWS
- Receiver buffer: out-of-order delivery, gap filling, reads across segment boundaries

## License

GPL-3.0. See [LICENSE](LICENSE).
