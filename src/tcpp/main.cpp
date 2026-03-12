#include <print>
#include "tun.hpp"
#include "tcp.hpp"

#include <mutex>
#include <thread>

struct Context
{
    Tcp tcp{};
    tun tun;
    std::mutex mx;// BEFORE ACCESSING ANY FIELD IT MUST BE LOCKED

    static Context &instance()
    {
        static Context ctx{"dev1"};
        return ctx;
    }

    Context(const Context&) = delete;

    Context(Context&&) = delete;

    Context& operator=(Context&) = delete;

    Context& operator=(Context&&) = delete;
private:
    explicit Context(std::string_view dev_name)
        : tun(dev_name) {}
};

struct TcpSocket
{
    Quad quad_;

    void connect(const std::string_view daddr, const std::uint16_t dport)
    {
        auto& ctx_ = Context::instance();
        std::unique_lock conn_lock{ctx_.mx};
        std::println("user: connect got mutex");

        std::uint32_t addr{};
        int ret = inet_pton(AF_INET, daddr.data(), &addr);
        if (ret < 0) {
            throw std::runtime_error("Ill formated address");
        }
        quad_ = ctx_.tcp.connect(ctx_.tun,  addr, dport);

        auto& conn = ctx_.tcp.connections[quad_];
        conn->conn_var_.wait(conn_lock);
        std::println("user: handshaked");
        // 3 way handshake is complete at this point
    }

    ssize_t read(void *buf, const std::size_t buf_sz)
    {
        auto& ctx_ = Context::instance();
        std::unique_lock recv_lock{ ctx_.mx };
        std::println("USER: TAKE THE READ LOCK");
        auto &conn = ctx_.tcp.connections[quad_];
        conn->recv_var_.wait(recv_lock);

        assert(ctx_.tcp.connections.contains(quad_));
        // We got notified
        if (conn->is_finished) {
            return 0;// EOF
        }

        return 148;
    }

    ssize_t write(const void *buf, const std::size_t buf_sz)
    {
        // NOT IMPLEMENTED
        throw std::runtime_error("not implemented");
    }
};


struct TcpListener
{
    std::uint16_t port_{};
public:
    void bind(const std::uint16_t port)
    {
        auto& ctx_ = Context::instance();
        std::unique_lock lock{ ctx_.mx };
        port_ = port;
        if (ctx_.tcp.pending.contains(port)) { throw std::runtime_error("Already bound"); }
        ctx_.tcp.pending.emplace(port, std::deque<Quad>{});
    }

    void listen(int backlog)
    {
        assert(backlog > 0);
        // TODO: set max capacity
        auto& ctx_ = Context::instance();
        std::unique_lock lock{ ctx_.mx };

        auto iter = ctx_.tcp.pending.find(port_);
        assert(iter != ctx_.tcp.pending.end());

        // TODO: find a way to set a limit
        // iter->second.reserve(static_cast<std::size_t>(backlog));
    }

    TcpSocket accept()
    {
        auto& ctx_ = Context::instance();

        std::unique_lock accept_lock{ ctx_.mx };
        ctx_.tcp.accept_var_.wait(accept_lock,
            [this, &ctx_] { return ctx_.tcp.pending.contains(port_) && !ctx_.tcp.pending[port_].empty(); });

        auto iter = ctx_.tcp.pending.find(port_);

        auto quad = iter->second.front();
        iter->second.pop_front();

        TcpSocket ret{ quad };
        return ret;
    }
};

std::jthread run_underlying_stuff()
{
    auto& ctx = Context::instance();
    ctx.tun.set_addr("10.0.0.1");
    ctx.tun.set_mask("255.255.255.0");
    ctx.tun.set_flags(IFF_UP | IFF_RUNNING);
    std::jthread tcp_thread{ [] {
            while (true) {// NOLINT
                auto& ctx = Context::instance();
                std::unique_lock lock{ ctx.mx };
                ctx.tcp.process_packet(ctx.tun);
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));// Let other threads lock the mutex
            }
        }
    };
    return tcp_thread;
}

int main()
{
    auto net_thread = run_underlying_stuff();

    sleep(3);

    TcpSocket sock{};
    sock.connect("10.0.0.1", 8090);

    while (true) {
        std::array<char, 512> buf{};
        auto rd = sock.read(buf.data(), buf.size());
        if (rd == 0) {
            std::println("user: FIN");
            break;
        }
    }

    // TcpListener listener{};
    // listener.bind(8090);
    // listener.listen(999);
    // std::println("user: bound and listening");
    // auto sock = listener.accept();
    // std::println("user: accepted");
    // while (true) {
    //     std::array<char, 512> buf{};
    //     auto rd = sock.read(buf.data(), buf.size());
    //     if (rd == 0) {
    //         std::println("user: DATA FINISHED, CLOSING...");
    //         break;
    //     }
    // }


    sleep(2);

    net_thread.join();
    return 0;
}