#include <chrono>
#include <print>
#include "net/tcp.hpp"

#include <mutex>
#include <thread>

struct Context
{
    Tcp tcp;
    std::mutex mx;// BEFORE ACCESSING ANY FIELD IT MUST BE LOCKED

    static Context &instance()
    {
        static Context ctx{ "tun1" };
        return ctx;
    }

    ~Context() = default;

    Context(const Context &) = delete;

    Context(Context &&) = delete;

    Context &operator=(Context &) = delete;

    Context &operator=(Context &&) = delete;

private:
    explicit Context(std::string_view dev_name)
        : tcp(dev_name) {}
};


struct TcpSocket
{
    Quad quad_;

    void connect(const std::string_view daddr, const std::uint16_t dport)
    {
        auto &ctx_ = Context::instance();
        std::unique_lock conn_lock{ ctx_.mx };

        std::uint32_t addr{};
        int ret = inet_pton(AF_INET, daddr.data(), &addr);
        if (ret < 0) { throw std::runtime_error("Ill formated address"); }
        quad_ = ctx_.tcp.connect(addr, dport);

        auto &conn = ctx_.tcp.get_connection(quad_);
        conn.get_connect_var().wait(conn_lock);
        // 3 way handshake is complete at this point
    }

    ssize_t read(void *buf, const std::size_t buf_sz)
    {
        auto &ctx_ = Context::instance();
        std::unique_lock recv_lock{ ctx_.mx };
        std::println("USER: TAKE THE READ LOCK");
        auto &conn = ctx_.tcp.get_connection(quad_);

        // It isn't supposed to go into TcpConnection::read() until either new data comes in or conneciton is terminated
        conn.get_recv_var().wait(recv_lock, [&conn] { return !conn.is_recv_empty() || (conn.is_finished() && conn.is_recv_empty()); });
        return conn.read(buf, buf_sz);
    }

    ssize_t write(std::span<const std::byte> buf)
    {
        auto &ctx = Context::instance();
        std::size_t sent_total = 0;
        while (sent_total < buf.size()) {
            std::unique_lock send_lock{ ctx.mx };
            auto &conn = ctx.tcp.get_connection(quad_);
            conn.get_send_var().wait(send_lock, [&conn] { return conn.send_buf_free_space() > 0; });

            const auto to_send_buf = buf.subspan(sent_total);
            const auto result = conn.write(to_send_buf);

            if (result < 0) { throw std::runtime_error("Write error"); }
            sent_total += static_cast<std::size_t>(result);
        }
        return static_cast<ssize_t>(sent_total);
    }

    // This will initiase a one-side close (send FIN)
    void shutdown(const ShutdownType sht)
    {
        if (sht == ShutdownType::WRITE) {
            auto &ctx = Context::instance();
            std::unique_lock ctx_lock{ ctx.mx };
            ctx.tcp.get_connection(quad_).shutdown(sht);
        } else { throw std::runtime_error("Unimplemented other shutdown types"); }
    }

    template<typename Value>
    void set_option(const ConnectionOption opt, const Value& val)
    {
        auto& ctx = Context::instance();
        std::unique_lock ctx_lock { ctx.mx };
        ctx.tcp.get_connection(quad_).set_option(opt, val);
    }

    // This will initiate a full shutdown
    void close()
    {
        // This function shall not wait for connection teardown and return immediately. TCP will take care of proper closing
        auto &ctx = Context::instance();
        std::unique_lock ctx_lock{ ctx.mx };
        auto &conn = ctx.tcp.get_connection(quad_);
        conn.close();
    }
};


struct TcpListener
{
    std::uint16_t port_{};

public:
    void bind(const std::uint16_t port)
    {
        auto &ctx_ = Context::instance();
        std::unique_lock lock{ ctx_.mx };
        port_ = port;

        ctx_.tcp.bind(port);
    }

    void listen([[maybe_unused]] int backlog) {}

    TcpSocket accept()
    {
        auto &ctx_ = Context::instance();

        std::unique_lock accept_lock{ ctx_.mx };
        ctx_.tcp.get_accept_var().wait(accept_lock,
            [this, &ctx_] { return ctx_.tcp.has_conn_on_port(port_); });
        std::println("AFTER ACCEPT WAIT");
        auto quad = ctx_.tcp.pop_conn(port_);
        TcpSocket ret{ quad };
        return ret;
    }
};

std::jthread run_underlying_stuff()
{
    auto &ctx = Context::instance();

    std::jthread tcp_thread{ [](std::stop_token tok) {
            while (!tok.stop_requested()) {// NOLINT
                auto &ctx = Context::instance();
                std::unique_lock lock{ ctx.mx };
                ctx.tcp.process_packet();
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

    // sleep(3);

    // std::jthread conn_thread{[] {
    //     TcpSocket sock{};
    //     sock.connect("10.0.0.1", 8090);
    //
    //     while (true) {
    //         std::array<char, 512> buf{};
    //         auto rd = sock.read(buf.data(), buf.size());
    //         std::println("user: rd {}", rd);
    //         if (rd == 0) {
    //             std::println("user: FIN");
    //             break;
    //         }
    //     }
    // }};

    //
    TcpListener listener{};
    listener.bind(8090);
    listener.listen(999);
    std::println("user: bound and listening");
    auto sock = listener.accept();
    // sock.set_option(ConnectionOption::NAGLE, false);
    std::println("user: accepted");
    while (true) {
        std::array<std::byte, 512> buf{};
        auto rd = sock.read(buf.data(), buf.size());
        if (rd == 0) {
            std::println("user: DATA FINISHED, CLOSING...");
            break;
        } else {
            auto wr = sock.write(std::span<const std::byte>(buf.data(), static_cast<std::size_t>(rd)));
        }
    }


    // Test FIN
    // TcpListener listener{};
    // listener.bind(8090);
    // listener.listen(999);
    // std::println("user: bound and listening");
    // auto sock = listener.accept();
    // std::println("user: accepted");
    // sock.shutdown(ShutdownType::WRITE);


    //
    // sleep(3); // Wait for py test thing to start
    // TcpSocket sock{};
    // sock.connect("10.0.0.1", 8090);
    //
    // while (true) {
    //     std::array<std::byte, 100> buf{};
    //     std::memset(buf.data(), 'c', buf.size());
    //     auto wr = sock.write(buf);
    //     std::this_thread::sleep_for(std::chrono::milliseconds(100));
    // }

    sleep(2);
    net_thread.request_stop();
    net_thread.join();
    return 0;
}
