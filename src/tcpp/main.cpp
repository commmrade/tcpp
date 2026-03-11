#include <print>
#include "tun.hpp"
#include "tcp.hpp"

#include <mutex>
#include <thread>

struct Context
{
    Tcp tcp{};
    tun tun;
    std::mutex mx; // BEFORE ACCESSING ANY FIELD IT MUST BE LOCKED

    Context(std::string_view dev_name)
        : tun(dev_name) {}
};

struct Socket
{
    // TODO: Fix this
    Quad quad_;
    Context &ctx_;


    ssize_t read(void *buf, const std::size_t buf_sz)
    {
        std::unique_lock recv_lock{ctx_.mx};
        assert(ctx_.tcp.connections.contains(quad_));
        auto& conn = ctx_.tcp.connections[quad_];
        conn->recv_var_.wait(recv_lock);

        // We got notified
        if (conn->is_finished) {
            return 0; // EOF
        }

        return 148;
    }

    ssize_t write(const void *buf, const std::size_t buf_sz)
    {
        // NOT IMPLEMENTED
        throw std::runtime_error("not implemented");
    }
};


struct Listener
{
    // TODO: this is kinda stupid?
    Context &ctx_;
    std::uint16_t port_{};

public:
    void bind(const std::uint16_t port)
    {
        std::unique_lock lock{ctx_.mx};
        port_ = port;
        if (ctx_.tcp.pending.contains(port)) {
            throw std::runtime_error("Already bound");
        }
        ctx_.tcp.pending.emplace(port, std::deque<Quad>{});
    }

    void listen(int backlog)
    {
        // TODO: set max capacity
    }

    Socket accept()
    {
        std::unique_lock accept_lock{ctx_.mx};
        std::println("Locked mutex in accept");
        ctx_.tcp.accept_var_.wait(accept_lock, [this]{ return ctx_.tcp.pending.contains(port_) && !ctx_.tcp.pending[port_].empty(); });
        std::println("AFTER WAIT");
        assert(ctx_.tcp.pending.contains(port_));
        auto iter = ctx_.tcp.pending.find(port_);
        assert(!iter->second.empty());
        auto quad = iter->second.front();
        iter->second.pop_front();
        Socket ret{quad, ctx_};
        return ret;
    }
};

void run_underlying_stuff(Context &ctx)
{
    {
        std::unique_lock lock{ ctx.mx };
        ctx.tun.set_addr("10.0.0.1");
        ctx.tun.set_mask("255.255.255.0");
        ctx.tun.set_flags(IFF_UP | IFF_RUNNING);
    }
    std::jthread tcp_thread{ [&ctx] {
            while (true) { // NOLINT
                std::unique_lock lock{ ctx.mx };
                ctx.tcp.process_packet(ctx.tun);
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Let other threads lock the mutex
            }
        }
    };
    tcp_thread.detach();
}

int main()
{

    Context ctx{"tun1"};
    run_underlying_stuff(ctx);

    // Now it's userspace things
    Listener listener{ ctx };
    listener.bind(8090);
    listener.listen(999);
    std::println("user: bound and listening");
    auto sock = listener.accept();
    std::println("user: accepted");
    while (true) {
        std::array<char, 512> buf{};
        auto rd = sock.read(buf.data(), buf.size());
        if (rd == 0) {
            std::println("user: DATA FINISHED, CLOSIGN...");
            break;
        } else {
            std::println("Oof");
        }
    }

    sleep(5);
    return 0;
}