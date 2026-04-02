// ...

int main() {
    sleep(3); // Wait for py test thing to start
    TcpSocket sock{};
    sock.connect("10.0.0.1", 8090);

    while (true) {
        std::array<char, 100> buf{};
        std::memset(buf.data(), 'c', buf.size());
        auto wr = sock.write(buf.data(), buf.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
