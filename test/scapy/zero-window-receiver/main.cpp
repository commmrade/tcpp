// ...

int main() {
    TcpListener listener{};
    listener.bind(8090);
    listener.listen(999);
    auto sock = listener.accept();
    while (true) {
        std::array<char, 512> buf{};
        auto rd = sock.read(buf.data(), buf.size());
        sleep(10);
    }

    return 0;
}
