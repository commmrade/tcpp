// ...

int main() {
    TcpListener listener{};
    listener.bind(8090);
    listener.listen(999);
    auto sock = listener.accept();
    while (true) {
        std::array<char, 512> buf{};
        sleep(10);
        auto rd = sock.read(buf.data(), buf.size());
    }

    return 0;
}
