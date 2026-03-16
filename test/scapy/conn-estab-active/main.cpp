// ...

int main() {
    sleep(3); // Wait for py test thing to start
    TcpSocket sock{};
    sock.connect("10.0.0.1", 8090);

    while (true) {
        std::array<char, 512> buf{};
        auto rd = sock.read(buf.data(), buf.size());
        std::println("user: rd {}", rd);
        if (rd == 0) {
            std::println("user: FIN");
            break;
        }
    }
}
