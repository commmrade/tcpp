// ...

int main() {
    sleep(3);
    TcpSocket sock{};
    sock.connect("10.0.0.1", 8090);

    while (true) {
        std::array<char, 512> buf{};

        auto wr = sock.write("exit", 4);
        std::println("user: written exit");

        auto rd = sock.read(buf.data(), buf.size());
        std::println("user: rd {}", rd);
        if (rd == 0) {
            std::println("user: FIN");
            break;
        }
    }
}
