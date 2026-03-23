// ...

int main() {
    TcpListener listener{};
    listener.bind(8090);
    listener.listen(999);
    std::println("user: bound and listening");
    auto sock = listener.accept();
    std::println("user: accepted");
    while (true) {
        std::array<char, 512> buf{};
        auto rd = sock.read(buf.data(), buf.size());
        if (rd == 0) {
            std::println("user: DATA FINISHED, CLOSING...");
            break;
        }
    }
}
