// ...
//
int main() {
    TcpListener listener{};
    listener.bind(8090);
    listener.listen(999);
    std::println("user: bound and listening");
    auto sock = listener.accept();
    std::println("user: accepted");
    sock.shutdown(ShutdownType::WRITE);
}
