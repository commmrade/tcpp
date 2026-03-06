#include <print>
#include <spdlog/spdlog.h>


void foo()
{
    spdlog::info("cock");
    throw std::logic_error("something");
}

int main()
{
    int val = 0;
    ++val;
    spdlog::info("val: {}", val);
    foo();
    return 0;
}