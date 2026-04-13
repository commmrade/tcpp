//
// Created by klewy on 4/13/26.
//

#ifndef TCPP_CLOCK_HPP
#define TCPP_CLOCK_HPP
#include <cstdint>
#include <chrono>

class ClockInterface
{
public:
    virtual ~ClockInterface() = default;
    virtual std::int64_t now() = 0;
};

class Clock : public ClockInterface
{
    std::int64_t now() override
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};

#endif //TCPP_CLOCK_HPP