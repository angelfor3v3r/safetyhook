#include <print>
#include <thread>

#include <safetyhook.hpp>

SafetyHookInline g_hook{};

SAFETYHOOK_NOINLINE void SayHello(int times) {
    std::println("Hello #{}", times);
}

void Hooked_SayHello([[maybe_unused]] int times) {
    g_hook.call<void, int>(1337);
}

void SayHelloInfinitely() {
    int count{};

    while (true) {
        SayHello(count++);
    }
}

int main() {
    // Starting a thread for SayHello
    std::thread t(SayHelloInfinitely);
    t.detach();

    g_hook = safetyhook::create_inline(SayHello, Hooked_SayHello);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    g_hook = {};

    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}