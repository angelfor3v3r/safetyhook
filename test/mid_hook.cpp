#include <boost/ut.hpp>
#include <safetyhook.hpp>

using namespace boost::ut;

static suite<"mid hook"> mid_hook_tests = [] {
    "Mid hook to change a register"_test = [] {
        struct Target {
            __declspec(noinline) static int __fastcall add_42(int a) { return a + 42; }
        };

        expect(Target::add_42(0) == 42_i);

        static SafetyHookMid hook;

        struct Hook {
            static void add_42(SafetyHookContext& ctx) {
#if SAFETYHOOK_ARCH_X86_64
                ctx.rcx = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
                ctx.ecx = 1337 - 42;
#endif
            }
        };

        auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

        expect(hook_result.has_value());

        hook = std::move(*hook_result);

        expect(Target::add_42(1) == 1337_i);

        hook.reset();

        expect(Target::add_42(2) == 44_i);
    };

#if SAFETYHOOK_ARCH_X86_64
    "Mid hook to change an XMM register"_test = [] {
        struct Target {
            __declspec(noinline) static float __fastcall add_42(float a) { return a + 0.42f; }
        };

        expect(Target::add_42(0.0f) == 0.42_f);

        static SafetyHookMid hook;

        struct Hook {
            static void add_42(SafetyHookContext& ctx) { ctx.xmm0.f32[0] = 1337.0f - 0.42f; }
        };

        auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

        expect(hook_result.has_value());

        hook = std::move(*hook_result);

        expect(Target::add_42(1.0f) == 1337.0_f);

        hook.reset();

        expect(Target::add_42(2.0f) == 2.42_f);
    };
#endif
};