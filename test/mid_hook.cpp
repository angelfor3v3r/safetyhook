#include <cmath>
#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>
#include <safetyhook.hpp>

#if SAFETYHOOK_ARCH_X86_32
#include <xbyak/xbyak.h>

using namespace Xbyak::util;
#endif

TEST(MidHook, MidHookToChangeARegister) {
    struct Target {
        SAFETYHOOK_NOINLINE static int SAFETYHOOK_FASTCALL add_42(int a) { return a + 42; }
    };

    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    auto volatile add_42 = Target::add_42;

    EXPECT_EQ(add_42(0), 42);

    SafetyHookMid hook{};

    struct Hook {
        static void add_42(SafetyHookContext& ctx) {
#if SAFETYHOOK_OS_WINDOWS
#if SAFETYHOOK_ARCH_X86_64
            ctx.rcx = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
            ctx.ecx = 1337 - 42;
#endif
#elif SAFETYHOOK_OS_LINUX
#if SAFETYHOOK_ARCH_X86_64
            ctx.rdi = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
            *reinterpret_cast<int*>(ctx.esp + 4) = 1337 - 42;
#endif
#endif
        }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_EQ(add_42(1), 1337);

    hook.reset();

    EXPECT_EQ(add_42(2), 44);
}

#if SAFETYHOOK_ARCH_X86_64
TEST(MidHook, MidHookToChangeAnXMMRegister) {
    struct Target {
        SAFETYHOOK_NOINLINE static float SAFETYHOOK_FASTCALL add_42(float a) { return a + 0.42f; }
    };

    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    auto volatile add_42 = Target::add_42;

    EXPECT_FLOAT_EQ(add_42(0.0f), 0.42f);

    SafetyHookMid hook{};

    struct Hook {
        static void add_42(SafetyHookContext& ctx) { ctx.xmm0.f32[0] = 1337.0f - 0.42f; }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_FLOAT_EQ(add_42(1.0f), 1337.0f);

    hook.reset();

    EXPECT_FLOAT_EQ(add_42(2.0f), 2.42f);
}
#endif

TEST(MidHook, MidHookEnableAndDisable) {
    struct Target {
        SAFETYHOOK_NOINLINE static int SAFETYHOOK_FASTCALL add_42(int a) {
            volatile int b = a;
            return b + 42;
        }
    };

    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    auto volatile add_42 = Target::add_42;

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);

    SafetyHookMid hook{};

    struct Hook {
        static void add_42(SafetyHookContext& ctx) {
#if SAFETYHOOK_OS_WINDOWS
#if SAFETYHOOK_ARCH_X86_64
            ctx.rcx = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
            ctx.ecx = 1337 - 42;
#endif
#elif SAFETYHOOK_OS_LINUX
#if SAFETYHOOK_ARCH_X86_64
            ctx.rdi = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
            *reinterpret_cast<int*>(ctx.esp + 4) = 1337 - 42;
#endif
#endif
        }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42, SafetyHookMid::StartDisabled);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);

    ASSERT_TRUE(hook.enable().has_value());

    EXPECT_EQ(add_42(1), 1337);
    EXPECT_EQ(add_42(2), 1337);
    EXPECT_EQ(add_42(3), 1337);

    ASSERT_TRUE(hook.disable().has_value());

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);

    hook.reset();

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);
}

#if SAFETYHOOK_ARCH_X86_32

namespace st_test {
constexpr float INPUT[8] = {128.0f, 64.0f, 32.0f, 16.0f, 8.0f, 4.0f, 2.0f, 1.0f};
constexpr float OUTPUT[8] = {0.0f, 10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f};
} // namespace st_test

// Round-trip every ST register: read+write ST0..ST7, verify via fstp the modified values are what FRSTOR reinstated.
TEST(MidHookX87, ReadAndWriteAllStRegisters) {
    Xbyak::CodeGenerator cg{};

    cg.fninit();

    for (int i = 7; i >= 0; --i) {
        cg.fld(dword[reinterpret_cast<uintptr_t>(&st_test::INPUT[i])]);
    }

    auto nop_offset = cg.getSize();

    cg.nop(5);
    cg.mov(eax, dword[esp + 4]);

    for (int i = 0; i < 8; ++i) {
        cg.fstp(dword[eax + i * 4]);
    }

    cg.ret();

    using Fn = void(SAFETYHOOK_CCALL*)(float*);

    auto volatile target = cg.getCode<Fn>();

    float out[8]{};
    target(out);

    for (int i = 0; i < 8; ++i) {
        EXPECT_FLOAT_EQ(out[i], st_test::INPUT[i]);
    }

    SafetyHookMid hook{};

    struct Hook {
        static void cb(SafetyHookContext& ctx) {
            safetyhook::Fpu* st[8] = {&ctx.st0, &ctx.st1, &ctx.st2, &ctx.st3, &ctx.st4, &ctx.st5, &ctx.st6, &ctx.st7};

            for (int i = 0; i < 8; ++i) {
                EXPECT_FLOAT_EQ(st[i]->as_f32(), st_test::INPUT[i]);
                EXPECT_NEAR(st[i]->as_f64(), static_cast<double>(st_test::INPUT[i]), 1e-6);
            }

            for (int i = 0; i < 8; ++i) {
                st[i]->set_f32(st_test::OUTPUT[i]);
            }

            for (int i = 0; i < 8; ++i) {
                EXPECT_FLOAT_EQ(st[i]->as_f32(), st_test::OUTPUT[i]);
            }
        }
    };

    auto hr = SafetyHookMid::create(reinterpret_cast<void*>(const_cast<uint8_t*>(cg.getCode() + nop_offset)), Hook::cb);

    ASSERT_TRUE(hr.has_value());

    hook = std::move(*hr);

    for (auto&& v : out) {
        v = 0.0f;
    }

    target(out);

    for (int i = 0; i < 8; ++i) {
        EXPECT_FLOAT_EQ(out[i], st_test::OUTPUT[i]);
    }

    hook.reset();

    for (auto&& v : out) {
        v = 0.0f;
    }

    target(out);

    for (int i = 0; i < 8; ++i) {
        EXPECT_FLOAT_EQ(out[i], st_test::INPUT[i]);
    }
}

// MXCSR rounding-mode read/write: load RC=3 (truncate) so cvtss2si(3.5f)=3; the callback flips RC to 0 (nearest) so
// cvtss2si(3.5f)=4.
TEST(MidHookX87, ReadAndWriteMxcsr) {
    Xbyak::CodeGenerator cg{};

    cg.push(0x1F80u | (3u << 13));
    cg.ldmxcsr(dword[esp]);
    cg.pop(eax);

    auto nop_offset = cg.getSize();

    cg.nop(5);
    cg.cvtss2si(eax, dword[esp + 4]);
    cg.ret();

    auto volatile target = cg.getCode<int(SAFETYHOOK_CCALL*)(float)>();

    EXPECT_EQ(target(3.5f), 3);

    SafetyHookMid hook{};

    struct Hook {
        static void cb(SafetyHookContext& ctx) {
            EXPECT_EQ((ctx.mxcsr >> 13) & 3, 3u);

            ctx.mxcsr &= ~(3u << 13);
        }
    };

    auto hr = SafetyHookMid::create(reinterpret_cast<void*>(const_cast<uint8_t*>(cg.getCode() + nop_offset)), Hook::cb);

    ASSERT_TRUE(hr.has_value());

    hook = std::move(*hr);

    EXPECT_EQ(target(3.5f), 4);

    hook.reset();

    EXPECT_EQ(target(3.5f), 3);
}

// st_pop / st_push_f* let the callback mutate the logical x87 stack the original instruction will operate on. Two 1.0s
// pushed; the callback pops the top (old ST1 is now ST0), pushes 42, and the original fstp delivers 42 to *out.
TEST(MidHookX87, StPopAndPushHookMutatesLiveStack) {
    Xbyak::CodeGenerator cg{};

    cg.fninit();
    cg.fld1();
    cg.fld1();

    auto nop_offset = cg.getSize();

    cg.nop(5);
    cg.mov(eax, dword[esp + 8]);
    cg.fstp(dword[eax]);
    cg.ret();

    auto volatile target = cg.getCode<void(SAFETYHOOK_CCALL*)(float, float*)>();

    float out{};
    target(0.0f, &out);

    EXPECT_FLOAT_EQ(out, 1.0f);

    SafetyHookMid hook{};

    struct Hook {
        static void cb(SafetyHookContext& ctx) {
            EXPECT_FLOAT_EQ(ctx.st0.as_f32(), 1.0f);
            EXPECT_FLOAT_EQ(ctx.st1.as_f32(), 1.0f);

            ctx.st_pop();

            EXPECT_FLOAT_EQ(ctx.st0.as_f32(), 1.0f);

            ctx.st_push_f32(42.0f);

            EXPECT_FLOAT_EQ(ctx.st0.as_f32(), 42.0f);
            EXPECT_FLOAT_EQ(ctx.st1.as_f32(), 1.0f);
        }
    };

    auto hr = SafetyHookMid::create(reinterpret_cast<void*>(const_cast<uint8_t*>(cg.getCode() + nop_offset)), Hook::cb);

    ASSERT_TRUE(hr.has_value());

    hook = std::move(*hr);

    out = 0.0f;
    target(0.0f, &out);

    EXPECT_FLOAT_EQ(out, 42.0f);

    hook.reset();

    out = 0.0f;
    target(0.0f, &out);

    EXPECT_FLOAT_EQ(out, 1.0f);
}

TEST(MidHookX87, StProxyArithmeticOps) {
    Xbyak::CodeGenerator cg{};

    cg.fninit();
    cg.fld1(); // ST0 = 1.0

    auto nop_offset = cg.getSize();

    cg.nop(5);
    cg.mov(eax, dword[esp + 4]);
    cg.fstp(dword[eax]);
    cg.ret();

    auto volatile target = cg.getCode<void(SAFETYHOOK_CCALL*)(float*)>();

    float out{};
    target(&out);

    EXPECT_FLOAT_EQ(out, 1.0f);

    SafetyHookMid hook{};

    struct Hook {
        static void cb(SafetyHookContext& ctx) {
            constexpr auto ratio = 16.0f / 9.0f;

            // `ctx.st0.f32() *= ratio;` -- read-modify-write via the FpuF32 proxy.
            ctx.st0.f32() *= ratio;

            EXPECT_FLOAT_EQ(ctx.st0.f32(), ratio);

            // `ctx.st0.f32() = ctx.st0.f32() / ratio;` -- recovers 1.0f.
            ctx.st0.f32() = ctx.st0.f32() / ratio;

            EXPECT_FLOAT_EQ(ctx.st0.f32(), 1.0f);

            // Assign and add via the proxy.
            ctx.st0.f32() = 10.0f;
            ctx.st0.f32() += 5.0f;
            ctx.st0.f32() -= 2.0f;

            EXPECT_FLOAT_EQ(ctx.st0.f32(), 13.0f);
        }
    };

    auto hr = SafetyHookMid::create(reinterpret_cast<void*>(const_cast<uint8_t*>(cg.getCode() + nop_offset)), Hook::cb);

    ASSERT_TRUE(hr.has_value());

    hook = std::move(*hr);

    out = 0.0f;
    target(&out);

    EXPECT_FLOAT_EQ(out, 13.0f);

    hook.reset();

    out = 0.0f;
    target(&out);

    EXPECT_FLOAT_EQ(out, 1.0f);
}

// The callback's view of the FNSAVE environment matches what the FPU saved: fninit control word, TOP after two pushes
// and the tag of every physical register.
TEST(MidHookX87, FpuEnvMatchesFnsaveLayout) {
    Xbyak::CodeGenerator cg{};

    cg.fninit();
    cg.fld1();
    cg.fldz();

    auto nop_offset = cg.getSize();

    cg.nop(5);
    cg.fninit();
    cg.ret();

    auto volatile target = cg.getCode<void(SAFETYHOOK_CCALL*)()>();

    SafetyHookMid hook{};

    struct Hook {
        static void cb(SafetyHookContext& ctx) {
            EXPECT_EQ(ctx.fpu_env.fcw, 0x037F);
            EXPECT_EQ(ctx.fpu_env.top(), 6);
            EXPECT_EQ(ctx.fpu_env.tag(6), 1); // ST(0) = 0.0: zero
            EXPECT_EQ(ctx.fpu_env.tag(7), 0); // ST(1) = 1.0: valid

            for (uint8_t i = 0; i < 6; ++i) {
                EXPECT_EQ(ctx.fpu_env.tag(i), 3); // empty
            }
        }
    };

    auto hr = SafetyHookMid::create(reinterpret_cast<void*>(const_cast<uint8_t*>(cg.getCode() + nop_offset)), Hook::cb);

    ASSERT_TRUE(hr.has_value());

    hook = std::move(*hr);

    target();
}

namespace x87_diff {
constexpr float ONE = 1.0f;
constexpr float TWO = 2.0f;
constexpr float FOUR = 4.0f;

// TOP, C1, IE, SF, ES and B: what fld / fstp define. C0, C2, C3 are undefined after them.
constexpr uint16_t FSW_MASK = 0x3800 | 0x0200 | 0x0001 | 0x0040 | 0x0080 | 0x8000;

struct Result {
    float out;
    safetyhook::FpuEnv env;
};

using Emit = void (*)(Xbyak::CodeGenerator&);
using Callback = void (*)(SafetyHookContext&);

// Runs `prologue; site; epilogue` and returns the stored float and the environment the FPU reports after it. With a
// callback, the site is a mid hook on a nop instead of the real instruction(s).
Result run(Emit prologue, Emit site, Emit epilogue, Callback callback) {
    Xbyak::CodeGenerator cg{};

    cg.mov(eax, dword[esp + 4]);
    cg.fninit();
    prologue(cg);

    auto site_offset = cg.getSize();

    if (callback != nullptr) {
        cg.nop(5);
    } else {
        site(cg);
    }

    epilogue(cg);
    cg.mov(ecx, dword[esp + 8]);
    cg.fnstenv(ptr[ecx]);
    cg.fninit();
    cg.ret();

    SafetyHookMid hook{};

    if (callback != nullptr) {
        auto hr =
            SafetyHookMid::create(reinterpret_cast<void*>(const_cast<uint8_t*>(cg.getCode() + site_offset)), callback);

        EXPECT_TRUE(hr.has_value());

        if (hr) {
            hook = std::move(*hr);
        }
    }

    auto volatile target = cg.getCode<void(SAFETYHOOK_CCALL*)(float*, safetyhook::FpuEnv*)>();

    Result result{};
    target(&result.out, &result.env);

    return result;
}

void expect_same(const Result& fpu, const Result& hooked) {
    EXPECT_EQ(fpu.env.fsw & FSW_MASK, hooked.env.fsw & FSW_MASK);
    EXPECT_EQ(fpu.env.ftw, hooked.env.ftw);
    EXPECT_EQ(std::memcmp(&fpu.out, &hooked.out, sizeof(float)), 0) << fpu.out << " vs " << hooked.out;
}

void none(Xbyak::CodeGenerator&) {
}
} // namespace x87_diff

// A mid hook replacing `fld` on an empty stack (cursey/safetyhook#130, Deer Avenger 4): the following fdiv must see
// the pushed value, not an empty register.
TEST(MidHookX87, StPushOntoEmptyStackActsLikeFld) {
    using namespace x87_diff;

    auto site = [](Xbyak::CodeGenerator& cg) { cg.fld(dword[reinterpret_cast<uintptr_t>(&ONE)]); };
    auto epilogue = [](Xbyak::CodeGenerator& cg) {
        cg.fdiv(dword[reinterpret_cast<uintptr_t>(&FOUR)]);
        cg.fstp(dword[eax]);
    };

    auto fpu = run(none, site, epilogue, nullptr);
    auto hooked = run(none, site, epilogue, [](SafetyHookContext& ctx) { ctx.st_push_f32(1.0f); });

    EXPECT_FLOAT_EQ(fpu.out, 0.25f);
    expect_same(fpu, hooked);
}

namespace x87_diff {
float popped{};
} // namespace x87_diff

TEST(MidHookX87, StPopF32ActsLikeFstp) {
    using namespace x87_diff;

    auto prologue = [](Xbyak::CodeGenerator& cg) {
        cg.fld1();
        cg.fld(dword[reinterpret_cast<uintptr_t>(&TWO)]);
    };
    auto site = [](Xbyak::CodeGenerator& cg) { cg.fstp(dword[reinterpret_cast<uintptr_t>(&popped)]); };
    auto epilogue = [](Xbyak::CodeGenerator& cg) { cg.fstp(dword[eax]); };

    popped = 0.0f;
    auto fpu = run(prologue, site, epilogue, nullptr);
    EXPECT_FLOAT_EQ(popped, 2.0f);

    popped = 0.0f;
    auto hooked = run(prologue, site, epilogue, [](SafetyHookContext& ctx) { popped = ctx.st_pop_f32(); });
    EXPECT_FLOAT_EQ(popped, 2.0f);

    EXPECT_FLOAT_EQ(fpu.out, 1.0f);
    expect_same(fpu, hooked);
}

TEST(MidHookX87, StPopOnEmptyStackUnderflowsLikeFstp) {
    using namespace x87_diff;

    auto site = [](Xbyak::CodeGenerator& cg) { cg.fstp(st0); };

    auto fpu = run(none, site, none, nullptr);
    auto hooked = run(none, site, none, [](SafetyHookContext& ctx) { ctx.st_pop(); });

    EXPECT_NE(fpu.env.fsw & 0x0041, 0); // IE and SF
    expect_same(fpu, hooked);
}

TEST(MidHookX87, StPushOntoFullStackOverflowsLikeFld) {
    using namespace x87_diff;

    auto prologue = [](Xbyak::CodeGenerator& cg) {
        for (int i = 0; i < 8; ++i) {
            cg.fld1();
        }
    };
    auto site = [](Xbyak::CodeGenerator& cg) { cg.fld(dword[reinterpret_cast<uintptr_t>(&TWO)]); };
    auto epilogue = [](Xbyak::CodeGenerator& cg) { cg.fst(dword[eax]); };

    auto fpu = run(prologue, site, epilogue, nullptr);
    auto hooked = run(prologue, site, epilogue, [](SafetyHookContext& ctx) { ctx.st_push_f32(2.0f); });

    EXPECT_TRUE(std::isnan(fpu.out)); // masked stack overflow loads the indefinite
    expect_same(fpu, hooked);
}

#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
namespace f80_test {
// 1e-30L has a mantissa distinct from its double-rounded form, so as_f64() would lose precision, but as_f80() must
// recover it bit-for-bit.
constexpr long double PROBE = 1e-30L;
constexpr long double REPLACEMENT = 3.141592653589793238L;
} // namespace f80_test

// Verify the f80 path is lossless: push PROBE, read it back exactly (which as_f64 cannot do), then mutate via the proxy
// and observe it via fstp tbyte.
TEST(MidHookX87, StF80LosslessRoundTrip) {
    Xbyak::CodeGenerator cg{};

    cg.fninit();
    cg.db(0xDB); // fld tbyte [disp32]: DB /5 with mod=00 rm=101. Xbyak has no tbyte frame.
    cg.db(0x2D);
    cg.dd(reinterpret_cast<uint32_t>(&f80_test::PROBE));

    auto nop_offset = cg.getSize();

    cg.nop(5);
    cg.mov(eax, dword[esp + 4]);
    cg.db(0xDB); // fstp tbyte [eax]: DB /7 with mod=00 rm=000. No tbyte frame either.
    cg.db(0x38);
    cg.ret();

    auto volatile target = cg.getCode<void(SAFETYHOOK_CCALL*)(long double*)>();

    long double out{};
    target(&out);

    EXPECT_EQ(out, f80_test::PROBE);

    SafetyHookMid hook{};

    struct Hook {
        static void cb(SafetyHookContext& ctx) {
            // as_f64() would round here; as_f80() must be bit-exact.
            EXPECT_EQ(ctx.st0.as_f80(), f80_test::PROBE);

            ctx.st0.f80() = f80_test::REPLACEMENT;

            EXPECT_EQ(ctx.st0.as_f80(), f80_test::REPLACEMENT);

            // x87 +=/-= isn't bit-exact in general, so check against the recomputed value, not the original.
            ctx.st0.f80() += 1.0L;

            EXPECT_EQ(ctx.st0.as_f80(), f80_test::REPLACEMENT + 1.0L);
        }
    };

    auto hr = SafetyHookMid::create(reinterpret_cast<void*>(const_cast<uint8_t*>(cg.getCode() + nop_offset)), Hook::cb);

    ASSERT_TRUE(hr.has_value());

    hook = std::move(*hr);

    out = 0.0L;
    target(&out);

    EXPECT_EQ(out, f80_test::REPLACEMENT + 1.0L);

    hook.reset();

    out = 0.0L;
    target(&out);

    EXPECT_EQ(out, f80_test::PROBE);
}
#endif

#endif
