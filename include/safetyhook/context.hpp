/// @file safetyhook/context.hpp
/// @brief Context structure for MidHook.

#pragma once

#ifndef SAFETYHOOK_USE_CXXMODULES
#include <cstddef>
#include <cstdint>
#else
import std.compat;
#endif

#include "safetyhook/common.hpp"

namespace safetyhook {
union Xmm {
    uint8_t u8[16];
    uint16_t u16[8];
    uint32_t u32[4];
    uint64_t u64[2];
    float f32[4];
    double f64[2];
};

#if SAFETYHOOK_ARCH_X86_32

class FpuF32;
class FpuF64;

#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
class FpuF80;
#endif

/// @brief 80-bit x87 extended-precision register (ST(n) slot from FNSAVE/FRSTOR).
/// @note Bit 63 (explicit integer) makes direct reinterpretation as double unsafe;
///       use as_f*/set_f*/f*() or the lossless f80() path (__LDBL_MANT_DIG__ == 64 only).
struct Fpu {
    uint8_t raw[10]{};

    [[nodiscard]] float as_f32() const noexcept;  ///< Read as float (via FPU fld/fstp).
    [[nodiscard]] double as_f64() const noexcept; ///< Read as double (via FPU fld/fstp).

    void set_f32(float value) noexcept;  ///< Write from float (via FPU fld/fstp).
    void set_f64(double value) noexcept; ///< Write from double (via FPU fld/fstp).

#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
    [[nodiscard]] long double as_f80() const noexcept; ///< Read as long double (lossless memcpy).

    void set_f80(long double value) noexcept; ///< Write from long double (lossless memcpy).

    [[nodiscard]] FpuF80 f80() noexcept; ///< Mutable long double proxy.
#endif

    [[nodiscard]] FpuF32 f32() noexcept; ///< Mutable float proxy.
    [[nodiscard]] FpuF64 f64() noexcept; ///< Mutable double proxy.
};

/// @brief Mutable float proxy over an Fpu slot.
/// @details Assignment and compound-assignment read-modify-write the slot in place;
///         implicit conversion reads it. Each op touches one slot only, never fpu_env
///         or neighboring slots.
/// @note Modeled on std::atomic_ref<float>: member compound-assignment + implicit
///       conversion. No free binary operators -- a prvalue proxy would dangle (it
///       must alias a concrete slot). Arithmetic via implicit conversion instead.
class FpuF32 {
    Fpu* m{};

public:
    explicit FpuF32(Fpu* m) noexcept : m{m} {}

    [[nodiscard]] operator float() const noexcept { return m->as_f32(); }

    FpuF32& operator=(float value) noexcept {
        m->set_f32(value);
        return *this;
    }

    FpuF32& operator+=(float value) noexcept {
        m->set_f32(m->as_f32() + value);
        return *this;
    }

    FpuF32& operator-=(float value) noexcept {
        m->set_f32(m->as_f32() - value);
        return *this;
    }

    FpuF32& operator*=(float value) noexcept {
        m->set_f32(m->as_f32() * value);
        return *this;
    }

    FpuF32& operator/=(float value) noexcept {
        m->set_f32(m->as_f32() / value);
        return *this;
    }
};

/// @brief Mutable double proxy over an Fpu slot.
/// @copydetails FpuF32
class FpuF64 {
    Fpu* m{};

public:
    explicit FpuF64(Fpu* m) noexcept : m{m} {}

    [[nodiscard]] operator double() const noexcept { return m->as_f64(); }

    FpuF64& operator=(double value) noexcept {
        m->set_f64(value);
        return *this;
    }

    FpuF64& operator+=(double value) noexcept {
        m->set_f64(m->as_f64() + value);
        return *this;
    }

    FpuF64& operator-=(double value) noexcept {
        m->set_f64(m->as_f64() - value);
        return *this;
    }

    FpuF64& operator*=(double value) noexcept {
        m->set_f64(m->as_f64() * value);
        return *this;
    }

    FpuF64& operator/=(double value) noexcept {
        m->set_f64(m->as_f64() / value);
        return *this;
    }
};

#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
/// @brief Mutable long double proxy over an Fpu slot (lossless 10-byte memcpy).
/// @details GCC/Clang only (__LDBL_MANT_DIG__ == 64): direct 10-byte memcpys, no FPU roundtrip.
/// @copydetails FpuF32
class FpuF80 {
    Fpu* m{};

public:
    explicit FpuF80(Fpu* m) noexcept : m{m} {}

    [[nodiscard]] operator long double() const noexcept { return m->as_f80(); }

    FpuF80& operator=(long double value) noexcept {
        m->set_f80(value);
        return *this;
    }

    FpuF80& operator+=(long double value) noexcept {
        m->set_f80(m->as_f80() + value);
        return *this;
    }

    FpuF80& operator-=(long double value) noexcept {
        m->set_f80(m->as_f80() - value);
        return *this;
    }

    FpuF80& operator*=(long double value) noexcept {
        m->set_f80(m->as_f80() * value);
        return *this;
    }

    FpuF80& operator/=(long double value) noexcept {
        m->set_f80(m->as_f80() / value);
        return *this;
    }
};
#endif

inline FpuF32 Fpu::f32() noexcept {
    return FpuF32{this};
}

inline FpuF64 Fpu::f64() noexcept {
    return FpuF64{this};
}

#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
inline FpuF80 Fpu::f80() noexcept {
    return FpuF80{this};
}
#endif

/// @brief 28-byte x87 operating environment saved by FNSAVE (32-bit protected mode, Intel SDM Vol. 1, 8.1.10).
/// @details FRSTOR replays it on return. st_push_f*() and st_pop*() keep TOP and the tag word in step with the slots
///          they move, like fld / fstp st(0) would.
#pragma pack(push, 1)
struct FpuEnv {
    uint16_t fcw;       ///< Control word (rounding, precision, exception masks).
    uint16_t reserved0; ///< Reserved.
    uint16_t fsw;       ///< Status word (TOP in bits 11..13, condition codes, exception flags).
    uint16_t reserved1; ///< Reserved.
    uint16_t ftw;       ///< Tag word: 2 bits per physical register (00 valid, 01 zero, 10 special, 11 empty).
    uint16_t reserved2; ///< Reserved.
    uint32_t fip;       ///< Last x87 instruction pointer offset.
    uint16_t fcs;       ///< Last x87 instruction CS selector.
    uint16_t fop;       ///< Last x87 opcode (low 11 bits).
    uint32_t fdp;       ///< Last x87 operand pointer offset.
    uint16_t fds;       ///< Last x87 operand DS selector.
    uint16_t reserved3; ///< Reserved.

    /// @return Physical register index of ST(0), 0..7.
    [[nodiscard]] uint8_t top() const noexcept { return (fsw >> 11) & 7; }

    /// @return Tag (0 valid, 1 zero, 2 special, 3 empty) of physical register `index` (0..7).
    [[nodiscard]] uint8_t tag(uint8_t index) const noexcept { return (ftw >> ((index & 7) * 2)) & 3; }
};
#pragma pack(pop)

#endif

/// @brief Context structure for 64-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 64-bit registers at the moment the hook is called.
/// @note rip will point to a trampoline containing the replaced instruction(s).
/// @note rsp is read-only. Modifying it will have no effect. Use trampoline_rsp to modify rsp if needed but make sure
/// the top of the stack is the rip you want to resume at.
struct Context64 {
    Xmm xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
    uintptr_t rflags, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax, rbp, rsp, trampoline_rsp, rip;
};

/// @brief Context structure for 32-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 32-bit registers at the moment the hook is called.
/// @note eip will point to a trampoline containing the replaced instruction(s).
/// @note esp is read-only. Modifying it will have no effect. Use trampoline_esp to modify esp if needed but make sure
/// the top of the stack is the eip you want to resume at.
/// @note x87 state: FNSAVE captures fpu_env + st0..st7 (108 bytes, st0 = ST(0));
///       stmxcsr saves mxcsr. FRSTOR/ldmxcsr replay them verbatim on return, so writes
///       to st0..st7 or mxcsr take effect. FNSAVE also resets the live FPU to FINIT
///       defaults -- callback math runs there, not in the program's env; the program's
///       captured env is restored on return. Proxy ops touch only one slot's 10 bytes.
struct Context32 {
#if SAFETYHOOK_ARCH_X86_32
    FpuEnv fpu_env;                             ///< x87 operating environment (28 bytes).
    Fpu st0, st1, st2, st3, st4, st5, st6, st7; ///< x87 ST(0)..ST(7), logical stack order (80 bytes).
    uint32_t mxcsr;                             ///< SSE control/status (saved via stmxcsr).
#endif

    Xmm xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
    uintptr_t eflags, edi, esi, edx, ecx, ebx, eax, ebp, esp, trampoline_esp, eip;

#if SAFETYHOOK_ARCH_X86_32
    /// @brief Pop ST(0), like `fstp st(0)`: st1..st7 move down to st0..st6, ST(0)'s register is tagged empty and
    /// TOP is incremented.
    /// @note Popping an empty stack is a stack underflow, as on the FPU: IE and SF are set and C1 cleared; when the
    /// invalid-operation exception is unmasked, the stack is left unchanged and the exception is raised on the next
    /// x87 instruction of the hooked code.
    void st_pop() noexcept;

    /// @brief Pop ST(0) and return it as a float, like `fstp dword`.
    /// @return The popped value, or the x87 indefinite (NaN) when the stack was empty.
    [[nodiscard]] float st_pop_f32() noexcept;

    /// @brief Pop ST(0) and return it as a double, like `fstp qword`.
    /// @return The popped value, or the x87 indefinite (NaN) when the stack was empty.
    [[nodiscard]] double st_pop_f64() noexcept;

    /// @brief Push `value` as the new ST(0), like `fld dword`: st0..st6 move up to st1..st7, TOP is decremented and
    /// the new register is tagged from its value.
    /// @note Pushing onto a full stack is a stack overflow, as on the FPU: IE, SF and C1 are set and, when the
    /// invalid-operation exception is masked, the indefinite (NaN) is pushed instead; when it is unmasked, the stack is
    /// left unchanged and the exception is raised on the next x87 instruction of the hooked code.
    /// @param value The value to load as the new ST(0).
    void st_push_f32(float value) noexcept;

    /// @brief Push `value` as the new ST(0), like `fld qword`. See st_push_f32().
    /// @param value The value to load as the new ST(0).
    void st_push_f64(double value) noexcept;

private:
    void st_push(const Fpu& value) noexcept;
    [[nodiscard]] Fpu st_pop_value() noexcept;
#endif
};

/// @brief Context structure for MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the registers at the moment the hook is called.
/// @note The structure is different depending on architecture.
/// @note The structure exposes integer, SSE (XMM), and (on x86-32) x87 FPU + MXCSR state.
#if SAFETYHOOK_ARCH_X86_64
using Context = Context64;
#elif SAFETYHOOK_ARCH_X86_32
using Context = Context32;

static_assert(sizeof(FpuEnv) == 28, "FpuEnv must match the 28-byte FNSAVE environment image");
static_assert(offsetof(FpuEnv, fsw) == 4, "FNSAVE: FSW at +4");
static_assert(offsetof(FpuEnv, ftw) == 8, "FNSAVE: FTW at +8");
static_assert(offsetof(FpuEnv, fip) == 12, "FNSAVE: FIP at +12");
static_assert(offsetof(FpuEnv, fdp) == 20, "FNSAVE: FDP at +20");
static_assert(sizeof(Fpu) == 10, "Fpu must match the 10-byte x87 register slot");

// Context32 layout is consumed by the hand-written x87 trampoline in
// src/mid_hook.x86_32.asm; pin the offsets the asm encodes to catch layout drift.
static_assert(offsetof(Context32, fpu_env) == 0, "asm: fnsave [esp]");
static_assert(offsetof(Context32, st0) == 28, "asm: ST(0) follows 28-byte env");
static_assert(offsetof(Context32, st7) == 98, "asm: ST(7) = ST(0) + 7*10");
static_assert(offsetof(Context32, mxcsr) == 108, "asm: stmxcsr [esp+0x6C]");
static_assert(offsetof(Context32, xmm0) == 112, "asm: fxsave-style XMM block");
static_assert(offsetof(Context32, eflags) == 240, "asm: GP regs base");
static_assert(offsetof(Context32, eip) == 280, "asm: resume rip");

// GCC i386 SysV sees 284; MSVC pads the tail to 288 for Xmm alignment.
// Harmless: the asm uses literal offsets + movdqu and allocates its own frame.
static_assert(sizeof(Context32) == 284 || sizeof(Context32) == 288, "asm: total context frame size");
#endif
} // namespace safetyhook