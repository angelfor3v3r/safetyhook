#include "safetyhook/context.hpp"

#include <array>
#include <cstring>
#include <memory>
#include <mutex>

#include "safetyhook/os.hpp"

namespace safetyhook {

#if SAFETYHOOK_ARCH_X86_32

#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
// GCC/Clang: long double is 80-bit, bit-identical to Fpu::raw.
// Compiler emits fld/fstp tbyte; no stubs needed.

long double Fpu::as_f80() const noexcept {
    long double result{};
    std::memcpy(&result, raw, 10);

    return result;
}

void Fpu::set_f80(long double value) noexcept {
    std::memcpy(raw, &value, 10);
}

double Fpu::as_f64() const noexcept {
    return static_cast<double>(as_f80());
}

void Fpu::set_f64(double value) noexcept {
    set_f80(static_cast<long double>(value));
}

float Fpu::as_f32() const noexcept {
    return static_cast<float>(as_f64());
}

void Fpu::set_f32(float value) noexcept {
    set_f64(static_cast<double>(value));
}

#else

// MSVC: long double == double, so no f80. Two __cdecl stubs bounce through the FPU; f32 routes through f64.
// SAFETYHOOK_CCALL pins __cdecl so /Gz (stdcall) / /Gr (fastcall) can't mismatch the stubs' ABI.
using FpuToDoubleFn = void(SAFETYHOOK_CCALL*)(const Fpu* fpu, double& dest) noexcept;
using DoubleToFpuFn = void(SAFETYHOOK_CCALL*)(double value, Fpu* fpu) noexcept;

struct VmDeleter {
    void operator()(uint8_t* address) const noexcept {
        if (address != nullptr) {
            vm_free(address);
        }
    }
};

struct ConverterCode {
    FpuToDoubleFn fpu_to_double{};
    DoubleToFpuFn double_to_fpu{};
    std::unique_ptr<uint8_t, VmDeleter> memory{};
};

// First stub is 13 bytes (4 + 2 + 4 + 2 + 1). Named so code + FPU_TO_DOUBLE_LEN stays auditable.
constexpr size_t FPU_TO_DOUBLE_LEN = 13;

// __cdecl stubs (24 bytes total): fpu_to_double then double_to_fpu.
// clang-format off
constexpr std::array<uint8_t, 24> CONVERTER_CODE{{
    // fpu_to_double(const Fpu* fpu, double& dest)
    0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
    0xDB, 0x28,             // fld tbyte [eax]
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]
    0xDD, 0x18,             // fstp qword [eax]
    0xC3,                   // ret

    // double_to_fpu(double value, Fpu* fpu)
    0xDD, 0x44, 0x24, 0x04, // fld qword [esp+4]
    0x8B, 0x44, 0x24, 0x0C, // mov eax, [esp+12]
    0xDB, 0x38,             // fstp tbyte [eax]
    0xC3,                   // ret
}};
// clang-format on

ConverterCode make_converter_code() {
    auto mem = vm_allocate(nullptr, CONVERTER_CODE.size(), VM_ACCESS_RW);
    if (!mem) {
        return {};
    }

    auto* code = mem.value();
    std::memcpy(code, CONVERTER_CODE.data(), CONVERTER_CODE.size());

    // Code is immutable after copy; drop W to satisfy W^X.
    if (!vm_protect(code, CONVERTER_CODE.size(), VM_ACCESS_RX)) {
        return {};
    }

    ConverterCode result{};
    result.fpu_to_double = reinterpret_cast<FpuToDoubleFn>(code);
    result.double_to_fpu = reinterpret_cast<DoubleToFpuFn>(code + FPU_TO_DOUBLE_LEN);
    result.memory = std::unique_ptr<uint8_t, VmDeleter>(code);

    return result;
}

ConverterCode& get_converter_code() {
    static std::once_flag flag{};
    static ConverterCode code{};

    std::call_once(flag, []() { code = make_converter_code(); });

    return code;
}

float Fpu::as_f32() const noexcept {
    return static_cast<float>(as_f64());
}

double Fpu::as_f64() const noexcept {
    auto& code = get_converter_code();
    if (code.fpu_to_double == nullptr) {
        return 0.0;
    }

    double result{};
    code.fpu_to_double(this, result);

    return result;
}

void Fpu::set_f32(float value) noexcept {
    set_f64(value);
}

void Fpu::set_f64(double value) noexcept {
    auto& code = get_converter_code();
    if (code.double_to_fpu == nullptr) {
        return;
    }

    code.double_to_fpu(value, this);
}

#endif

namespace {
constexpr uint16_t FCW_IM = 1u << 0; // invalid-operation exception mask
constexpr uint16_t FSW_IE = 1u << 0; // invalid operation
constexpr uint16_t FSW_SF = 1u << 6; // stack fault
constexpr uint16_t FSW_ES = 1u << 7; // exception summary
constexpr uint16_t FSW_C1 = 1u << 9; // condition code 1 (overflow / underflow on a stack fault)
constexpr uint16_t FSW_B = 1u << 15; // busy, mirrors ES
constexpr uint16_t FSW_TOP = 7u << 11;

constexpr uint8_t TAG_VALID = 0;
constexpr uint8_t TAG_ZERO = 1;
constexpr uint8_t TAG_SPECIAL = 2;
constexpr uint8_t TAG_EMPTY = 3;

// QNaN floating-point indefinite, what a masked stack fault loads.
constexpr Fpu INDEFINITE{{0, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0xFF}};

// The tag the FPU gives a register holding `value`.
uint8_t tag_of(const Fpu& value) noexcept {
    const auto exponent = static_cast<uint16_t>(value.raw[8] | ((value.raw[9] & 0x7F) << 8));
    uint64_t significand{};
    std::memcpy(&significand, value.raw, sizeof(significand));

    if (exponent == 0x7FFF) {
        return TAG_SPECIAL; // infinity or NaN
    }

    if (exponent == 0) {
        return significand == 0 ? TAG_ZERO : TAG_SPECIAL; // zero, or denormal / pseudo-denormal
    }

    // Integer bit clear with a non-zero exponent: unnormal.
    return (significand >> 63) != 0 ? TAG_VALID : TAG_SPECIAL;
}

void set_tag(FpuEnv& env, uint8_t index, uint8_t tag) noexcept {
    const auto shift = (index & 7u) * 2u;
    env.ftw = static_cast<uint16_t>((env.ftw & ~(3u << shift)) | (static_cast<unsigned>(tag) << shift));
}

void set_top(FpuEnv& env, uint8_t top) noexcept {
    env.fsw = static_cast<uint16_t>((env.fsw & ~FSW_TOP) | ((top & 7u) << 11));
}

// Records an x87 stack fault (#IS) like the FPU does. Returns true when the exception is masked, in which case the
// instruction still completes; an unmasked one leaves the stack alone and is raised by the next x87 instruction.
bool stack_fault(FpuEnv& env, bool overflow) noexcept {
    env.fsw =
        static_cast<uint16_t>(overflow ? env.fsw | FSW_IE | FSW_SF | FSW_C1 : (env.fsw | FSW_IE | FSW_SF) & ~FSW_C1);

    if ((env.fcw & FCW_IM) != 0) {
        return true;
    }

    env.fsw |= FSW_ES | FSW_B;

    return false;
}
} // namespace

void Context32::st_push(const Fpu& value) noexcept {
    const auto top = static_cast<uint8_t>((fpu_env.top() - 1) & 7);
    auto loaded = value;

    if (fpu_env.tag(top) != TAG_EMPTY) {
        if (!stack_fault(fpu_env, true)) {
            return;
        }

        loaded = INDEFINITE;
    } else {
        fpu_env.fsw &= static_cast<uint16_t>(~FSW_C1);
    }

    std::memmove(&st1, &st0, sizeof(Fpu) * 7);
    st0 = loaded;
    set_top(fpu_env, top);
    set_tag(fpu_env, top, tag_of(loaded));
}

Fpu Context32::st_pop_value() noexcept {
    const auto top = fpu_env.top();
    auto value = st0;

    if (fpu_env.tag(top) == TAG_EMPTY) {
        if (!stack_fault(fpu_env, false)) {
            return INDEFINITE;
        }

        value = INDEFINITE;
    } else {
        fpu_env.fsw &= static_cast<uint16_t>(~FSW_C1);
    }

    std::memmove(&st0, &st1, sizeof(Fpu) * 7);
    st7 = Fpu{};
    set_tag(fpu_env, top, TAG_EMPTY);
    set_top(fpu_env, static_cast<uint8_t>(top + 1));

    return value;
}

void Context32::st_pop() noexcept {
    (void)st_pop_value();
}

float Context32::st_pop_f32() noexcept {
    return st_pop_value().as_f32();
}

double Context32::st_pop_f64() noexcept {
    return st_pop_value().as_f64();
}

void Context32::st_push_f32(float value) noexcept {
    Fpu slot{};
    slot.set_f32(value);
    st_push(slot);
}

void Context32::st_push_f64(double value) noexcept {
    Fpu slot{};
    slot.set_f64(value);
    st_push(slot);
}

#endif // SAFETYHOOK_ARCH_X86_32

} // namespace safetyhook
