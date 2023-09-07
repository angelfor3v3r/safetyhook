#include <iostream>

#if __has_include(<Zydis/Zydis.h>)
#include <Zydis/Zydis.h>
#define USE_ZYDIS
#elif __has_include(<Zydis.h>)
#include <Zydis.h>
#define USE_ZYDIS
#endif

#if __has_include(<bddisasm/bddisasm.h>)
#include <bddisasm/bddisasm.h>
#define USE_BDDISASM
#elif __has_include(<bddisasm.h>)
#include <bddisasm.h>
#define USE_BDDISASM
#endif

#if defined(USE_ZYDIS) && defined(USE_BDDISASM)
#error "Please only use Zydis or bddisasm, not both."
#endif

#include <safetyhook.hpp>

struct DecodeData {
    uint8_t length{};
    uint8_t opcode{};
    uint32_t rel_offset_value{};
};

static bool decode(DecodeData& out, uint8_t* ip) {
#if defined(USE_ZYDIS)
    ZydisDecoder decoder{};
    ZyanStatus status;

#if defined(_M_X64)
    status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif defined(_M_IX86)
    status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#else
#error "Unsupported architecture"
#endif

    if (!ZYAN_SUCCESS(status)) {
        return false;
    }

    ZydisDecodedInstruction ix;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, ip, 15, &ix))) {
        return false;
    }

    out.length = ix.length;
    out.opcode = ix.opcode;
    out.rel_offset_value = (uint32_t)ix.raw.imm[0].value.s;
#elif defined(USE_BDDISASM)
    INSTRUX ix{};

#if defined(_M_X64)
    if (!ND_SUCCESS(NdDecode(&ix, static_cast<const ND_UINT8*>(ip), ND_CODE_64, ND_DATA_64)))
#elif defined(_M_IX86)
    if (!ND_SUCCESS(NdDecode(&ix, static_cast<const ND_UINT8*>(ip), ND_CODE_32, ND_DATA_32)))
#else
#error "Unsupported architecture"
#endif
    {
        return false;
    }

    out.length = ix.Length;
    out.opcode = ix.PrimaryOpCode;
#endif

    return true;
}

__declspec(noinline) int add_42(int a) {
    return a + 42;
}

void hooked_add_42(SafetyHookContext& ctx) {
#ifdef _M_X64
    ctx.rax = 1337;
#else
    ctx.eax = 1337;
#endif
}

SafetyHookMid g_hook{};

int main() {
    std::cout << add_42(2) << "\n";

    // Let's disassemble add_42 and hook its RET.
    auto ip = reinterpret_cast<uint8_t*>(add_42);

    DecodeData ix{};

    while (*ip != 0xC3) {
        decode(ix, ip);

        // Follow JMPs
        if (ix.opcode == 0xE9) {
            ip += ix.length + static_cast<int32_t>(ix.rel_offset_value);
        } else {
            ip += ix.length;
        }
    }

    g_hook = safetyhook::create_mid(ip, hooked_add_42);

    std::cout << add_42(3) << "\n";

    g_hook.reset();

    std::cout << add_42(4) << "\n";

    return 0;
}
