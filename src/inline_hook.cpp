#include <iterator>

#include <Windows.h>

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

#include <safetyhook/allocator.hpp>
#include <safetyhook/thread_freezer.hpp>
#include <safetyhook/utility.hpp>

#include <safetyhook/inline_hook.hpp>

namespace safetyhook {
class UnprotectMemory {
public:
    UnprotectMemory(uint8_t* address, size_t size) : m_address{address}, m_size{size} {
        VirtualProtect(m_address, m_size, PAGE_EXECUTE_READWRITE, &m_protect);
    }

    ~UnprotectMemory() { VirtualProtect(m_address, m_size, m_protect, &m_protect); }

private:
    uint8_t* m_address{};
    size_t m_size{};
    DWORD m_protect{};
};

struct DecodeData {
    uint8_t length{};
    uint8_t opcode{};
    bool is_relative{};
    bool has_disp{};
    uint8_t disp_size{};
    uint8_t disp_offset{};
    uint32_t disp_value{};
    bool has_rel_offset{};
    uint8_t rel_offset_size{};
    uint8_t rel_offset_offset{};
    uint32_t rel_offset_value{};
    bool is_cond_branch{};
    bool is_uncond_branch{};
    bool is_short_branch{};
};

#pragma pack(push, 1)
struct JmpE9 {
    uint8_t opcode{0xE9};
    uint32_t offset{0};
};

#if defined(_M_X64)
struct JmpFF {
    uint8_t opcode0{0xFF};
    uint8_t opcode1{0x25};
    uint32_t offset{0};
};

struct TrampolineEpilogueE9 {
    JmpE9 jmp_to_original{};
    JmpFF jmp_to_destination{};
    uint64_t destination_address{};
};

struct TrampolineEpilogueFF {
    JmpFF jmp_to_original{};
    uint64_t original_address{};
};
#elif defined(_M_IX86)
struct TrampolineEpilogueE9 {
    JmpE9 jmp_to_original{};
    JmpE9 jmp_to_destination{};
};
#endif
#pragma pack(pop)

#ifdef _M_X64
static auto make_jmp_ff(uint8_t* src, uint8_t* dst, uint8_t* data) {
    JmpFF jmp{};

    jmp.offset = static_cast<uint32_t>(data - src - sizeof(jmp));
    store(data, dst);

    return jmp;
}

static void emit_jmp_ff(uint8_t* src, uint8_t* dst, uint8_t* data, size_t size = sizeof(JmpFF)) {
    if (size < sizeof(JmpFF)) {
        return;
    }

    UnprotectMemory unprotect{src, size};

    if (size > sizeof(JmpFF)) {
        std::fill_n(src, size, static_cast<uint8_t>(0x90));
    }

    store(src, make_jmp_ff(src, dst, data));
}
#endif

constexpr auto make_jmp_e9(uint8_t* src, uint8_t* dst) {
    JmpE9 jmp{};

    jmp.offset = static_cast<uint32_t>(dst - src - sizeof(jmp));

    return jmp;
}

static void emit_jmp_e9(uint8_t* src, uint8_t* dst, size_t size = sizeof(JmpE9)) {
    if (size < sizeof(JmpE9)) {
        return;
    }

    UnprotectMemory unprotect{src, size};

    if (size > sizeof(JmpE9)) {
        std::fill_n(src, size, static_cast<uint8_t>(0x90));
    }

    store(src, make_jmp_e9(src, dst));
}

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

    ZydisDecodedInstruction ix{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, ip, ZYDIS_MAX_INSTRUCTION_LENGTH, &ix))) {
        return false;
    }

    out.length = ix.length;
    out.opcode = ix.opcode;
    out.is_relative = (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;
    out.has_disp = ix.raw.disp.value != 0;
    out.disp_size = ix.raw.disp.size / CHAR_BIT;
    out.disp_offset = ix.raw.disp.offset;
    out.disp_value = ix.raw.disp.value;
    out.has_rel_offset = ix.raw.imm[0].is_relative;
    out.rel_offset_size = ix.raw.imm[0].size / CHAR_BIT;
    out.rel_offset_offset = ix.raw.imm[0].offset;
    out.rel_offset_value = (uint32_t)ix.raw.imm[0].value.s;
    out.is_cond_branch = ix.meta.category == ZYDIS_CATEGORY_COND_BR;
    out.is_uncond_branch = ix.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
    out.is_short_branch = ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT;
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
    out.is_relative = ix.IsRipRelative;
    out.has_disp = ix.HasDisp;
    out.disp_size = ix.DispLength;
    out.disp_offset = ix.DispOffset;
    out.disp_value = ix.Displacement;
    out.has_rel_offset = ix.HasRelOffs;
    out.rel_offset_size = ix.RelOffsLength;
    out.rel_offset_offset = ix.RelOffsOffset;
    out.rel_offset_value = ix.RelativeOffset;

    if (ix.BranchInfo.IsBranch) {
        out.is_cond_branch = ix.BranchInfo.IsConditional;
        out.is_uncond_branch = !ix.BranchInfo.IsConditional;
        out.is_short_branch = !ix.BranchInfo.IsFar;
    }
#endif

    return true;
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(void* target, void* destination) {
    return create(Allocator::global(), target, destination);
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(
    const std::shared_ptr<Allocator>& allocator, void* target, void* destination) {
    InlineHook hook{};

    if (const auto setup_result =
            hook.setup(allocator, reinterpret_cast<uint8_t*>(target), reinterpret_cast<uint8_t*>(destination));
        !setup_result) {
        return std::unexpected{setup_result.error()};
    }

    return hook;
}

InlineHook::InlineHook(InlineHook&& other) noexcept {
    *this = std::move(other);
}

InlineHook& InlineHook::operator=(InlineHook&& other) noexcept {
    if (this != &other) {
        destroy();

        std::scoped_lock lock{m_mutex, other.m_mutex};

        m_target = other.m_target;
        m_destination = other.m_destination;
        m_trampoline = std::move(other.m_trampoline);
        m_trampoline_size = other.m_trampoline_size;
        m_original_bytes = std::move(other.m_original_bytes);

        other.m_target = nullptr;
        other.m_destination = nullptr;
        other.m_trampoline_size = 0;
    }

    return *this;
}

InlineHook::~InlineHook() {
    destroy();
}

void InlineHook::reset() {
    *this = {};
}

std::expected<void, InlineHook::Error> InlineHook::setup(
    const std::shared_ptr<Allocator>& allocator, uint8_t* target, uint8_t* destination) {
    m_target = target;
    m_destination = destination;

    if (auto e9_result = e9_hook(allocator); !e9_result) {
#ifdef _M_X64
        if (auto ff_result = ff_hook(allocator); !ff_result) {
            return ff_result;
        }
#else
        return e9_result;
#endif
    }

    return {};
}

std::expected<void, InlineHook::Error> InlineHook::e9_hook(const std::shared_ptr<Allocator>& allocator) {
    m_original_bytes.clear();
    m_trampoline_size = sizeof(TrampolineEpilogueE9);

    std::vector<uint8_t*> desired_addresses{m_target};
    DecodeData ix{};

    for (auto ip = m_target; ip < m_target + sizeof(JmpE9); ip += ix.length) {
        if (!decode(ix, ip)) {
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        m_trampoline_size += ix.length;
        m_original_bytes.insert(m_original_bytes.end(), ip, ip + ix.length);

        if (ix.is_relative) {
            if (ix.has_disp && ix.disp_size == 4) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.disp_value);
                desired_addresses.emplace_back(target_address);
            } else if (ix.has_rel_offset && ix.rel_offset_size == 4) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.rel_offset_value);
                desired_addresses.emplace_back(target_address);
            } else if (ix.has_rel_offset && ix.is_cond_branch && ix.is_short_branch) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.rel_offset_value);
                desired_addresses.emplace_back(target_address);
                m_trampoline_size += 4; // near conditional branches are 4 bytes larger.
            } else if (ix.has_rel_offset && ix.is_uncond_branch && ix.is_short_branch) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.rel_offset_value);
                desired_addresses.emplace_back(target_address);
                m_trampoline_size += 3; // near unconditional branches are 3 bytes larger.
            } else {
                return std::unexpected{Error::unsupported_instruction_in_trampoline(ip)};
            }
        }
    }

    auto trampoline_allocation = allocator->allocate_near(desired_addresses, m_trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{Error::bad_allocation(trampoline_allocation.error())};
    }

    m_trampoline = std::move(*trampoline_allocation);

    for (auto ip = m_target, tramp_ip = m_trampoline.data(); ip < m_target + m_original_bytes.size(); ip += ix.length) {
        if (!decode(ix, ip)) {
            m_trampoline.free();
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        if (ix.is_relative && ix.has_disp && ix.disp_size == 4) {
            std::copy_n(ip, ix.length, tramp_ip);
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.disp_value);
            const auto new_disp = target_address - (tramp_ip + ix.length);
            store(tramp_ip + ix.disp_offset, static_cast<int32_t>(new_disp));
            tramp_ip += ix.length;
        } else if (ix.is_relative && ix.has_rel_offset && ix.rel_offset_size == 4) {
            std::copy_n(ip, ix.length, tramp_ip);
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.rel_offset_value);
            const auto new_disp = target_address - (tramp_ip + ix.length);
            store(tramp_ip + ix.rel_offset_offset, static_cast<int32_t>(new_disp));
            tramp_ip += ix.length;
        } else if (ix.has_rel_offset && ix.is_cond_branch && ix.is_short_branch) {
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.rel_offset_value);
            auto new_disp = target_address - (tramp_ip + 6);

            // Handle the case where the target is now in the trampoline.
            if (target_address < m_target + m_original_bytes.size()) {
                new_disp = static_cast<ptrdiff_t>(ix.rel_offset_value);
            }

            *tramp_ip = 0x0F;
            *(tramp_ip + 1) = 0x10 + ix.opcode;
            store(tramp_ip + 2, static_cast<int32_t>(new_disp));
            tramp_ip += 6;
        } else if (ix.has_rel_offset && ix.is_uncond_branch && ix.is_short_branch) {
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.rel_offset_value);
            auto new_disp = target_address - (tramp_ip + 5);

            // Handle the case where the target is now in the trampoline.
            if (target_address < m_target + m_original_bytes.size()) {
                new_disp = static_cast<ptrdiff_t>(ix.rel_offset_value);
            }

            *tramp_ip = 0xE9;
            store(tramp_ip + 1, static_cast<int32_t>(new_disp));
            tramp_ip += 5;
        } else {
            std::copy_n(ip, ix.length, tramp_ip);
            tramp_ip += ix.length;
        }
    }

    auto trampoline_epilogue = reinterpret_cast<TrampolineEpilogueE9*>(
        m_trampoline.address() + m_trampoline_size - sizeof(TrampolineEpilogueE9));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_original);
    auto dst = m_target + m_original_bytes.size();
    emit_jmp_e9(src, dst);

    // jmp from trampoline to destination.
    src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_destination);
    dst = m_destination;

#ifdef _M_X64
    auto data = reinterpret_cast<uint8_t*>(&trampoline_epilogue->destination_address);
    emit_jmp_ff(src, dst, data);
#else
    emit_jmp_e9(src, dst);
#endif

    // jmp from original to trampoline.
    execute_while_frozen(
        [this, &trampoline_epilogue] {
            const auto src = m_target;
            const auto dst = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_destination);
            emit_jmp_e9(src, dst, m_original_bytes.size());
        },
        [this](uint32_t, HANDLE, CONTEXT& ctx) {
            for (size_t i = 0; i < m_original_bytes.size(); ++i) {
                fix_ip(ctx, m_target + i, m_trampoline.data() + i);
            }
        });

    return {};
}

#ifdef _M_X64
std::expected<void, InlineHook::Error> InlineHook::ff_hook(const std::shared_ptr<Allocator>& allocator) {
    m_original_bytes.clear();
    m_trampoline_size = sizeof(TrampolineEpilogueFF);
    DecodeData ix{};

    for (auto ip = m_target; ip < m_target + sizeof(JmpFF) + sizeof(uintptr_t); ip += ix.length) {
        if (!decode(ix, ip)) {
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        // We can't support any instruction that is IP relative here because
        // ff_hook should only be called if e9_hook failed indicating that
        // we're likely outside the +- 2GB range.
        if (ix.is_relative) {
            return std::unexpected{Error::ip_relative_instruction_out_of_range(ip)};
        }

        m_original_bytes.insert(m_original_bytes.end(), ip, ip + ix.length);
        m_trampoline_size += ix.length;
    }

    auto trampoline_allocation = allocator->allocate(m_trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{Error::bad_allocation(trampoline_allocation.error())};
    }

    m_trampoline = std::move(*trampoline_allocation);

    std::copy(m_original_bytes.begin(), m_original_bytes.end(), m_trampoline.data());

    const auto trampoline_epilogue =
        reinterpret_cast<TrampolineEpilogueFF*>(m_trampoline.data() + m_trampoline_size - sizeof(TrampolineEpilogueFF));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uint8_t*>(&trampoline_epilogue->jmp_to_original);
    auto dst = m_target + m_original_bytes.size();
    auto data = reinterpret_cast<uint8_t*>(&trampoline_epilogue->original_address);
    emit_jmp_ff(src, dst, data);

    // jmp from original to trampoline.
    execute_while_frozen(
        [this] {
            const auto src = m_target;
            const auto dst = m_destination;
            const auto data = src + sizeof(JmpFF);
            emit_jmp_ff(src, dst, data, m_original_bytes.size());
        },
        [this](uint32_t, HANDLE, CONTEXT& ctx) {
            for (size_t i = 0; i < m_original_bytes.size(); ++i) {
                fix_ip(ctx, m_target + i, m_trampoline.data() + i);
            }
        });

    return {};
}
#endif

void InlineHook::destroy() {
    std::scoped_lock lock{m_mutex};

    if (!m_trampoline) {
        return;
    }

    execute_while_frozen(
        [this] {
            UnprotectMemory unprotect{m_target, m_original_bytes.size()};
            std::copy(m_original_bytes.begin(), m_original_bytes.end(), m_target);
        },
        [this](uint32_t, HANDLE, CONTEXT& ctx) {
            for (size_t i = 0; i < m_original_bytes.size(); ++i) {
                fix_ip(ctx, m_trampoline.data() + i, m_target + i);
            }
        });

    m_trampoline.free();
}
} // namespace safetyhook
