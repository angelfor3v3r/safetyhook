# SafetyHook

SafetyHook is a **C++23** procedure hooking library for Windows and Linux x86 and x86_64 systems. It aims to make runtime procedure hooking as safe as possible while maintaining simplicity of its implementation. To that end it currently does:

* Traps other threads when creating or deleting hooks
* Fixes the IP of threads that may be affected by the creation or deletion of hooks
* Fixes IP relative displacements of relocated instructions (eg. `lea rax, [rip + 0x1234]`)
* Fixes relative offsets of relocated instructions (eg. `jmp 0x1234`)
* Widens short branches into near branches
* Handles short branches that land within the trampoline
* Uses a modern disassembler engine that supports the latest instructions
* Has a carefully designed API that is hard to misuse

## Installation

SafetyHook can be added via CMake's `FetchContent`, git submodules, or copied directly into your project using the amalgamated builds. SafetyHook requires [Zydis](https://github.com/zyantific/zydis) to function.

### Amalgamated builds

This is the easiest way to use safety hook. You can find amalgamated builds on the [releases](https://github.com/cursey/safetyhook/releases) page. Simply download the ZIP file with or without [Zydis](https://github.com/zyantific/zydis) and copy the files into your project.

You may need to define `ZYDIS_STATIC_BUILD` if you're using the build with [Zydis](https://github.com/zyantific/zydis) included.

### CMake FetchContent

```CMake
include(FetchContent)

# Safetyhook
FetchContent_Declare(
    safetyhook
    GIT_REPOSITORY "https://github.com/cursey/safetyhook.git"
    GIT_TAG "origin/main"
)
FetchContent_MakeAvailable(safetyhook)
```

### [CPM.cmake](https://github.com/cpm-cmake/CPM.cmake)
```CMake
include(cmake/CPM.cmake)

CPMAddPackage("gh:cursey/safetyhook@0.5.3")
```

If you want SafetyHook to fetch [Zydis](https://github.com/zyantific/zydis) you must enable the CMake option `-DSAFETYHOOK_FETCH_ZYDIS=ON`.

## Usage

```C++
#include <print>

#include <safetyhook.hpp>

__declspec(noinline) int add(int x, int y) {
    return x + y;
}

SafetyHookInline g_add_hook{};

int hook_add(int x, int y) {
    return g_add_hook.call<int>(x * 2, y * 2);
}

int main() {
    std::println("unhooked add(2, 3) = {}", add(2, 3));

    // Create a hook on add (This uses SafetyHook's easy API).
    g_add_hook = safetyhook::create_inline(add, hook_add);

    std::println("hooked add(3, 4) = {}", add(3, 4));

    g_add_hook = {}; // or `g_add_hook.reset();`

    std::println("unhooked add(5, 6) = {}", add(5, 6));

    return 0;
}
```
