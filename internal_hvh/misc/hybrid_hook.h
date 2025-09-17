#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <unordered_map>

#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/ZydisDisassembler.hpp>
#include <polyhook2/Virtuals/VFuncSwapHook.hpp>
#include <polyhook2/Virtuals/VTableSwapHook.hpp>

class c_hook {
public:
    virtual ~c_hook() = default;

    virtual uintptr_t apply(uintptr_t) { return 0; }

    virtual uintptr_t apply(uint32_t, uintptr_t) { return 0; }

    virtual bool is_detour() { return false; }
};

class c_detour : public c_hook {
public:
    using address_t = uintptr_t;

    c_detour() = default;
    explicit c_detour(address_t src) : m_src(src) {}
    ~c_detour() override { unhook(); }

    bool is_detour() override { return true; }

    // commit the detour. 
    // dest: address of your hook function. Returns trampoline ptr (original).
    address_t apply(address_t dest) override {
        if (m_detour) {
            return static_cast<address_t>(m_trampoline);
        }
        if (!m_src || !dest) {
            return 0;
        }

        static_assert(sizeof(void*) == 4, "c_detour is configured for x86 only. Build 32-bit or switch to x64Detour.");

        // Construct and commit the PLH detour 
        // (using Zydis as the backend)
        m_detour = std::make_unique<PLH::x86Detour>(
            static_cast<uint64_t>(m_src),
            static_cast<uint64_t>(dest),
            &m_trampoline,
            m_dis
        );

        const bool ok = m_detour->hook();
        if (!ok) {
            m_detour.reset();
            m_trampoline = 0;
            return 0;
        }
        return static_cast<address_t>(m_trampoline);
    }

    template <typename Fn>
    Fn original() const { return reinterpret_cast<Fn>(m_trampoline); }

    void unhook() {
        if (m_detour) {
            m_detour->unHook();
            m_detour.reset();
            m_trampoline = 0;
        }
    }

    address_t src() const { return m_src; }
    address_t apply(const uint32_t, address_t) override { return 0; } // unused overload

private:
    address_t m_src{ 0 };
    uint64_t m_trampoline{ 0 }; // PolyHook2 stores tramp as u64

    // Disassembler must remain alive as long as the detour
    PLH::ZydisDisassembler m_dis{ PLH::Mode::x86 };
    std::unique_ptr<PLH::x86Detour> m_detour; // controls hook lifetime

    c_detour(const c_detour&) = delete;
    c_detour& operator=(const c_detour&) = delete;
    c_detour(c_detour&&) noexcept = default;
    c_detour& operator=(c_detour&&) noexcept = default;
};

class c_vtable_hook : public c_hook {
public:
    enum class mode { vfunc_swap, vtable_swap };

    explicit c_vtable_hook(uintptr_t instance, mode m = mode::vfunc_swap)
        : m_instance(instance), m_mode(m) {
    }

    ~c_vtable_hook() override { unhook_all(); }

    // Hook a single virtual at index with replacement pointer
    // Returns the original function pointer.
    uintptr_t apply(uint32_t index, uintptr_t replacement) override {
        if (!m_instance) return 0;

        // Grab the original from the live vtable 
        // (safe for both modes)
        auto** vt_ptr = reinterpret_cast<uintptr_t**>(m_instance);
        uintptr_t original = (*vt_ptr)[index];

        HookEntry entry{};
        entry.index = index;
        entry.original = original;

        if (m_mode == mode::vfunc_swap) {
            // In-place swap of one vfunc entry
            auto hook = std::make_unique<PLH::VFuncSwapHook>(
                reinterpret_cast<uint64_t*>(*vt_ptr),
                static_cast<uint16_t>(index),
                static_cast<uint64_t>(replacement)
            );
            if (!hook->hook()) {
                return 0;
            }
            entry.vfunc = std::move(hook);
        }
        else {
            // Deep copy entire table, redirect this index, swap the vptr
            auto hook = std::make_unique<PLH::VTableSwapHook>(
                static_cast<uint64_t>(m_instance),
                static_cast<uint16_t>(index),
                static_cast<uint64_t>(replacement)
            );
            if (!hook->hook()) {
                return 0;
            }
            entry.vtable = std::move(hook);
        }

        m_hooks.emplace_back(std::move(entry));
        return original;
    }

    void unhook_all() {
        for (auto& e : m_hooks) {
            if (e.vfunc)  e.vfunc->unHook();
            if (e.vtable) e.vtable->unHook();
        }
        m_hooks.clear();
    }

    bool is_detour() override { return false; }

private:
    struct HookEntry {
        uint32_t index{};
        uintptr_t original{};
        std::unique_ptr<PLH::VFuncSwapHook>  vfunc;
        std::unique_ptr<PLH::VTableSwapHook> vtable;
    };

    uintptr_t m_instance{ 0 };
    mode m_mode{ mode::vfunc_swap };
    std::vector<HookEntry> m_hooks{};
};
