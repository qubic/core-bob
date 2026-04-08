#include "GlobalVar.h"

GlobalState& GS() {
    // Allocate once on the heap to avoid gigantic .bss/.data sections.
    static GlobalState* inst = []() -> GlobalState* {
        // Use malloc to avoid throwing in low-memory situations; then zero memory.
        void* mem = std::malloc(sizeof(GlobalState));
        if (!mem) {
            // If you have a logger available here, you could log and abort.
            std::abort();
        }
        std::memset(mem, 0, sizeof(GlobalState));
        // Placement-new is optional since GlobalState is trivially constructible.
        return new (mem) GlobalState();
    }();
    return *inst;
}

