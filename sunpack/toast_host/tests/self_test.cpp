#include "toast.h"

int main() {
    // A second activation verifies that the first probe released its COM state.
    for (int index = 0; index < 2; ++index) {
        if (FAILED(sunpack_toast_self_test())) return 1;
    }
    if (sunpack_toast_clear(nullptr) != E_INVALIDARG) return 2;
    if (sunpack_toast_destroy(nullptr) != E_INVALIDARG) return 3;
    if (sunpack_toast_create(nullptr) != E_POINTER) return 4;
    void* context = nullptr;
    if (FAILED(sunpack_toast_create(&context)) || !context) return 5;
    if (FAILED(sunpack_toast_destroy(context))) return 6;
    return 0;
}
