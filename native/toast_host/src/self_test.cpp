#include "toast.h"

int main() {
    for (int index = 0; index < 10; ++index) {
        if (FAILED(sunpack_toast_self_test())) return 1;
    }
    if (sunpack_toast_clear(nullptr) != E_INVALIDARG) return 2;
    if (sunpack_toast_destroy(nullptr) != E_INVALIDARG) return 3;
    if (sunpack_toast_create_presenter(nullptr, nullptr, nullptr) != E_POINTER) return 4;
    void* context = reinterpret_cast<void*>(1);
    if (sunpack_toast_create_presenter(nullptr, nullptr, &context) != E_INVALIDARG || context) return 5;
    return 0;
}
