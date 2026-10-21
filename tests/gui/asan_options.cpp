// Test processes allocate many short-lived inspection objects. Keep one
// allocation frames instead of thirty; access-error stacks, instrumentation,
// redzones and the use-after-free quarantine retain their normal settings.
// ASAN_OPTIONS can override this default for deeper allocation diagnostics.
extern "C" __declspec(dllexport) const char* __asan_default_options() {
    return "malloc_context_size=1";
}
