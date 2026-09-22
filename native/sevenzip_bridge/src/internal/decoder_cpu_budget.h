#pragma once

#define SUNPACK_CPU_MANAGED_THREAD_HINT 32u

#ifdef __cplusplus
extern "C" {
#endif

void *sunpack_cpu_current_job_context(void);

/* Installs context on the calling thread and returns the previous context. */
void *sunpack_cpu_exchange_current_job_context(void *context);

unsigned sunpack_cpu_acquire_extra_for_context(
    void *context,
    unsigned wanted,
    unsigned minimum_grant);

unsigned sunpack_cpu_acquire_all_available_for_context(
    void *context);

void sunpack_cpu_release_extra_for_context(
    void *context,
    unsigned count);

unsigned sunpack_cpu_acquire_extra(
    unsigned wanted,
    unsigned minimum_grant);

unsigned sunpack_cpu_acquire_all_available(void);

void sunpack_cpu_release_extra(unsigned count);

#ifdef __cplusplus
}
#endif
