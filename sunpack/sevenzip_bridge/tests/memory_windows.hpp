#pragma once
#include <Windows.h>
#include <Psapi.h>

// Simulate system commitment using an actual isolated Job's limit/usage.
// No test switch, Job query or alternate budget policy enters production.
inline BOOL test_performance_information(PPERFORMANCE_INFORMATION info, DWORD size) {
    if (!GetPerformanceInfo(info, size)) return FALSE;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    struct Usage { ULONG64 total, peak; } usage{};
    if (QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr) &&
        (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY) &&
        QueryInformationJobObject(nullptr, static_cast<JOBOBJECTINFOCLASS>(28), &usage, sizeof(usage), nullptr)) {
        info->CommitLimit = limits.JobMemoryLimit / info->PageSize;
        info->CommitTotal = (usage.total + info->PageSize - 1) / info->PageSize;
    }
    return TRUE;
}
#undef GetPerformanceInfo
#define GetPerformanceInfo test_performance_information
