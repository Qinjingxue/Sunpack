#include "Ppmd7.h"
#include <stdlib.h>
#include <windows.h>

typedef struct {
    IByteIn stream;
    const Byte *current;
    const Byte *end;
    BoolInt exhausted;
} PpmdHeaderInput;

static Byte ReadByte(IByteInPtr stream) {
    PpmdHeaderInput *input = (PpmdHeaderInput *)stream;
    if (input->current != input->end)
        return *input->current++;
    input->exhausted = True;
    return 0;
}

static void *Alloc(ISzAllocPtr allocator, size_t size) {
    (void)allocator;
    return malloc(size);
}

static void Free(ISzAllocPtr allocator, void *memory) {
    (void)allocator;
    free(memory);
}

static const ISzAlloc allocator = { Alloc, Free };

static int ReserveModel(SunpackMemoryReservation *reservation, size_t size) {
    reservation->base = VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_NOACCESS);
    return reservation->base != NULL;
}

static int CommitModel(SunpackMemoryReservation *reservation, void *address, size_t size) {
    (void)reservation;
    return VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE) != NULL;
}

static void ReleaseModel(SunpackMemoryReservation *reservation) {
    VirtualFree(reservation->base, 0, MEM_RELEASE);
}

static const SunpackMemoryReservationOps model_memory = { ReserveModel, CommitModel, ReleaseModel };

// The caller supplies a complete packed metadata stream and its checked size.
int sunpack_decode_ppmd7_header(
    const Byte *data, size_t size, UInt32 memory, unsigned order, UInt64 remaining,
    void *context, int (*write)(void *, const Byte *, size_t)
) {
    PpmdHeaderInput input = { { ReadByte }, data, data + size, False };
    CPpmd7 decoder;
    Byte buffer[16 * 1024];
    Ppmd7_Construct(&decoder);
    decoder.rc.dec.Stream = &input.stream;
    if (!Ppmd7z_RangeDec_Init(&decoder.rc.dec) || input.exhausted)
        return SZ_ERROR_DATA;
    const BoolInt allocated = memory < SUNPACK_LARGE_ALLOCATION
        ? Ppmd7_Alloc(&decoder, memory, &allocator)
        : Ppmd7_AllocReserved(&decoder, memory, &allocator, &model_memory);
    if (!allocated)
        return SZ_ERROR_MEM;
    Ppmd7_Init(&decoder, order);
    int result = SZ_OK;
    if (decoder.CommitFailed) {
        result = SZ_ERROR_MEM;
        goto finish;
    }
    while (remaining != 0) {
        const size_t count = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        for (size_t i = 0; i < count; ++i) {
            const int symbol = Ppmd7z_DecodeSymbol(&decoder);
            // A failed model update can leave no context for the next symbol.
            if (symbol < 0 || (input.exhausted | decoder.CommitFailed)) {
                result = decoder.CommitFailed ? SZ_ERROR_MEM : SZ_ERROR_DATA;
                goto finish;
            }
            buffer[i] = (Byte)symbol;
        }
        if (write(context, buffer, count)) {
            result = SZ_ERROR_WRITE;
            goto finish;
        }
        remaining -= count;
    }
    if (!Ppmd7z_RangeDec_IsFinishedOK(&decoder.rc.dec) || input.current != input.end)
        result = SZ_ERROR_DATA;
finish:
    Ppmd7_Free(&decoder, &allocator);
    return result;
}
