// SunpackSharedOutput.h
//
// Private zero-copy output extension used only by the embedded SunPack/7-Zip build.
// The normal ISequentialOutStream ABI remains untouched. Compatible decoders can
// either fill a writer-owned buffer directly or lend an immutable decoder span
// to the asynchronous writer until WaitBorrowed() retires its token.

#ifndef SUNPACK_7ZIP_SHARED_OUTPUT_H
#define SUNPACK_7ZIP_SHARED_OUTPUT_H

#include "../IStream.h"

#define Z7_IFACEM_ISunpackSharedOutput(x) \
    x(Acquire(UInt32 desiredSize, Byte **data, UInt32 *capacity, UInt64 *token)) \
    x(Commit(UInt64 token, UInt32 size, UInt32 *processedSize)) \
    x(SubmitBorrowed(const Byte *data, UInt32 size, UInt32 *processedSize, UInt64 *token)) \
    x(WaitBorrowed(UInt64 token))

struct ISunpackSharedOutput : public IUnknown
{
    Z7_IFACE_COM7_PURE(ISunpackSharedOutput)
};

// Borrowed-output tokens are pointers to this tiny stable record. Keeping the
// wait callback in the token itself avoids a registry lookup on the hot path
// and lets folder streams retire a token after the underlying file stream has
// already changed at a solid-file boundary.
struct CSunpackSharedOutputLeaseToken
{
    void *context;
    HRESULT (*waitAndRelease)(void *context);
};

inline UInt64 SunpackSharedOutput_MakeToken(CSunpackSharedOutputLeaseToken *token)
{
    static_assert(sizeof(void *) <= sizeof(UInt64), "shared-output token must fit in UInt64");
    return (UInt64)(size_t)token;
}

inline HRESULT SunpackSharedOutput_WaitToken(UInt64 value)
{
    if (value == 0)
        return E_INVALIDARG;
    CSunpackSharedOutputLeaseToken *token =
        (CSunpackSharedOutputLeaseToken *)(size_t)value;
    return token->waitAndRelease
        ? token->waitAndRelease(token->context)
        : E_FAIL;
}

// Fixed-size token ring for decoder-owned windows. It has no allocation and
// keeps a bounded number of writes in flight; power-of-two N makes the hot
// index operation a mask instead of division.
template <unsigned N>
class CSunpackSharedOutputLeaseRing
{
    static_assert(N != 0 && (N & (N - 1)) == 0,
        "shared-output lease ring size must be a power of two");

    UInt64 _tokens[N]{};
    unsigned _head = 0;
    unsigned _count = 0;

public:
    ~CSunpackSharedOutputLeaseRing()
    {
        Drain();
    }

    HRESULT RetireOne()
    {
        if (_count == 0)
            return S_OK;
        const HRESULT result = SunpackSharedOutput_WaitToken(_tokens[_head]);
        _tokens[_head] = 0;
        _head = (_head + 1) & (N - 1);
        --_count;
        return result;
    }

    HRESULT Push(UInt64 token)
    {
        if (token == 0)
            return E_INVALIDARG;

        HRESULT result = S_OK;
        if (_count == N)
            result = RetireOne();

        const unsigned tail = (_head + _count) & (N - 1);
        _tokens[tail] = token;
        ++_count;
        return result;
    }

    HRESULT Drain()
    {
        HRESULT first = S_OK;
        while (_count != 0)
        {
            const HRESULT current = RetireOne();
            if (first == S_OK && current != S_OK)
                first = current;
        }
        return first;
    }

    bool Empty() const { return _count == 0; }
};


// Fixed-size range-aware token set for cyclic decoder windows. Unlike the
// FIFO-only ring above, this can retire only leases whose source bytes overlap
// a physical window region that is about to be overwritten. N remains a power
// of two so slot scans stay tiny and allocation-free.
template <unsigned N>
class CSunpackSharedOutputRangeLeaseRing
{
    static_assert(N != 0 && (N & (N - 1)) == 0,
        "shared-output range lease ring size must be a power of two");

    struct CEntry
    {
        UInt64 Token = 0;
        UInt64 Begin = 0;
        UInt64 End = 0;
    };

    CEntry _entries[N]{};
    unsigned _count = 0;
    unsigned _cursor = 0;

    HRESULT RetireIndex(unsigned index)
    {
        CEntry &entry = _entries[index];
        if (entry.Token == 0)
            return S_OK;
        const UInt64 token = entry.Token;
        entry = CEntry{};
        --_count;
        return SunpackSharedOutput_WaitToken(token);
    }

public:
    ~CSunpackSharedOutputRangeLeaseRing()
    {
        Drain();
    }

    HRESULT RetireOne()
    {
        if (_count == 0)
            return S_OK;
        for (unsigned i = 0; i < N; ++i)
        {
            const unsigned index = (_cursor + i) & (N - 1);
            if (_entries[index].Token != 0)
            {
                _cursor = (index + 1) & (N - 1);
                return RetireIndex(index);
            }
        }
        return E_FAIL;
    }

    HRESULT Push(UInt64 token, UInt64 begin, UInt64 end)
    {
        if (token == 0 || end < begin)
            return E_INVALIDARG;

        HRESULT result = S_OK;
        if (_count == N)
            result = RetireOne();

        for (unsigned i = 0; i < N; ++i)
        {
            const unsigned index = (_cursor + i) & (N - 1);
            if (_entries[index].Token == 0)
            {
                _entries[index].Token = token;
                _entries[index].Begin = begin;
                _entries[index].End = end;
                ++_count;
                _cursor = (index + 1) & (N - 1);
                return result;
            }
        }

        // A full set must have freed one slot above.
        return result == S_OK ? E_FAIL : result;
    }

    HRESULT RetireOverlapping(UInt64 begin, UInt64 end)
    {
        if (begin >= end || _count == 0)
            return S_OK;

        HRESULT first = S_OK;
        for (unsigned i = 0; i < N; ++i)
        {
            CEntry &entry = _entries[i];
            if (entry.Token == 0)
                continue;
            if (entry.Begin < end && begin < entry.End)
            {
                const HRESULT current = RetireIndex(i);
                if (first == S_OK && current != S_OK)
                    first = current;
            }
        }
        return first;
    }

    HRESULT Drain()
    {
        HRESULT first = S_OK;
        for (unsigned i = 0; i < N; ++i)
        {
            if (_entries[i].Token == 0)
                continue;
            const HRESULT current = RetireIndex(i);
            if (first == S_OK && current != S_OK)
                first = current;
        }
        return first;
    }

    bool Empty() const { return _count == 0; }
};

// Project-private IID. It is intentionally not an upstream 7-Zip interface.
inline const IID IID_ISunpackSharedOutput =
{ 0xa9585c42, 0x79d1, 0x4f17, { 0xa6, 0xa2, 0x73, 0x9e, 0x35, 0x42, 0x7d, 0x16 } };

#endif
