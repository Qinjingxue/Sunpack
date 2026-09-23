/* Alloc.c -- Memory allocation functions
: Igor Pavlov : Public domain */

#include "Precomp.h"

#ifdef _WIN32
#include "7zWindows.h"
#include <winioctl.h>
#endif
#include <stdlib.h>

#include "Alloc.h"

#if defined(Z7_LARGE_PAGES) && defined(_WIN32) && \
    (!defined(Z7_WIN32_WINNT_MIN) || Z7_WIN32_WINNT_MIN < 0x0502)  // < Win2003 (xp-64)
  #define Z7_USE_DYN_GetLargePageMinimum
#endif

// for debug:
#if 0
#if defined(__CHERI__) && defined(__SIZEOF_POINTER__) && (__SIZEOF_POINTER__ == 16)
// #pragma message("=== Z7_ALLOC_NO_OFFSET_ALLOCATOR === ")
#define Z7_ALLOC_NO_OFFSET_ALLOCATOR
#endif
#endif

// #define SZ_ALLOC_DEBUG
/* use SZ_ALLOC_DEBUG to debug alloc/free operations */
#ifdef SZ_ALLOC_DEBUG

#include <string.h>
#include <stdio.h>
static int g_allocCount = 0;
#ifdef _WIN32
static int g_allocCountMid = 0;
#ifdef Z7_LARGE_PAGES
static int g_allocCountBig = 0;
#endif
#endif

#define CONVERT_INT_TO_STR(charType, tempSize) \
  char temp[tempSize]; unsigned i = 0; \
  while (val >= 10) { temp[i++] = (char)('0' + (unsigned)(val % 10)); val /= 10; } \
  *s++ = (charType)('0' + (unsigned)val); \
  while (i != 0) { i--; *s++ = temp[i]; } \
  *s = 0;

static void ConvertUInt64ToString(UInt64 val, char *s)
{
  CONVERT_INT_TO_STR(char, 24)
}

#define GET_HEX_CHAR(t) ((char)(((t < 10) ? ('0' + t) : ('A' + (t - 10)))))

static void ConvertUInt64ToHex(UInt64 val, char *s)
{
  UInt64 v = val;
  unsigned i;
  for (i = 1;; i++)
  {
    v >>= 4;
    if (v == 0)
      break;
  }
  s[i] = 0;
  do
  {
    unsigned t = (unsigned)(val & 0xF);
    val >>= 4;
    s[--i] = GET_HEX_CHAR(t);
  }
  while (i);
}

#define DEBUG_OUT_STREAM stderr

static void Print(const char *s)
{
  fputs(s, DEBUG_OUT_STREAM);
}

static void PrintAligned(const char *s, size_t align)
{
  size_t len = strlen(s);
  for(;;)
  {
    fputc(' ', DEBUG_OUT_STREAM);
    if (len >= align)
      break;
    ++len;
  }
  Print(s);
}

static void PrintLn(void)
{
  Print("\n");
}

static void PrintHex(UInt64 v, size_t align)
{
  char s[32];
  ConvertUInt64ToHex(v, s);
  PrintAligned(s, align);
}

static void PrintDec(int v, size_t align)
{
  char s[32];
  ConvertUInt64ToString((unsigned)v, s);
  PrintAligned(s, align);
}

static void PrintAddr(void *p)
{
  PrintHex((UInt64)(size_t)(ptrdiff_t)p, 12);
}


#define PRINT_REALLOC(name, cnt, size, ptr) { \
    Print(name " "); \
    if (!ptr) PrintDec(cnt++, 10); \
    PrintHex(size, 10); \
    PrintAddr(ptr); \
    PrintLn(); }

#define PRINT_ALLOC(name, cnt, size, ptr) { \
    Print(name " "); \
    PrintDec(cnt++, 10); \
    PrintHex(size, 10); \
    PrintAddr(ptr); \
    PrintLn(); }
 
#define PRINT_FREE(name, cnt, ptr) if (ptr) { \
    Print(name " "); \
    PrintDec(--cnt, 10); \
    PrintAddr(ptr); \
    PrintLn(); }
 
#else

#ifdef _WIN32
#ifdef Z7_LARGE_PAGES
#define PRINT_ALLOC(name, cnt, size, ptr)
#endif
#endif
#define PRINT_FREE(name, cnt, ptr)
#define Print(s)
#define PrintLn()
#ifndef Z7_ALLOC_NO_OFFSET_ALLOCATOR
#define PrintHex(v, align)
#endif
#define PrintAddr(p)

#endif


/*
by specification:
  malloc(non_NULL, 0)   : returns NULL or a unique pointer value that can later be successfully passed to free()
  realloc(NULL, size)   : the call is equivalent to malloc(size)
  realloc(non_NULL, 0)  : the call is equivalent to free(ptr)

in main compilers:
  malloc(0)             : returns non_NULL
  realloc(NULL,     0)  : returns non_NULL
  realloc(non_NULL, 0)  : returns NULL
*/


void *MyAlloc(size_t size)
{
  if (size == 0)
    return NULL;
  // PRINT_ALLOC("Alloc    ", g_allocCount, size, NULL)
  #ifdef SZ_ALLOC_DEBUG
  {
    void *p = malloc(size);
    if (p)
    {
      PRINT_ALLOC("Alloc    ", g_allocCount, size, p)
    }
    return p;
  }
  #else
  return malloc(size);
  #endif
}

void MyFree(void *address)
{
  PRINT_FREE("Free    ", g_allocCount, address)
  
  free(address);
}

void *MyRealloc(void *address, size_t size)
{
  if (size == 0)
  {
    MyFree(address);
    return NULL;
  }
  // PRINT_REALLOC("Realloc  ", g_allocCount, size, address)
  #ifdef SZ_ALLOC_DEBUG
  {
    void *p = realloc(address, size);
    if (p)
    {
      PRINT_REALLOC("Realloc    ", g_allocCount, size, address)
    }
    return p;
  }
  #else
  return realloc(address, size);
  #endif
}


#ifdef _WIN32

void *MidAlloc(size_t size)
{
  if (size == 0)
    return NULL;
  #ifdef SZ_ALLOC_DEBUG
  {
    void *p = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (p)
    {
      PRINT_ALLOC("Alloc-Mid", g_allocCountMid, size, p)
    }
    return p;
  }
  #else
  return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
  #endif
}

void MidFree(void *address)
{
  PRINT_FREE("Free-Mid", g_allocCountMid, address)

  if (!address)
    return;
  VirtualFree(address, 0, MEM_RELEASE);
}


#define SUNPACK_FILE_BUFFER_THRESHOLD ((size_t)1 << 24)

void SunpackFileBuffer_Construct(CSunpackFileBuffer *p)
{
  p->data = NULL;
  p->capacity = 0;
  p->fileHandle = NULL;
  p->mappingHandle = NULL;
  p->fileBacked = False;
}

static void SunpackFileBuffer_ReleaseWindows(CSunpackFileBuffer *p)
{
  if (p->data)
    UnmapViewOfFile(p->data);
  if (p->mappingHandle)
    CloseHandle((HANDLE)p->mappingHandle);
  if (p->fileHandle)
    CloseHandle((HANDLE)p->fileHandle);
  p->data = NULL;
  p->capacity = 0;
  p->fileHandle = NULL;
  p->mappingHandle = NULL;
  p->fileBacked = False;
}

void SunpackFileBuffer_Release(CSunpackFileBuffer *p)
{
  if (!p)
    return;
  if (p->fileBacked)
  {
    SunpackFileBuffer_ReleaseWindows(p);
    return;
  }
  if (p->data)
    MidFree(p->data);
  SunpackFileBuffer_Construct(p);
}

static BoolInt SunpackFileBuffer_CreateMapped(CSunpackFileBuffer *p, size_t size)
{
  WCHAR tempPath[MAX_PATH + 1];
  WCHAR tempName[MAX_PATH + 1];
  DWORD pathLen;
  HANDLE file;
  HANDLE mapping;
  void *view;
  LARGE_INTEGER endPos;
  DWORD sparseBytes = 0;
  const UInt64 size64 = (UInt64)size;

  pathLen = GetTempPathW((DWORD)(sizeof(tempPath) / sizeof(tempPath[0])), tempPath);
  if (pathLen == 0 || pathLen >= (DWORD)(sizeof(tempPath) / sizeof(tempPath[0])))
    return False;
  if (!GetTempFileNameW(tempPath, L"spk", 0, tempName))
    return False;

  file = CreateFileW(
      tempName,
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
      NULL);
  if (file == INVALID_HANDLE_VALUE)
  {
    DeleteFileW(tempName);
    return False;
  }

  /* Best effort: sparse backing avoids reserving physical disk clusters for
     untouched portions of a large decoder run. Non-NTFS filesystems may reject
     this request; the mapping remains correct without it. */
  DeviceIoControl(file, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &sparseBytes, NULL);

  endPos.QuadPart = (LONGLONG)size64;
  if (!SetFilePointerEx(file, endPos, NULL, FILE_BEGIN) || !SetEndOfFile(file))
  {
    CloseHandle(file);
    return False;
  }

  mapping = CreateFileMappingW(
      file,
      NULL,
      PAGE_READWRITE,
      (DWORD)(size64 >> 32),
      (DWORD)size64,
      NULL);
  if (!mapping)
  {
    CloseHandle(file);
    return False;
  }

  view = MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size);
  if (!view)
  {
    CloseHandle(mapping);
    CloseHandle(file);
    return False;
  }

  p->data = (Byte *)view;
  p->capacity = size;
  p->fileHandle = file;
  p->mappingHandle = mapping;
  p->fileBacked = True;
  return True;
}

static BoolInt SunpackFileBuffer_MapExisting(CSunpackFileBuffer *p, size_t size)
{
  void *view;
  if (!p->mappingHandle || p->capacity < size)
    return False;
  view = MapViewOfFile((HANDLE)p->mappingHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size);
  if (!view)
    return False;
  p->data = (Byte *)view;
  return True;
}

BoolInt SunpackFileBuffer_Ensure(CSunpackFileBuffer *p, size_t size)
{
  Byte *data;

  if (size == 0)
    size = 1;
  if (p->data && p->capacity >= size)
    return True;
  if (p->fileBacked && p->capacity >= size)
    return SunpackFileBuffer_MapExisting(p, size);

  SunpackFileBuffer_Release(p);

  if (size >= SUNPACK_FILE_BUFFER_THRESHOLD)
  {
    if (SunpackFileBuffer_CreateMapped(p, size))
      return True;
  }

  data = (Byte *)MidAlloc(size);
  if (!data)
    return False;
  p->data = data;
  p->capacity = size;
  p->fileBacked = False;
  return True;
}

void SunpackFileBuffer_Unmap(CSunpackFileBuffer *p)
{
  if (!p || !p->fileBacked || !p->data)
    return;
  UnmapViewOfFile(p->data);
  p->data = NULL;
}

#ifdef Z7_LARGE_PAGES
// #pragma message("Z7_LARGE_PAGES")

#ifdef MEM_LARGE_PAGES
  #define MY_MEM_LARGE_PAGES  MEM_LARGE_PAGES
#else
  #define MY_MEM_LARGE_PAGES  0x20000000
#endif

extern
size_t g_LargePageSize;
size_t g_LargePageSize = 0;
extern
size_t g_LargePageThresholdMin;
size_t g_LargePageThresholdMin = 0;
extern
UInt32 g_LargePageFlags;
UInt32 g_LargePageFlags = 0;

void *BigAlloc(size_t size)
{
  if (size == 0)
    return NULL;

  PRINT_ALLOC("Alloc-Big", g_allocCountBig, size, NULL)

  #ifdef Z7_LARGE_PAGES
  {
    const size_t ps = g_LargePageSize - 1;
    if (ps < (1u << 30) && size > g_LargePageThresholdMin)
    {
      const size_t size2 = (size + ps) & ~ps;
      if (size2 >= size)
      {
        void *p = VirtualAlloc(NULL, size2, MEM_COMMIT | MY_MEM_LARGE_PAGES, PAGE_READWRITE);
        if (p)
        {
          PRINT_ALLOC("Alloc-BM ", g_allocCountMid, size2, p)
          return p;
        }
        if (g_LargePageFlags & Z7_LARGE_PAGES_FLAG_FAIL_STOP)
          return p;
      }
    }
  }
  #endif

  return MidAlloc(size);
}

void BigFree(void *address)
{
  PRINT_FREE("Free-Big", g_allocCountBig, address)
  MidFree(address);
}

#endif // Z7_LARGE_PAGES
#endif // _WIN32

#ifndef _WIN32

void SunpackFileBuffer_Construct(CSunpackFileBuffer *p)
{
  p->data = NULL;
  p->capacity = 0;
  p->fileHandle = NULL;
  p->mappingHandle = NULL;
  p->fileBacked = False;
}

void SunpackFileBuffer_Release(CSunpackFileBuffer *p)
{
  if (!p)
    return;
  if (p->data)
    MidFree(p->data);
  SunpackFileBuffer_Construct(p);
}

BoolInt SunpackFileBuffer_Ensure(CSunpackFileBuffer *p, size_t size)
{
  Byte *data;
  if (size == 0)
    size = 1;
  if (p->data && p->capacity >= size)
    return True;
  SunpackFileBuffer_Release(p);
  data = (Byte *)MidAlloc(size);
  if (!data)
    return False;
  p->data = data;
  p->capacity = size;
  return True;
}

void SunpackFileBuffer_Unmap(CSunpackFileBuffer *p)
{
  UNUSED_VAR(p)
}

#endif


static void *SzAlloc(ISzAllocPtr p, size_t size) { UNUSED_VAR(p)  return MyAlloc(size); }
static void SzFree(ISzAllocPtr p, void *address) { UNUSED_VAR(p)  MyFree(address); }
const ISzAlloc g_Alloc = { SzAlloc, SzFree };

#ifdef _WIN32
static void *SzMidAlloc(ISzAllocPtr p, size_t size) { UNUSED_VAR(p)  return MidAlloc(size); }
static void SzMidFree(ISzAllocPtr p, void *address) { UNUSED_VAR(p)  MidFree(address); }
const ISzAlloc g_MidAlloc = { SzMidAlloc, SzMidFree };
#endif

#if defined(Z7_LARGE_PAGES)
static void *SzBigAlloc(ISzAllocPtr p, size_t size) { UNUSED_VAR(p)  return BigAlloc(size); }
static void SzBigFree(ISzAllocPtr p, void *address) { UNUSED_VAR(p)  BigFree(address); }
const ISzAlloc g_BigAlloc = { SzBigAlloc, SzBigFree };
#endif

#ifndef Z7_ALLOC_NO_OFFSET_ALLOCATOR

#define ADJUST_ALLOC_SIZE 0
/*
#define ADJUST_ALLOC_SIZE (sizeof(void *) - 1)
*/
/*
  Use (ADJUST_ALLOC_SIZE = (sizeof(void *) - 1)), if
     MyAlloc() can return address that is NOT multiple of sizeof(void *).
*/

/*
  uintptr_t : <stdint.h> C99 (optional)
            : unsupported in VS6
*/
typedef
  #ifdef _WIN32
    UINT_PTR
  #elif 1
    uintptr_t
  #else
    ptrdiff_t
  #endif
    MY_uintptr_t;

#if 0 \
    || (defined(__CHERI__) \
    || defined(__SIZEOF_POINTER__) && (__SIZEOF_POINTER__ > 8))
// for 128-bit pointers (cheri):
#define MY_ALIGN_PTR_DOWN(p, align)  \
    ((void *)((char *)(p) - ((size_t)(MY_uintptr_t)(p) & ((align) - 1))))
#else
#define MY_ALIGN_PTR_DOWN(p, align) \
    ((void *)((((MY_uintptr_t)(p)) & ~((MY_uintptr_t)(align) - 1))))
#endif

#endif

#ifndef _WIN32
#include <unistd.h> // for _POSIX_ADVISORY_INFO : for some linux
#if (defined(Z7_ALLOC_NO_OFFSET_ALLOCATOR) \
        || defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200112L) \
        || defined(_POSIX_ADVISORY_INFO) && (_POSIX_ADVISORY_INFO >= 200112L) \
        || defined(__APPLE__) \
        /* || defined(__linux__) */)
  #define USE_posix_memalign
  // #pragma message("USE_posix_memalign")
#endif
#endif

#ifndef USE_posix_memalign
#define MY_ALIGN_PTR_UP_PLUS(p, align) MY_ALIGN_PTR_DOWN(((char *)(p) + (align) + ADJUST_ALLOC_SIZE), align)
#endif

/*
  This posix_memalign() is for test purposes only.