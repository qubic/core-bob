#pragma once
#include <stdint.h>
#include <immintrin.h>
#define SPECTRUM_DEPTH 24 // Defines SPECTRUM_CAPACITY (1 << SPECTRUM_DEPTH)
#define SPECTRUM_CAPACITY (1ULL << SPECTRUM_DEPTH) // Must be 2^N

#define ASSETS_CAPACITY 0x1000000ULL // Must be 2^N
#define ASSETS_DEPTH 24 // Is derived from ASSETS_CAPACITY (=N)

#define GLOBAL_VAR_DECL extern
#define GLOBAL_VAR_INIT(val)
#define ASSERT(x)
#define ACQUIRE(x)
#define RELEASE(x)

// PORTED FROM QUBIC CORE

static void setMem(void* buffer, unsigned long long size, unsigned char value)
{
    memset(buffer, value, size);
}

static void copyMem(void* destination, const void* source, unsigned long long length)
{
    memcpy(destination, source, length);
}

static bool allocatePool(unsigned long long size, void** buffer)
{
    void* ptr = malloc(size);
    if (ptr)
    {
        *buffer = ptr;
        return true;
    }
    return false;
}

static void freePool(void* buffer)
{
    free(buffer);
}

static bool allocPoolWithErrorLog(const wchar_t* name, const unsigned long long size, void** buffer, const int LINE)
{
    *buffer = malloc(size);
    if (*buffer == nullptr)
    {
        printf("Memory allocation failed for %ls on line %u\n", name, LINE);
        return false;
    }

    // Zero out allocated memory
    setMem(*buffer, size, 0);

    return true;
}