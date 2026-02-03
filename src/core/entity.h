#pragma once
#include "src/shim.h"
#include "common_def.h"
static char spectrumLock;
struct EntityRecord
{
    m256i publicKey;
    long long incomingAmount, outgoingAmount;

    // Numbers of transfers. These may overflow for entities with high traffic, such as Qx.
    unsigned int numberOfIncomingTransfers, numberOfOutgoingTransfers;

    unsigned int latestIncomingTransferTick, latestOutgoingTransferTick;
};

static_assert(sizeof(EntityRecord) == 32 + 2 * 8 + 2 * 4 + 2 * 4, "Something is wrong with the struct size.");

// This should to be optimized if used in non-debugging context (using unsigned long long comparison as much as possible)
static inline bool isZero(const void* ptr, unsigned long long size)
{
    const char* cPtr = (const char*)ptr;
    for (unsigned long long i = 0; i < size; ++i)
    {
        if (cPtr[i] != 0)
            return false;
    }
    return true;
}

static long long energy(const int index)
{
    return spectrum[index].incomingAmount - spectrum[index].outgoingAmount;
}

// Increase balance of entity.
static void increaseEnergy(const m256i& publicKey, long long amount, uint32_t tick)
{
    if (!isZero((uint8_t*)&publicKey, 32) && amount >= 0)
    {
        unsigned int index = publicKey.m256i_u32[0] & (SPECTRUM_CAPACITY - 1);

        iteration:
        if (spectrum[index].publicKey == publicKey)
        {
            spectrum[index].incomingAmount += amount;
            spectrum[index].numberOfIncomingTransfers++;
            spectrum[index].latestIncomingTransferTick = tick;
        }
        else
        {
            if (isZero(spectrum[index].publicKey))
            {
                spectrum[index].publicKey = publicKey;
                spectrum[index].incomingAmount = amount;
                spectrum[index].numberOfIncomingTransfers = 1;
                spectrum[index].latestIncomingTransferTick = tick;
            }
            else
            {
                index = (index + 1) & (SPECTRUM_CAPACITY - 1);
                goto iteration;
            }
        }
    }
}

// Decrease balance of entity if it is high enough. Does NOT check if index is valid.
static bool decreaseEnergy(const int index, long long amount, uint32_t tick)
{
    if (amount >= 0)
    {
        if (energy(index) >= amount)
        {
            spectrum[index].outgoingAmount += amount;
            spectrum[index].numberOfOutgoingTransfers++;
            spectrum[index].latestOutgoingTransferTick = tick;
            return true;
        }
    }

    return false;
}

static int spectrumIndex(const m256i& publicKey)
{
    if (isZero(publicKey))
    {
        return -1;
    }

    unsigned int index = publicKey.m256i_u32[0] & (SPECTRUM_CAPACITY - 1);

    ACQUIRE(spectrumLock);

    iteration:
    if (spectrum[index].publicKey == publicKey)
    {
        RELEASE(spectrumLock);

        return index;
    }
    else
    {
        if (isZero(spectrum[index].publicKey))
        {
            RELEASE(spectrumLock);

            return -1;
        }
        else
        {
            index = (index + 1) & (SPECTRUM_CAPACITY - 1);

            goto iteration;
        }
    }
}

static void reorganizeSpectrum()
{

    std::vector<uint8_t> reorgBuffer(SPECTRUM_CAPACITY * sizeof(EntityRecord));

    EntityRecord* reorgSpectrum = (EntityRecord*)reorgBuffer.data();
    setMem(reorgSpectrum, SPECTRUM_CAPACITY * sizeof(EntityRecord), 0);
    for (unsigned int i = 0; i < SPECTRUM_CAPACITY; i++)
    {
        if (spectrum[i].incomingAmount - spectrum[i].outgoingAmount)
        {
            unsigned int index = spectrum[i].publicKey.m256i_u32[0] & (SPECTRUM_CAPACITY - 1);

            iteration:
            if (isZero(reorgSpectrum[index].publicKey))
            {
                copyMem(&reorgSpectrum[index], &spectrum[i], sizeof(EntityRecord));
            }
            else
            {
                index = (index + 1) & (SPECTRUM_CAPACITY - 1);

                goto iteration;
            }
        }
    }
    copyMem(spectrum, reorgSpectrum, SPECTRUM_CAPACITY * sizeof(EntityRecord));
}