#pragma once
#include "src/shim.h"
#include "common_def.h"
#define EMPTY 0
#define ISSUANCE 1
#define OWNERSHIP 2
#define POSSESSION 3

#define AMPERE 0
#define CANDELA 1
#define KELVIN 2
#define KILOGRAM 3
#define METER 4
#define MOLE 5
#define SECOND 6

struct AssetRecord
{
    union
    {
        struct
        {
            m256i publicKey;
            unsigned char type;
            char name[7]; // Capital letters + digits
            char numberOfDecimalPlaces;
            char unitOfMeasurement[7]; // Powers of the corresponding SI base units going in alphabetical order
        } issuance;

        static_assert(sizeof(issuance) == 32 + 1 + 7 + 1 + 7, "Something is wrong with the struct size.");

        struct
        {
            m256i publicKey;
            unsigned char type;
            char padding[1];
            unsigned short managingContractIndex;
            unsigned int issuanceIndex;
            long long numberOfShares;
        } ownership;

        static_assert(sizeof(ownership) == 32 + 1 + 1 + 2 + 4 + 8, "Something is wrong with the struct size.");

        struct
        {
            m256i publicKey;
            unsigned char type;
            char padding[1];
            unsigned short managingContractIndex;
            unsigned int ownershipIndex;
            long long numberOfShares;
        } possession;

        static_assert(sizeof(possession) == 32 + 1 + 1 + 2 + 4 + 8, "Something is wrong with the struct size.");

    } varStruct;
};
GLOBAL_VAR_DECL volatile char universeLock GLOBAL_VAR_INIT(0);
static constexpr char CONTRACT_ASSET_UNIT_OF_MEASUREMENT[7] = { 0, 0, 0, 0, 0, 0, 0 };

static constexpr unsigned int NO_ASSET_INDEX = 0xffffffff;

static long long issueAsset(const m256i& issuerPublicKey, const char name[7], char numberOfDecimalPlaces, const char unitOfMeasurement[7], long long numberOfShares, unsigned short managingContractIndex,
                            int* issuanceIndex, int* ownershipIndex, int* possessionIndex)
{
    *issuanceIndex = issuerPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);

    ACQUIRE(universeLock);

    iteration:
    if (assets[*issuanceIndex].varStruct.issuance.type == EMPTY)
    {
        assets[*issuanceIndex].varStruct.issuance.publicKey = issuerPublicKey;
        assets[*issuanceIndex].varStruct.issuance.type = ISSUANCE;
        copyMem(assets[*issuanceIndex].varStruct.issuance.name, name, sizeof(assets[*issuanceIndex].varStruct.issuance.name));
        assets[*issuanceIndex].varStruct.issuance.numberOfDecimalPlaces = numberOfDecimalPlaces;
        copyMem(assets[*issuanceIndex].varStruct.issuance.unitOfMeasurement, unitOfMeasurement, sizeof(assets[*issuanceIndex].varStruct.issuance.unitOfMeasurement));

        *ownershipIndex = (*issuanceIndex + 1) & (ASSETS_CAPACITY - 1);
        iteration2:
        if (assets[*ownershipIndex].varStruct.ownership.type == EMPTY)
        {
            assets[*ownershipIndex].varStruct.ownership.publicKey = issuerPublicKey;
            assets[*ownershipIndex].varStruct.ownership.type = OWNERSHIP;
            assets[*ownershipIndex].varStruct.ownership.managingContractIndex = managingContractIndex;
            assets[*ownershipIndex].varStruct.ownership.issuanceIndex = *issuanceIndex;
            assets[*ownershipIndex].varStruct.ownership.numberOfShares = numberOfShares;

            *possessionIndex = (*ownershipIndex + 1) & (ASSETS_CAPACITY - 1);
            iteration3:
            if (assets[*possessionIndex].varStruct.possession.type == EMPTY)
            {
                assets[*possessionIndex].varStruct.possession.publicKey = issuerPublicKey;
                assets[*possessionIndex].varStruct.possession.type = POSSESSION;
                assets[*possessionIndex].varStruct.possession.managingContractIndex = managingContractIndex;
                assets[*possessionIndex].varStruct.possession.ownershipIndex = *ownershipIndex;
                assets[*possessionIndex].varStruct.possession.numberOfShares = numberOfShares;

                assetChangeFlags[*issuanceIndex >> 6] |= (1ULL << (*issuanceIndex & 63));
                assetChangeFlags[*ownershipIndex >> 6] |= (1ULL << (*ownershipIndex & 63));
                assetChangeFlags[*possessionIndex >> 6] |= (1ULL << (*possessionIndex & 63));
                RELEASE(universeLock);

                return numberOfShares;
            }
            else
            {
                *possessionIndex = (*possessionIndex + 1) & (ASSETS_CAPACITY - 1);

                goto iteration3;
            }
        }
        else
        {
            *ownershipIndex = (*ownershipIndex + 1) & (ASSETS_CAPACITY - 1);

            goto iteration2;
        }
    }
    else
    {
        if (assets[*issuanceIndex].varStruct.issuance.type == ISSUANCE
            && ((*((unsigned long long*)assets[*issuanceIndex].varStruct.issuance.name)) & 0xFFFFFFFFFFFFFF) == ((*((unsigned long long*)name)) & 0xFFFFFFFFFFFFFF)
            && assets[*issuanceIndex].varStruct.issuance.publicKey == issuerPublicKey)
        {
            RELEASE(universeLock);
            return 0;
        }

        *issuanceIndex = (*issuanceIndex + 1) & (ASSETS_CAPACITY - 1);

        goto iteration;
    }
}

static bool transferShareOwnershipAndPossession(int sourceOwnershipIndex, int sourcePossessionIndex, const m256i& destinationPublicKey, long long numberOfShares,
                                                int* destinationOwnershipIndex, int* destinationPossessionIndex,
                                                bool lock)
{

    if (numberOfShares <= 0)
    {
        return false;
    }

    if (lock)
    {
        ACQUIRE(universeLock);
    }

    ASSERT(sourceOwnershipIndex >= 0 && sourceOwnershipIndex < ASSETS_CAPACITY);
    ASSERT(sourcePossessionIndex >= 0 && sourcePossessionIndex < ASSETS_CAPACITY);
    if (assets[sourceOwnershipIndex].varStruct.ownership.type != OWNERSHIP || assets[sourceOwnershipIndex].varStruct.ownership.numberOfShares < numberOfShares
        || assets[sourcePossessionIndex].varStruct.possession.type != POSSESSION || assets[sourcePossessionIndex].varStruct.possession.numberOfShares < numberOfShares
        || assets[sourcePossessionIndex].varStruct.possession.ownershipIndex != sourceOwnershipIndex)
    {
        if (lock)
        {
            RELEASE(universeLock);
        }

        return false;
    }

    // Special case: all-zero destination means burning shares
    if (isZero(destinationPublicKey))
    {
        // Don't allow burning of contract shares
        const unsigned int issuanceIndex = assets[sourceOwnershipIndex].varStruct.ownership.issuanceIndex;
        ASSERT(issuanceIndex < ASSETS_CAPACITY);
        const auto& issuance = assets[issuanceIndex].varStruct.issuance;
        ASSERT(issuance.type == ISSUANCE);
        if (isZero(issuance.publicKey))
        {
            if (lock)
            {
                RELEASE(universeLock);
            }

            return false;
        }

        // Burn by subtracting shares from source records
        assets[sourceOwnershipIndex].varStruct.ownership.numberOfShares -= numberOfShares;
        assets[sourcePossessionIndex].varStruct.possession.numberOfShares -= numberOfShares;
        assetChangeFlags[sourceOwnershipIndex >> 6] |= (1ULL << (sourceOwnershipIndex & 63));
        assetChangeFlags[sourcePossessionIndex >> 6] |= (1ULL << (sourcePossessionIndex & 63));

        if (lock)
        {
            RELEASE(universeLock);
        }

        return true;
    }

    // Default case: transfer shares to destinationPublicKey
    ASSERT(destinationOwnershipIndex != nullptr);
    ASSERT(destinationPossessionIndex != nullptr);
    *destinationOwnershipIndex = destinationPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
    iteration:
    if (assets[*destinationOwnershipIndex].varStruct.ownership.type == EMPTY
        || (assets[*destinationOwnershipIndex].varStruct.ownership.type == OWNERSHIP
            && assets[*destinationOwnershipIndex].varStruct.ownership.managingContractIndex == assets[sourceOwnershipIndex].varStruct.ownership.managingContractIndex
            && assets[*destinationOwnershipIndex].varStruct.ownership.issuanceIndex == assets[sourceOwnershipIndex].varStruct.ownership.issuanceIndex
            && assets[*destinationOwnershipIndex].varStruct.ownership.publicKey == destinationPublicKey))
    {
        assets[sourceOwnershipIndex].varStruct.ownership.numberOfShares -= numberOfShares;

        if (assets[*destinationOwnershipIndex].varStruct.ownership.type == EMPTY)
        {
            assets[*destinationOwnershipIndex].varStruct.ownership.publicKey = destinationPublicKey;
            assets[*destinationOwnershipIndex].varStruct.ownership.type = OWNERSHIP;
            assets[*destinationOwnershipIndex].varStruct.ownership.managingContractIndex = assets[sourceOwnershipIndex].varStruct.ownership.managingContractIndex;
            assets[*destinationOwnershipIndex].varStruct.ownership.issuanceIndex = assets[sourceOwnershipIndex].varStruct.ownership.issuanceIndex;
        }
        assets[*destinationOwnershipIndex].varStruct.ownership.numberOfShares += numberOfShares;

        *destinationPossessionIndex = destinationPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
        iteration2:
        if (assets[*destinationPossessionIndex].varStruct.possession.type == EMPTY
            || (assets[*destinationPossessionIndex].varStruct.possession.type == POSSESSION
                && assets[*destinationPossessionIndex].varStruct.possession.managingContractIndex == assets[sourcePossessionIndex].varStruct.possession.managingContractIndex
                && assets[*destinationPossessionIndex].varStruct.possession.ownershipIndex == *destinationOwnershipIndex
                && assets[*destinationPossessionIndex].varStruct.possession.publicKey == destinationPublicKey))
        {
            assets[sourcePossessionIndex].varStruct.possession.numberOfShares -= numberOfShares;

            if (assets[*destinationPossessionIndex].varStruct.possession.type == EMPTY)
            {
                assets[*destinationPossessionIndex].varStruct.possession.publicKey = destinationPublicKey;
                assets[*destinationPossessionIndex].varStruct.possession.type = POSSESSION;
                assets[*destinationPossessionIndex].varStruct.possession.managingContractIndex = assets[sourcePossessionIndex].varStruct.possession.managingContractIndex;
                assets[*destinationPossessionIndex].varStruct.possession.ownershipIndex = *destinationOwnershipIndex;
            }
            assets[*destinationPossessionIndex].varStruct.possession.numberOfShares += numberOfShares;

            assetChangeFlags[sourceOwnershipIndex >> 6] |= (1ULL << (sourceOwnershipIndex & 63));
            assetChangeFlags[sourcePossessionIndex >> 6] |= (1ULL << (sourcePossessionIndex & 63));
            assetChangeFlags[*destinationOwnershipIndex >> 6] |= (1ULL << (*destinationOwnershipIndex & 63));
            assetChangeFlags[*destinationPossessionIndex >> 6] |= (1ULL << (*destinationPossessionIndex & 63));

            if (lock)
            {
                RELEASE(universeLock);
            }

            return true;
        }
        else
        {
            *destinationPossessionIndex = (*destinationPossessionIndex + 1) & (ASSETS_CAPACITY - 1);

            goto iteration2;
        }
    }
    else
    {
        *destinationOwnershipIndex = (*destinationOwnershipIndex + 1) & (ASSETS_CAPACITY - 1);

        goto iteration;
    }
}

// copy from qpi
static long long transferShareOwnershipAndPossession(unsigned long long assetName, const m256i& issuer, const m256i& owner, const m256i& possessor,
                                                     long long numberOfShares, long long managingContractindex, const m256i& newOwnerAndPossessor)
{
    ACQUIRE(universeLock);

    int issuanceIndex = issuer.m256i_u32[0] & (ASSETS_CAPACITY - 1);
    iteration:
    if (assets[issuanceIndex].varStruct.issuance.type == EMPTY)
    {
        RELEASE(universeLock);

        return -numberOfShares;
    }
    else
    {
        if (assets[issuanceIndex].varStruct.issuance.type == ISSUANCE
            && ((*((unsigned long long*)assets[issuanceIndex].varStruct.issuance.name)) & 0xFFFFFFFFFFFFFF) == assetName
            && assets[issuanceIndex].varStruct.issuance.publicKey == issuer)
        {
            int ownershipIndex = owner.m256i_u32[0] & (ASSETS_CAPACITY - 1);
            iteration2:
            if (assets[ownershipIndex].varStruct.ownership.type == EMPTY)
            {
                RELEASE(universeLock);

                return -numberOfShares;
            }
            else
            {
                if (assets[ownershipIndex].varStruct.ownership.type == OWNERSHIP
                    && assets[ownershipIndex].varStruct.ownership.issuanceIndex == issuanceIndex
                    && assets[ownershipIndex].varStruct.ownership.publicKey == owner
                    && assets[ownershipIndex].varStruct.ownership.managingContractIndex == managingContractindex) // TODO: This condition needs extra attention during refactoring!
                {
                    int possessionIndex = possessor.m256i_u32[0] & (ASSETS_CAPACITY - 1);
                    iteration3:
                    if (assets[possessionIndex].varStruct.possession.type == EMPTY)
                    {
                        RELEASE(universeLock);

                        return -numberOfShares;
                    }
                    else
                    {
                        if (assets[possessionIndex].varStruct.possession.type == POSSESSION
                            && assets[possessionIndex].varStruct.possession.ownershipIndex == ownershipIndex
                            && assets[possessionIndex].varStruct.possession.publicKey == possessor)
                        {
                            if (assets[possessionIndex].varStruct.possession.managingContractIndex == managingContractindex) // TODO: This condition needs extra attention during refactoring!
                            {
                                if (assets[possessionIndex].varStruct.possession.numberOfShares >= numberOfShares)
                                {
                                    int destinationOwnershipIndex, destinationPossessionIndex;
                                    if (!transferShareOwnershipAndPossession(ownershipIndex, possessionIndex, newOwnerAndPossessor, numberOfShares, &destinationOwnershipIndex, &destinationPossessionIndex, false))
                                    {
                                        RELEASE(universeLock);

                                        return -1;
                                    }
                                    else
                                    {
                                        RELEASE(universeLock);

                                        return assets[possessionIndex].varStruct.possession.numberOfShares;
                                    }
                                }
                                else
                                {
                                    RELEASE(universeLock);

                                    return assets[possessionIndex].varStruct.possession.numberOfShares - numberOfShares;
                                }
                            }
                        }
                        else
                        {
                            possessionIndex = (possessionIndex + 1) & (ASSETS_CAPACITY - 1);

                            goto iteration3;
                        }
                    }
                }
                else
                {
                    ownershipIndex = (ownershipIndex + 1) & (ASSETS_CAPACITY - 1);

                    goto iteration2;
                }
            }
        }
        else
        {
            issuanceIndex = (issuanceIndex + 1) & (ASSETS_CAPACITY - 1);

            goto iteration;
        }
    }
    return -1;
}

static bool findIssuerIndex(const m256i issuerPublicKey, const uint64_t name, int* issuanceIndex)
{
    *issuanceIndex = issuerPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
iteration:
    if (assets[*issuanceIndex].varStruct.issuance.type == EMPTY)
    {
        *issuanceIndex = -1; // cannot find
        return false;
    }
    else
    {
        if (assets[*issuanceIndex].varStruct.issuance.type == ISSUANCE
            && (((*((unsigned long long*)assets[*issuanceIndex].varStruct.issuance.name)) & 0xFFFFFFFFFFFFFF) == name)
            && assets[*issuanceIndex].varStruct.issuance.publicKey == issuerPublicKey)
        {
            return true;
        }

        *issuanceIndex = (*issuanceIndex + 1) & (ASSETS_CAPACITY - 1);
        goto iteration;
    }
}

static bool findOwnershipIndex(const int issuanceIndex,
                               const m256i owner,
                               const int managingIndex,
                               int* ownershipIndex)
{
    *ownershipIndex = owner.m256i_u32[0] & (ASSETS_CAPACITY - 1);
    iteration:
    if (assets[*ownershipIndex].varStruct.issuance.type == EMPTY)
    {
        *ownershipIndex = -1; // cannot find
        return false;
    }
    else
    {
        if (assets[*ownershipIndex].varStruct.ownership.type == OWNERSHIP
            && assets[*ownershipIndex].varStruct.ownership.issuanceIndex == issuanceIndex
            && assets[*ownershipIndex].varStruct.ownership.publicKey == owner
            && assets[*ownershipIndex].varStruct.ownership.managingContractIndex == managingIndex)
        {
            return true;
        }

        *ownershipIndex = (*ownershipIndex + 1) & (ASSETS_CAPACITY - 1);
        goto iteration;
    }
}

static bool findPossessionIndex(const int ownershipIndex,
                               const m256i possession,
                               const int managingIndex,
                               int* possessionIndex)
{
    *possessionIndex = possession.m256i_u32[0] & (ASSETS_CAPACITY - 1);
    iteration:
    if (assets[*possessionIndex].varStruct.issuance.type == EMPTY)
    {
        *possessionIndex = -1; // cannot find
        return false;
    }
    else
    {
        if (assets[*possessionIndex].varStruct.possession.type == POSSESSION
            && assets[*possessionIndex].varStruct.possession.ownershipIndex == ownershipIndex
            && assets[*possessionIndex].varStruct.possession.publicKey == possession
            && assets[*possessionIndex].varStruct.possession.managingContractIndex == managingIndex)
        {
            return true;
        }

        *possessionIndex = (*possessionIndex + 1) & (ASSETS_CAPACITY - 1);
        goto iteration;
    }
}

static bool transferShareManagementRights(int sourceOwnershipIndex, int sourcePossessionIndex,
                                          unsigned short destinationOwnershipManagingContractIndex,
                                          unsigned short destinationPossessionManagingContractIndex,
                                          long long numberOfShares,
                                          int* destinationOwnershipIndexPtr, int* destinationPossessionIndexPtr,
                                          bool lock)
{

    if (numberOfShares <= 0)
    {
        return false;
    }

    if (lock)
    {
        ACQUIRE(universeLock);
    }

    if (assets[sourceOwnershipIndex].varStruct.ownership.type != OWNERSHIP || assets[sourceOwnershipIndex].varStruct.ownership.numberOfShares < numberOfShares
        || assets[sourcePossessionIndex].varStruct.possession.type != POSSESSION || assets[sourcePossessionIndex].varStruct.possession.numberOfShares < numberOfShares
        || assets[sourcePossessionIndex].varStruct.possession.ownershipIndex != sourceOwnershipIndex)
    {
        if (lock)
        {
            RELEASE(universeLock);
        }

        return false;
    }

    const m256i& ownershipPublicKey = assets[sourceOwnershipIndex].varStruct.ownership.publicKey;
    const m256i& possessionPublicKey = assets[sourcePossessionIndex].varStruct.possession.publicKey;
    const int issuanceIndex = assets[sourceOwnershipIndex].varStruct.ownership.issuanceIndex;

    int destinationOwnershipIndex = ownershipPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
    iteration:
    if (assets[destinationOwnershipIndex].varStruct.ownership.type == EMPTY
        || (assets[destinationOwnershipIndex].varStruct.ownership.type == OWNERSHIP
            && assets[destinationOwnershipIndex].varStruct.ownership.managingContractIndex == destinationOwnershipManagingContractIndex
            && assets[destinationOwnershipIndex].varStruct.ownership.issuanceIndex == issuanceIndex
            && assets[destinationOwnershipIndex].varStruct.ownership.publicKey == ownershipPublicKey))
    {
        // found empty slot for ownership record or existing record to update
        assets[sourceOwnershipIndex].varStruct.ownership.numberOfShares -= numberOfShares;

        if (assets[destinationOwnershipIndex].varStruct.ownership.type == EMPTY)
        {
            assets[destinationOwnershipIndex].varStruct.ownership.publicKey = ownershipPublicKey;
            assets[destinationOwnershipIndex].varStruct.ownership.type = OWNERSHIP;
            assets[destinationOwnershipIndex].varStruct.ownership.managingContractIndex = destinationOwnershipManagingContractIndex;
            assets[destinationOwnershipIndex].varStruct.ownership.issuanceIndex = issuanceIndex;
        }
        assets[destinationOwnershipIndex].varStruct.ownership.numberOfShares += numberOfShares;

        int destinationPossessionIndex = possessionPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
        iteration2:
        if (assets[destinationPossessionIndex].varStruct.possession.type == EMPTY
            || (assets[destinationPossessionIndex].varStruct.possession.type == POSSESSION
                && assets[destinationPossessionIndex].varStruct.possession.managingContractIndex == destinationPossessionManagingContractIndex
                && assets[destinationPossessionIndex].varStruct.possession.ownershipIndex == destinationOwnershipIndex
                && assets[destinationPossessionIndex].varStruct.possession.publicKey == possessionPublicKey))
        {
            // found empty slot for poss possession or existing record to update
            assets[sourcePossessionIndex].varStruct.possession.numberOfShares -= numberOfShares;

            if (assets[destinationPossessionIndex].varStruct.possession.type == EMPTY)
            {
                assets[destinationPossessionIndex].varStruct.possession.publicKey = possessionPublicKey;
                assets[destinationPossessionIndex].varStruct.possession.type = POSSESSION;
                assets[destinationPossessionIndex].varStruct.possession.managingContractIndex = destinationPossessionManagingContractIndex;
                assets[destinationPossessionIndex].varStruct.possession.ownershipIndex = destinationOwnershipIndex;
            }
            assets[destinationPossessionIndex].varStruct.possession.numberOfShares += numberOfShares;

            assetChangeFlags[sourceOwnershipIndex >> 6] |= (1ULL << (sourceOwnershipIndex & 63));
            assetChangeFlags[sourcePossessionIndex >> 6] |= (1ULL << (sourcePossessionIndex & 63));
            assetChangeFlags[destinationOwnershipIndex >> 6] |= (1ULL << (destinationOwnershipIndex & 63));
            assetChangeFlags[destinationPossessionIndex >> 6] |= (1ULL << (destinationPossessionIndex & 63));

            if (lock)
            {
                RELEASE(universeLock);
            }

            if (destinationOwnershipIndexPtr)
            {
                *destinationOwnershipIndexPtr = destinationOwnershipIndex;
            }
            if (destinationPossessionIndexPtr)
            {
                *destinationPossessionIndexPtr = destinationPossessionIndex;
            }

            return true;
        }
        else
        {
            // try next slot for finding new possession record
            destinationPossessionIndex = (destinationPossessionIndex + 1) & (ASSETS_CAPACITY - 1);

            goto iteration2;
        }
    }
    else
    {
        // try next slot for finding new ownership record
        destinationOwnershipIndex = (destinationOwnershipIndex + 1) & (ASSETS_CAPACITY - 1);

        goto iteration;
    }
}

static void assetsEndEpoch()
{

    ACQUIRE(universeLock);
    std::vector<uint8_t> reorgBuffer(SPECTRUM_CAPACITY * sizeof(AssetRecord));
    // rebuild asset hash map, getting rid of all elements with zero shares
    AssetRecord* reorgAssets = (AssetRecord*)reorgBuffer.data();
    setMem(reorgAssets, ASSETS_CAPACITY * sizeof(AssetRecord), 0);
    for (unsigned int i = 0; i < ASSETS_CAPACITY; i++)
    {
        if (assets[i].varStruct.possession.type == POSSESSION
            && assets[i].varStruct.possession.numberOfShares > 0)
        {
            const unsigned int oldOwnershipIndex = assets[i].varStruct.possession.ownershipIndex;
            const unsigned int oldIssuanceIndex = assets[oldOwnershipIndex].varStruct.ownership.issuanceIndex;
            const m256i& issuerPublicKey = assets[oldIssuanceIndex].varStruct.issuance.publicKey;
            char* name = assets[oldIssuanceIndex].varStruct.issuance.name;
            int issuanceIndex = issuerPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
            iteration2:
            if (reorgAssets[issuanceIndex].varStruct.issuance.type == EMPTY
                || (reorgAssets[issuanceIndex].varStruct.issuance.type == ISSUANCE
                    && ((*((unsigned long long*)reorgAssets[issuanceIndex].varStruct.issuance.name)) & 0xFFFFFFFFFFFFFF) == ((*((unsigned long long*)name)) & 0xFFFFFFFFFFFFFF)
                    && reorgAssets[issuanceIndex].varStruct.issuance.publicKey == issuerPublicKey))
            {
                if (reorgAssets[issuanceIndex].varStruct.issuance.type == EMPTY)
                {
                    copyMem(&reorgAssets[issuanceIndex], &assets[oldIssuanceIndex], sizeof(AssetRecord));
                }

                const m256i& ownerPublicKey = assets[oldOwnershipIndex].varStruct.ownership.publicKey;
                int ownershipIndex = ownerPublicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
                iteration3:
                if (reorgAssets[ownershipIndex].varStruct.ownership.type == EMPTY
                    || (reorgAssets[ownershipIndex].varStruct.ownership.type == OWNERSHIP
                        && reorgAssets[ownershipIndex].varStruct.ownership.managingContractIndex == assets[oldOwnershipIndex].varStruct.ownership.managingContractIndex
                        && reorgAssets[ownershipIndex].varStruct.ownership.issuanceIndex == issuanceIndex
                        && reorgAssets[ownershipIndex].varStruct.ownership.publicKey == ownerPublicKey))
                {
                    if (reorgAssets[ownershipIndex].varStruct.ownership.type == EMPTY)
                    {
                        reorgAssets[ownershipIndex].varStruct.ownership.publicKey = ownerPublicKey;
                        reorgAssets[ownershipIndex].varStruct.ownership.type = OWNERSHIP;
                        reorgAssets[ownershipIndex].varStruct.ownership.managingContractIndex = assets[oldOwnershipIndex].varStruct.ownership.managingContractIndex;
                        reorgAssets[ownershipIndex].varStruct.ownership.issuanceIndex = issuanceIndex;
                    }
                    reorgAssets[ownershipIndex].varStruct.ownership.numberOfShares += assets[i].varStruct.possession.numberOfShares;

                    int possessionIndex = assets[i].varStruct.possession.publicKey.m256i_u32[0] & (ASSETS_CAPACITY - 1);
                    iteration4:
                    if (reorgAssets[possessionIndex].varStruct.possession.type == EMPTY
                        || (reorgAssets[possessionIndex].varStruct.possession.type == POSSESSION
                            && reorgAssets[possessionIndex].varStruct.possession.managingContractIndex == assets[i].varStruct.possession.managingContractIndex
                            && reorgAssets[possessionIndex].varStruct.possession.ownershipIndex == ownershipIndex
                            && reorgAssets[possessionIndex].varStruct.possession.publicKey == assets[i].varStruct.possession.publicKey))
                    {
                        if (reorgAssets[possessionIndex].varStruct.possession.type == EMPTY)
                        {
                            reorgAssets[possessionIndex].varStruct.possession.publicKey = assets[i].varStruct.possession.publicKey;
                            reorgAssets[possessionIndex].varStruct.possession.type = POSSESSION;
                            reorgAssets[possessionIndex].varStruct.possession.managingContractIndex = assets[i].varStruct.possession.managingContractIndex;
                            reorgAssets[possessionIndex].varStruct.possession.ownershipIndex = ownershipIndex;
                        }
                        reorgAssets[possessionIndex].varStruct.possession.numberOfShares += assets[i].varStruct.possession.numberOfShares;
                    }
                    else
                    {
                        possessionIndex = (possessionIndex + 1) & (ASSETS_CAPACITY - 1);

                        goto iteration4;
                    }
                }
                else
                {
                    ownershipIndex = (ownershipIndex + 1) & (ASSETS_CAPACITY - 1);

                    goto iteration3;
                }
            }
            else
            {
                issuanceIndex = (issuanceIndex + 1) & (ASSETS_CAPACITY - 1);

                goto iteration2;
            }
        }
    }
    copyMem(assets, reorgAssets, ASSETS_CAPACITY * sizeof(AssetRecord));

    setMem(assetChangeFlags, ASSETS_CAPACITY / 8, 0xFF);

    RELEASE(universeLock);
}

static void getAssetBalances(const m256i pk, const m256i issuer, const uint64_t assetName, const uint32_t manageSCIndex,
                      long long& ownershipBalance, long long& possessionBalance)
{
    ownershipBalance = -1;
    possessionBalance = -1;
    int issuanceIndex = -1;
    findIssuerIndex(issuer, assetName, &issuanceIndex);
    if (issuanceIndex == -1) return;

    int ownershipIndex = -1;
    findOwnershipIndex(issuanceIndex, pk, manageSCIndex, &ownershipIndex);
    if (ownershipIndex == -1) return;
    ownershipBalance = assets[ownershipIndex].varStruct.ownership.numberOfShares;

    int possIndex = -1;
    findPossessionIndex(ownershipIndex, pk, manageSCIndex, &possIndex);
    if (possIndex == -1) return;
    possessionBalance = assets[possIndex].varStruct.possession.numberOfShares;
    return;
}