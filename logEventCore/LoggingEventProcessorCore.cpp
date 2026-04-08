#include "LoggingEventProcessorCore.h"
#include "Entity.h"
#include "Asset.h"
void processQuTransfer(const QuTransfer& qt, uint32_t tick)
{
    auto src_idx = spectrumIndex(qt.sourcePublicKey);
    if (src_idx != -1)
    {
        if (!decreaseEnergy(src_idx, qt.amount, tick))
        {
            Logger::get()->critical("QUs transfer: Failed to decrease energy");
        }
    }
    else
    {
        if (qt.sourcePublicKey != m256i::zero()){
            Logger::get()->critical("QUs transfer has invalid source index");
        }
    }
    increaseEnergy(qt.destinationPublicKey, qt.amount, tick);
}

void processQuTransfer(LogEvent& le)
{
    QuTransfer qt;
    memcpy((void*)&qt, le.getLogBodyPtr(), sizeof(QuTransfer));
    processQuTransfer(qt, le.getTick());
}

void processQuBurn(LogEvent& le)
{
    Burning b;
    memcpy((void*)&b, le.getLogBodyPtr(), sizeof(Burning));
    auto src_idx = spectrumIndex(b.sourcePublicKey);
    if (src_idx != -1) decreaseEnergy(src_idx, b.amount, le.getTick());
}

void processIssueAsset(LogEvent& le)
{
    AssetIssuance ai;
    memcpy((void*)&ai, le.getLogBodyPtr(), sizeof(AssetIssuance));
    int issuanceIndex, ownershipIndex, possessionIndex;
    issueAsset(ai.issuerPublicKey, ai.name, ai.numberOfDecimalPlaces, ai.unitOfMeasurement, ai.numberOfShares, ai.managingContractIndex,
               &issuanceIndex, &ownershipIndex, &possessionIndex);
}



bool processDistributeDividends(std::vector<LogEvent>& vle)
{
    if (vle.size() == 0) return true;
    // sanity check
    for (auto& le : vle)
    {
        if (le.getType() != QU_TRANSFER) return false;
    }
    QuTransfer qt;
    memcpy((void*)&qt, vle[0].getLogBodyPtr(), sizeof(QuTransfer));
    auto src_id = qt.sourcePublicKey;
    long long total = 0;
    for (auto& le : vle)
    {
        QuTransfer qt1;
        memcpy((void*)&qt1, le.getLogBodyPtr(), sizeof(QuTransfer));
        if (qt1.sourcePublicKey != qt.sourcePublicKey) return false;
        total += qt1.amount;
    }
    auto src_idx = spectrumIndex(qt.sourcePublicKey);
    if (src_idx == -1) return false;
    decreaseEnergy(src_idx, total, vle[0].getTick());
    for (auto& le : vle)
    {
        QuTransfer qt1;
        memcpy((void*)&qt1, le.getLogBodyPtr(), sizeof(QuTransfer));
        increaseEnergy(qt1.destinationPublicKey, qt1.amount, vle[0].getTick());
    }
    return true;
}


// this is currently go with a pair Possession & Ownership
// need to update when the core changes ie: only transfer either Possession or Ownership
void processChangeOwnershipAndPossession(LogEvent& le0, LogEvent& le1)
{
    // sanity check
    bool valid = true;
    valid &= ((le0.getType() == ASSET_OWNERSHIP_CHANGE) && (le1.getType() == ASSET_POSSESSION_CHANGE)) || ((le1.getType() == ASSET_OWNERSHIP_CHANGE) && (le0.getType() == ASSET_POSSESSION_CHANGE));
    if (!valid)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    LogEvent ownership, possession;
    if (le0.getType() == ASSET_OWNERSHIP_CHANGE)
    {
        ownership = le0;
        possession = le1;
    }
    else
    {
        ownership = le1;
        possession = le0;
    }
    AssetOwnershipChange aoc{};
    AssetPossessionChange apc{};
    memcpy((void*)&aoc, ownership.getLogBodyPtr(), sizeof(AssetOwnershipChange));
    memcpy((void*)&apc, possession.getLogBodyPtr(), sizeof(AssetPossessionChange));
    if (memcmp(&aoc, &apc, sizeof(AssetOwnershipChange)) != 0)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    uint64_t assetName = 0;
    memcpy((void*)&assetName, aoc.name, 7);
    transferShareOwnershipAndPossession(assetName, aoc.issuerPublicKey, aoc.sourcePublicKey, aoc.sourcePublicKey, aoc.numberOfShares, aoc.managingContractIndex, aoc.destinationPublicKey);
}

// this is currently go with a pair Possession & Ownership
// need to update when the core changes ie: only transfer either Possession or Ownership
void processChangeManagingContract(LogEvent& le0, LogEvent& le1)
{
    // sanity check
    bool valid = true;
    valid &= ((le0.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE) && (le1.getType() == ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE))
            || ((le1.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE) && (le0.getType() == ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE));
    if (!valid)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    LogEvent ownership, possession;
    if (le0.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE)
    {
        ownership = le0;
        possession = le1;
    }
    else
    {
        ownership = le1;
        possession = le0;
    }
    AssetOwnershipManagingContractChange omcc{};
    AssetPossessionManagingContractChange pmcc{};
    memcpy((void*)&omcc, ownership.getLogBodyPtr(), sizeof(AssetOwnershipManagingContractChange));
    memcpy((void*)&pmcc, possession.getLogBodyPtr(), sizeof(AssetPossessionManagingContractChange));
    if (omcc.ownershipPublicKey != pmcc.ownershipPublicKey ||
            (memcmp(omcc.assetName, pmcc.assetName, 7) != 0) ||
            (omcc.numberOfShares != pmcc.numberOfShares) ||
            (omcc.sourceContractIndex != pmcc.sourceContractIndex) ||
            (omcc.destinationContractIndex != pmcc.destinationContractIndex)
        )
    {
        Logger::get()->error("Invalid pair Possession or Ownership in transfering management rights");
        exit(1);
    }
    uint64_t assetName = 0;
    memcpy((void*)&assetName, omcc.assetName, 7);
    long long nshare = omcc.numberOfShares;
    auto issuer = omcc.issuerPublicKey;
    auto owner = omcc.ownershipPublicKey;
    auto poss = pmcc.possessionPublicKey;
    auto src_id = omcc.sourceContractIndex;
    auto dst_id = omcc.destinationContractIndex;
    int issuanceIndex, ownershipIndex, possessionIndex;
    findIssuerIndex(issuer, assetName, &issuanceIndex);
    findOwnershipIndex(issuanceIndex, owner, src_id, &ownershipIndex);
    findPossessionIndex(ownershipIndex, poss, src_id, &possessionIndex);
    int destinationOwnershipIndexPtr, destinationPossessionIndexPtr;
    if (!transferShareManagementRights(ownershipIndex, possessionIndex, dst_id, dst_id, nshare,
                                  &destinationOwnershipIndexPtr, &destinationPossessionIndexPtr, false))
    {
        Logger::get()->error("Failed to transfer management rights");
        exit(1);
    }
}



static m256i qpi_next_id(const m256i& currentId)
{
    int index = spectrumIndex(currentId);
    while (++index < SPECTRUM_CAPACITY)
    {
        const m256i& nextId = spectrum[index].publicKey;
        if (!isZero(nextId))
        {
            return nextId;
        }
    }

    return m256i::zero();
}

static m256i qpi_prev_id(const m256i& currentId)
{
    int index = spectrumIndex(currentId);
    while (--index >= 0)
    {
        const m256i& prevId = spectrum[index].publicKey;
        if (!isZero(prevId))
        {
            return prevId;
        }
    }

    return m256i::zero();
}

bool processSendToManyBenchmark(LogEvent& le)
{
    struct QUTILSendToManyBenchmarkLog
    {
        uint32_t contractId; // to distinguish bw SCs
        uint32_t logType;
        m256i startId;
        int64_t dstCount;
        int64_t numTransfersEach;
    };
    auto s = (QUTILSendToManyBenchmarkLog*)le.getLogBodyPtr();
    struct
    {
        int64_t dstCount;
        int64_t total;
    } output;
    struct
    {
        int64_t dstCount;
        int64_t numTransfersEach;
    } input;
    struct
    {
        m256i currentId;
        uint64_t useNext;
        int t;
    } locals;
    memset(&output, 0, sizeof(output));
    memset(&input, 0, sizeof(input));
    memset(&locals, 0, sizeof(locals));

    input.dstCount = s->dstCount;
    input.numTransfersEach = s->numTransfersEach;

    locals.currentId = s->startId;
    locals.useNext = 1;

    while (output.dstCount < input.dstCount)
    {
        if (locals.useNext == 1)
            locals.currentId = qpi_next_id(locals.currentId);
        else
            locals.currentId = qpi_prev_id(locals.currentId);
        if (locals.currentId == m256i::zero())
        {
            locals.currentId = s->startId;
            locals.useNext = 1 - locals.useNext;
            continue;
        }

        output.dstCount++;
        for (locals.t = 0; locals.t < input.numTransfersEach; locals.t++)
        {
            //qpi.transfer(locals.currentId, 1);
            // simulate this with QU_TRANSFER qt
            QuTransfer qt{};
            qt.sourcePublicKey = m256i(4,0,0,0);
            qt.destinationPublicKey = locals.currentId;
            qt.amount = 1;
            processQuTransfer(qt, le.getTick());
            output.total += 1;
        }
    }
    return true;
}