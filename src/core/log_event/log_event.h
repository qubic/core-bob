#pragma once
#include "src/global_var.h"
#include "src/logger/logger.h"
#include "stdint.h"

#include <json/json.h>
// ---- Data Structures to be Stored ----

struct LogEvent {
    // Packed header layout (little-endian) at the beginning of content:
    //   offset 0..1   epoch (uint16_t)
    //   offset 2..5   tick  (uint32_t)
    //   offset 6..9   size/type combo (uint32_t): lower 24 bits = body size, upper 8 bits = type
    //   offset 10..17 logId (uint64_t)
    //   offset 18..25 logDigest (uint64_t)
    //
    // The body immediately follows the 26-byte header. Use getLogBodyPtr() to access it safely.
private:
    std::vector<uint8_t> content;
public:
    // Returns a pointer to the start of the log body (after the packed header).
    // Requires hasPackedHeader() == true.
    const uint8_t* getLogBodyPtr() const { return content.data() + PackedHeaderSize;}
    uint8_t* getRawPtr(){return content.data();}
    // Replaces internal content with [ptr, ptr+size).
    void updateContent(const uint8_t* ptr, const int size)
    {
        content.resize(size);
        if (size) memcpy(content.data(), ptr, size);
    }
    // Clears the content to an empty vector.
    void clear()
    {
        content.resize(0);
    }
    // Accessors reading from content.data()
    static constexpr size_t PackedHeaderSize = 26;

    bool hasPackedHeader() const {
        return content.size() >= PackedHeaderSize;
    }

    uint16_t getEpoch() const {
        if (!hasPackedHeader()) return 0;
        uint16_t v;
        memcpy(&v, content.data() + 0, sizeof(v));
        return v;
    }

    uint32_t getTick() const {
        if (!hasPackedHeader()) return 0;
        uint32_t v;
        memcpy(&v, content.data() + 2, sizeof(v));
        return v;
    }

    // Returns the 8-bit log type encoded in the header.
    uint32_t getType() const {
        if (!hasPackedHeader()) return 0;
        uint32_t combo;
        memcpy(&combo, content.data() + 6, sizeof(combo));
        return (combo >> 24) & 0xFFu;
    }

    uint32_t isSCType() const {
        auto type = getType();
        return type >= CONTRACT_ERROR_MESSAGE && type <= CONTRACT_DEBUG_MESSAGE;
    }

    template <typename T>
    const T* getStruct() const
    {
        return (const T*)getLogBodyPtr();
    }

    // Returns the 24-bit body size encoded in the header (excluding the 26-byte header).
    uint32_t getLogSize() const {
        if (!hasPackedHeader()) return 0;
        uint32_t combo;
        memcpy(&combo, content.data() + 6, sizeof(combo));
        return combo & 0x00FFFFFFu;
    }

    uint64_t getLogId() const {
        if (!hasPackedHeader()) return 0;
        uint64_t v;
        memcpy(&v, content.data() + 10, sizeof(v));
        return v;
    }

    // Optional per-event integrity value; interpretation depends on producer.
    uint64_t getLogDigest() const {
        if (!hasPackedHeader()) return 0;
        uint64_t v;
        memcpy(&v, content.data() + 18, sizeof(v));
        return v;
    }

    // Validates basic invariants against expected epoch/tick and size consistency.
    bool selfCheck(uint16_t epoch_, bool showErrorLog=true) const
    {
        if (content.size() < 8 + PackedHeaderSize)
        {
            if (showErrorLog) Logger::get()->critical("One Logging Event record is broken, expect >{} get {}", 8+PackedHeaderSize, content.size());
            return false;
        }
        // Basic invariants:
        if (getEpoch() != epoch_) {
            if (showErrorLog) Logger::get()->critical ("One Logging Event record is broken: expect epoch {} get {}", epoch_, getEpoch());
            return false;
        }
        const auto sz = getLogSize();
        if (content.size() != PackedHeaderSize + static_cast<size_t>(sz)) {
            // Allow zero-size content only if header says so.
            if (showErrorLog) Logger::get()->critical("One Logging Event record is broken: expect size {} get {}",
                     PackedHeaderSize + static_cast<size_t>(sz), content.size());
            return sz == 0 && content.size() == PackedHeaderSize;
        }
        // Enforce minimum body size based on known event types to prevent OOB reads later.
        // Returns 0 for unknown types (no extra constraint).
        auto min_needed = expectedMinBodySizeForType(getType());
        if (min_needed > 0 && sz < min_needed) {
            if (showErrorLog) Logger::get()->critical("LogEvent body too small for type {}: need >= {}, got {} (epoch {}, tick {}, logId {})",
                                    getType(), min_needed, sz, getEpoch(), getTick(), getLogId());
            return false;
        }
        uint64_t logDigest = 0;
        KangarooTwelve(this->getLogBodyPtr(), getLogSize(), (uint8_t*)&logDigest, 8);
        if (logDigest != getLogDigest())
        {
            return false;
        }
        return true;
    }

    // Convenience: interprets a special “custom message” event with type=255 and 8-byte payload.
    uint64_t getCustomMessage()
    {
        if (getType() == 255 && getLogSize() == 8 && hasPackedHeader())
        {
            uint64_t r;
            memcpy(&r, content.data() + PackedHeaderSize, 8);
            return r;
        }
        return 0;
    }

    std::string parseToJsonWithExtraData(const TickData& td, const int txIndex) const;
    Json::Value parseToJsonValueWithExtraData(const TickData& td, const int txIndex) const;
    std::string parseToJsonStr() const;
    std::string parseToJsonForEndEpoch(uint32_t endEpochTick, const std::string& timestamp) const;
private:
    Json::Value parseToJson() const;
    // Map known event types to the minimum body size we expect for safe decoding.
    // Unknown types return 0 (no constraint here; callers should still be defensive).
    static constexpr uint32_t expectedMinBodySizeForType(uint32_t t) {
        // Type codes must match the producer’s specification.
        switch (t) {
            case 0:   /* QU_TRANSFER */                          return sizeof(QuTransfer);
            case 8:   /* BURNING */                              return sizeof(Burning);
            case 1:   /* ASSET_ISSUANCE */                       return sizeof(AssetIssuance);
            case 2:   /* ASSET_OWNERSHIP_CHANGE */               return sizeof(AssetOwnershipChange);
            case 3:   /* ASSET_POSSESSION_CHANGE */              return sizeof(AssetPossessionChange);
            case 11:  /* ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE */ return sizeof(AssetOwnershipManagingContractChange);
            case 12:  /* ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE */ return sizeof(AssetPossessionManagingContractChange);
            case 10:  /* SPECTRUM_STATS (not decoded here) */    return 0;
            case 4:   /* CONTRACT_ERROR_MESSAGE */               return 0;
            case 5:   /* CONTRACT_WARNING_MESSAGE */             return 0;
            case 6:   /* CONTRACT_INFORMATION_MESSAGE */         return 0;
            case 7:   /* CONTRACT_DEBUG_MESSAGE */               return 0;
            case 255: /* CUSTOM_MESSAGE */                       return 8; // by convention
            default:                                             return 0;
        }
    }
};