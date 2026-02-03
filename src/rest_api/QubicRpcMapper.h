#pragma once

#include "src/core/m256i.h"
#include "src/core/structs.h"
#include "src/core/log_event/log_event.h"

#include <json/json.h>
#include <string>
#include <vector>

namespace QubicRpc {

// Chain constants
// Derived from keccak256("qubic:mainnet")[-4:] as big-endian uint32
// qubic:mainnet → 788278422 (0x2efc2c96)
// qubic:testnet → 1997427496 (0x770e5328)
// qubic:devnet  → 7948451 (0x007948a3)
// qubic:simnet  → 3266082397 (0xc2ac765d)
constexpr uint64_t CHAIN_ID = 0x2EFC2C96;  // 788278422 - qubic:mainnet

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

// Convert bytes to hex string with 0x prefix
std::string bytesToHex(const uint8_t* data, size_t len);

// Convert hex string (with or without 0x prefix) to bytes
bool hexToBytes(const std::string& hex, uint8_t* out, size_t outLen);

// ============================================================================
// Identity/PublicKey Conversions
// ============================================================================

// m256i (32 bytes) -> 0x + 64 hex chars
std::string publicKeyToHex(const m256i& publicKey);

// m256i -> 60-char Qubic identity
std::string publicKeyToIdentity(const m256i& publicKey);

// 0x + 64 hex -> m256i
bool hexToPublicKey(const std::string& hex, m256i& out);

// 0x + 64 hex -> 60-char Qubic identity string
std::string hexToQubicIdentity(const std::string& hex);

// 60-char Qubic identity -> 0x + 64 hex
std::string qubicIdentityToHex(const std::string& identity);

// ============================================================================
// Number Formatting
// ============================================================================

std::string uint64ToHex(uint64_t value);
std::string uint32ToHex(uint32_t value);
std::string int64ToHex(int64_t value);

uint64_t hexToUint64(const std::string& hex);
uint32_t hexToUint32(const std::string& hex);

// ============================================================================
// Tick Tag Parsing
// ============================================================================

// Parse tick tag: "latest", "earliest", "pending", or numeric tick
// Returns tick number, or -1 if invalid
int64_t parseTickTag(const std::string& tag);

// ============================================================================
// Tick Conversions
// ============================================================================

// Generate tick hash from tick data (signature)
std::string tickToHash(uint32_t tick, const TickData& td);

// Convert TickData to Qubic tick JSON format
Json::Value tickDataToQubicTick(uint32_t tick, const TickData& td,
                                 const std::vector<m256i>& txDigests,
                                 bool includeTransactions);

// ============================================================================
// Transaction Conversions
// ============================================================================

// Convert Qubic transaction to JSON
// @param txHash: the 60-char Qubic transaction hash
// @param includeTick: whether to include tick field (false when nested in tick response)
Json::Value transactionToQubicTx(const Transaction* tx, const std::string& txHash,
                                  uint32_t tick, int txIndex, const TickData& td,
                                  bool includeTick = true);

// Convert transaction + logs to receipt JSON
Json::Value transactionToQubicReceipt(const Transaction* tx, const std::string& txHash,
                                       uint32_t tick, int txIndex, const TickData& td,
                                       const std::vector<LogEvent>& logs, bool executed);

// ============================================================================
// Log Conversions
// ============================================================================

// Convert LogEvent to Qubic log JSON format
Json::Value logEventToQubicLog(const LogEvent& log, const TickData& td,
                                int txIndex, uint64_t logIndexInTick);

// Get human-readable log type name
std::string logTypeName(uint32_t logType);

}  // namespace QubicRpc
