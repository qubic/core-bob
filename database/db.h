/*
 db.h — Redis persistence API for node data

 Overview
 - Provides a narrow, implementation-agnostic interface for persisting and retrieving
   TickVotes, TickData, transactions, and log events.
 - Encapsulates connection lifecycle management to Redis.

 Keyspace conventions (conceptual)
 - tick_vote:{tick}:{computorIndex}:{hash}        -> binary TickVote
 - tick_data:{tick}:{computorIndex}:{hash}        -> binary TickData
 - transaction:{tick}:{hash}                      -> binary Transaction (or envelope)
 - log:{epoch}:{tick}:{txHash}:{type}:{logId}:{hash} -> binary log content
 - log_range:{tick}:{txId}                        -> from/length pair (per-tx in a tick)
 - db_status                                      -> latest overall tick/epoch, latest event tick/epoch
 - db_status:epoch:{epoch}                        -> per-epoch fields such as latest_log_id, latest_verified_tick

 Binary layout and endianness
 - All structs are written and read as-is (host byte order, little-endian on typical targets). Consumers must
   run on consistent architectures or serialize/deserialize explicitly when crossing boundaries.
 - LogEvent is stored/handled as a packed byte vector with a fixed-size header; see the LogEvent docs below.

 Error handling and return values
 - Functions returning bool: true means success; false means the operation failed or the requested entity was absent.
 - Functions returning integral counts or IDs: negative values indicate error or absence as documented per function.
 - Connection functions may throw std::runtime_error on failures where indicated.

 Concurrency
 - The API is designed to be callable from multiple threads. Actual thread safety depends on the underlying
   Redis client usage in the implementation. If the underlying client is not thread-safe, the implementation
   must provide appropriate synchronization.

 Atomicity
 - Update helpers that state “atomically” must ensure single-writer semantics via Redis-side primitives
   (e.g., Lua scripts, transactions, or WATCH/MULTI/EXEC) so that monotonicity constraints are honored.
*/

#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include <vector>
#include <immintrin.h> // For m256i
#include "structs.h"
#include "Logger.h"
#include "LogEvent.h"
// Forward declaration for the Redis client
namespace sw { namespace redis { class Redis; }}

// Placeholder definitions for constants from structs.h
#define SIGNATURE_SIZE 64
#define NUMBER_OF_TRANSACTIONS_PER_TICK 1024
#define MAX_NUMBER_OF_CONTRACTS 1024
#define WILDCARD "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib"

// ---- Database Interface ----

/**
 * Connects to the Redis server and prepares the DB layer for use.
 *
 * Notes
 * - Safe to call multiple times; subsequent calls are no-ops if already connected.
 *
 * Parameters
 * - connectionString: Redis (or KeyDB) URI. Example: "tcp://127.0.0.1:6379"
 *   Implementation may append connection options (e.g., pool sizing).
 *
 * Return Value
 * - None
 *
 * Throws
 * - std::runtime_error on connection or authentication failure.
 */
void db_connect(const std::string& connectionString);

/**
 * Closes the Redis connection and releases any associated resources.
 *
 * Notes
 * - Safe to call multiple times; it is a no-op if the connection is already closed.
 *
 * Return Value
 * - None
 */
void db_close();

// ---- Insertion Functions ----

/**
 * Inserts a TickVote as a binary blob.
 *
 * Key Format
 * - tick_vote:{tick}:{computorIndex}:{hash}
 *
 * Parameters
 * - vote: The TickVote to persist.
 *
 * Return Value
 * - true on success
 * - false if the write fails or DB is unavailable
 */
bool db_insert_tick_vote(const TickVote& vote);

/**
 * Inserts a TickData as a binary blob.
 *
 * Key Format
 * - tick_data:{tick}:{computorIndex}:{hash}
 *   (Implementations may use simplified or deduplicated keys.)
 *
 * Parameters
 * - data: The TickData to persist.
 *
 * Return Value
 * - true on success
 * - false on write failure or DB unavailable
 */
bool db_insert_tick_data(const TickData& data);

/**
 * Inserts a Transaction payload.
 *
 * Key Format
 * - transaction:{tick}:{hash}
 *   (Implementations may store by hash only.)
 *
 * Parameters
 * - tx: Pointer to a Transaction structure in memory. The stored size commonly
 *       includes the Transaction header/body, input payload (inputSize), and a signature.
 *
 * Return Value
 * - true on success
 * - false on write failure or invalid input
 *
 * Preconditions
 * - tx must be non-null and point to a valid Transaction instance.
 */
bool db_insert_transaction(const Transaction* tx);

/**
 * Inserts a log event payload.
 *
 * Content Layout
 * - Expected to start with a 26-byte packed header (see LogEvent::PackedHeaderSize),
 *   followed by the body.
 *
 * Key Format
 * - log:{epoch}:{tick}:{txHash}:{type}:{logId}:{hash}
 *   (Implementations may normalize to a minimal form.)
 *
 * Parameters
 * - epoch: Epoch of the log event
 * - tick: Tick of the log event
 * - logId: Monotonically increasing log identifier (per producer/epoch)
 * - logSize: Total byte size of the content buffer (header + body)
 * - content: Pointer to the raw content buffer
 *
 * Return Value
 * - true on success
 * - false on write failure or DB unavailable
 */
bool db_insert_log(uint16_t epoch, uint32_t tick, uint64_t logId, int logSize, const uint8_t* content);

/**
 * Inserts the per-tx log-id range for a given tick.
 *
 * Key Format
 * - log_range:{tick}:{txId}
 *   (Implementations may also store a per-tick summary.)
 *
 * Parameters
 * - tick: The tick the ranges belong to
 * - logRange: Struct that contains per-transaction [from, length] ranges within the tick
 *
 * Return Value
 * - true on success
 * - false on write failure or invalid data
 */
bool db_insert_log_range(uint32_t tick, const LogRangesPerTxInTick& logRange);

/**
 * Atomically updates the latest tick and epoch in the global DB status if and only if
 * the provided tick is strictly greater than the stored value.
 *
 * Monotonicity
 * - This helper must enforce monotonic updates (e.g., via Redis-side atomicity).
 *
 * Parameters
 * - tick: Candidate latest tick
 * - epoch: Associated epoch for the tick
 *
 * Return Value
 * - true if updated or if an equal/higher value is already stored
 * - false on failure
 */
bool db_update_latest_tick_and_epoch(uint32_t tick, uint16_t epoch);

// ---- Retrieval Functions ----

/**
 * Reads the latest tick and epoch from the global DB status.
 *
 * Parameters
 * - tick [out]: Receives the stored latest tick
 * - epoch [out]: Receives the stored latest epoch
 *
 * Return Value
 * - true on success (outputs are set)
 * - false on failure or if not present
 */
bool db_get_latest_tick_and_epoch(uint32_t& tick, uint16_t& epoch);

/**
 * Atomically updates the latest logging event tick/epoch in DB status, only if the
 * new tick is strictly greater than the stored event tick.
 *
 * Parameters
 * - tick: Candidate latest log event tick
 * - epoch: Associated epoch of that event
 *
 * Return Value
 * - true if updated or already up-to-date
 * - false on failure
 */
bool db_update_latest_event_tick_and_epoch(uint32_t tick, uint16_t epoch);

/**
 * Reads the latest logging event tick/epoch from DB status.
 *
 * Parameters
 * - tick [out]: Receives the latest log event tick
 * - epoch [out]: Receives the latest log event epoch
 *
 * Return Value
 * - true on success (outputs are set)
 * - false on failure or if fields are absent
 */
bool db_get_latest_event_tick_and_epoch(uint32_t& tick, uint16_t& epoch);

/**
 * Update the latest log id for a specific epoch.
 *
 * Storage
 * - db_status:epoch:{epoch} field latest_log_id
 *
 * Parameters
 * - epoch: Epoch key
 * - logId: Latest log id to store (monotonic)
 *
 * Return Value
 * - true on success
 * - false on failure
 */
bool db_update_latest_log_id(uint16_t epoch, long long logId);

/**
 * Get the latest log id for a specific epoch.
 *
 * Reads
 * - db_status:epoch:{epoch} field latest_log_id
 *
 * Parameters
 * - epoch: Epoch to query
 *
 * Return Value
 * - >= 0 on success (the latest log id)
 * - -1 on error or if the field is absent
 */
long long db_get_latest_log_id(uint16_t epoch);

// Track latest verified tick per epoch

/**
 * Update the latest verified tick for a specific epoch.
 *
 * Storage
 * - db_status:epoch:{epoch} field latest_verified_tick
 *
 * Monotonicity
 * - Only updates if the new tick > stored value.
 *
 * Parameters
 * - tick: Candidate latest verified tick (implicitly associated with current epoch)
 *
 * Return Value
 * - true on success
 * - false on failure
 */
bool db_update_latest_verified_tick(uint32_t tick);

/**
 * Get the latest verified tick for a specific epoch.
 *
 * Reads
 * - db_status:epoch:{epoch} field latest_verified_tick
 *
 * Parameters
 * - None (implementation may infer current epoch)
 *
 * Return Value
 * - >= 0 on success
 * - -1 if not present or on error
 */
long long db_get_latest_verified_tick();

/**
 * Count the number of votes for a given tick.
 *
 * Parameters
 * - tick: Tick for which to count votes
 *
 * Return Value
 * - >= 0 number of votes
 * - -1 on error
 */
long long db_get_tick_vote_count(uint32_t tick);

/**
 * Retrieve a single TickVote for a given tick and computor index.
 *
 * Parameters
 * - tick: Target tick
 * - computorIndex: Index in the computor set (implementation-defined bounds)
 * - vote [out]: Populated with the vote if found
 *
 * Return Value
 * - true if found (vote is populated)
 * - false if not found or on error
 */
bool db_get_tick_vote(uint32_t tick, uint16_t computorIndex, TickVote& vote);

/**
 * Retrieve all TickVotes for a given tick.
 *
 * Parameters
 * - tick: Target tick
 *
 * Return Value
 * - vector of votes (empty on failure or if none exist)
 *   Note: Returned vector may contain fewer than the total computor count if sparse.
 */
std::vector<TickVote> db_get_tick_votes(uint32_t tick);

/**
 * Count the number of transactions for a specific tick.
 *
 * Parameters
 * - tick: Target tick
 *
 * Return Value
 * - >= 0 transaction count
 * - -1 on error
 */
long long db_get_tick_transaction_count(uint32_t tick);

/**
 * Retrieve all log events for a transaction hash.
 *
 * Parameters
 * - txHash: Transaction hash string in canonical representation
 *
 * Return Value
 * - Vector of LogEvent. Empty on failure or if none exist.
 */
std::vector<LogEvent> db_get_logs_by_tx_hash(const std::string& txHash);

/**
 * Retrieve log events within an epoch and tick range [start_tick, end_tick].
 *
 * Parameters
 * - epoch: Epoch to query
 * - start_tick: Inclusive lower bound of tick range
 * - end_tick: Inclusive upper bound of tick range
 *
 * Return Value
 * - Vector of LogEvent. Empty on failure or if none exist.
 */
std::vector<LogEvent> db_get_logs_by_tick_range(uint16_t epoch, uint32_t start_tick, uint32_t end_tick, bool& success);

/**
 * Retrieve TickData for a specific tick.
 *
 * Consistency
 * - Implementations are expected to ensure consistency across redundant copies if stored.
 *
 * Parameters
 * - tick: Target tick to load
 * - data [out]: Receives the loaded TickData on success
 *
 * Return Value
 * - true if found and consistent (data is populated)
 * - false otherwise (absent, inconsistent, or error)
 */
bool db_get_tick_data(uint32_t tick, TickData& data);


/**
 * Get the quorum unix timestamp from votes for a given tick.
 *
 * Parameters:
 * - tick: The tick to get the quorum timestamp for
 *
 * Return Value:
 * - Unix timestamp if a date time has at least 451 votes
 * - 0 if no quorum is reached or on error
 */
uint64_t db_get_quorum_unixtime_from_votes(uint32_t tick);


/**
 * Retrieve the raw binary data of a transaction by
 */

bool db_check_log_range(uint32_t tick);
bool db_try_get_log_ranges(uint32_t tick, LogRangesPerTxInTick &logRange);
bool db_has_tick_data(uint32_t tick);
bool db_try_get_transaction(const std::string& tx_hash, std::vector<uint8_t>& tx_data);
bool db_check_transaction_exist(const std::string& tx_hash);

// ---- Deletion Functions ----
bool db_delete_log_ranges(uint32_t tick);
// Deletes TickData for a specific tick.
// Returns true if the key was removed (or did not exist), false on Redis error.
bool db_delete_tick_data(uint32_t tick);

bool db_delete_tick_vote(uint32_t tick);

// New: get aggregated log range for the whole tick (from key "...:-1")
// Returns true on success; outputs fromLogId and length.
bool db_try_get_log_range_for_tick(uint32_t tick, long long& fromLogId, long long& length);

// Store and get Computors by epoch. Key: "computor:<epoch>"
bool db_insert_computors(const Computors& comps);
bool db_get_computors(uint16_t epoch, Computors& comps);
bool db_log_exists(uint16_t epoch, uint64_t logId);

bool db_try_get_log(uint16_t epoch, uint64_t logId, LogEvent &log);
std::vector<LogEvent> db_try_get_logs(uint16_t epoch, long long logIdStart, long long logIdEnd);

long long db_get_last_indexed_tick();
bool db_update_last_indexed_tick(uint32_t tick);

#pragma pack(push, 1)
struct indexedTxData {
    int32_t  tx_index;
    bool     isExecuted;
    int64_t  from_log_id;
    int64_t  to_log_id;
    uint64_t timestamp;
};
#pragma pack(pop)

static_assert(sizeof(indexedTxData) == (sizeof(int32_t) + sizeof(bool) + sizeof(int64_t) + sizeof(int64_t) + sizeof(uint64_t)),
              "indexedTxData: unexpected padding");

bool db_set_indexed_tx(const char* key,
                       int tx_index,
                       long long from_log_id,
                       long long to_log_id,
                       uint64_t timestamp,
                       bool executed);

bool db_get_indexed_tx(const char* tx_hash,
                       int& tx_index,
                       long long& from_log_id,
                       long long& to_log_id,
                       uint64_t& timestamp,
                       bool& executed);


bool db_add_indexer(const std::string &key, uint32_t tickNumber);

bool db_get_combined_log_range_for_ticks(uint32_t startTick, uint32_t endTick, long long &fromLogId, long long &length);

std::vector<TickVote> db_try_to_get_votes(uint32_t tick);

std::vector<uint32_t> db_search_log(uint32_t scIndex, uint32_t scLogType, uint32_t fromTick, uint32_t toTick,
                                    std::string topic1, std::string topic2, std::string topic3);

bool db_insert_u32(const std::string key, uint32_t value);
bool db_get_u32(const std::string key, uint32_t &value);
bool db_rename(const std::string &key1, const std::string &key2);
bool db_key_exists(const std::string &key);
bool db_update_field(const std::string key, const std::string field, const std::string value);

bool db_try_get_tick_data(uint32_t tick, TickData& data);
bool db_get_end_epoch_log_range(uint16_t epoch, long long &fromLogId, long long &length);





void db_kvrocks_connect(const std::string &connectionString);

// functions for persistant on disk layer
void compressTickAndMoveToKVRocks(uint32_t tick);
bool cleanRawTick(uint32_t fromTick, uint32_t toTick, bool withTransactions);
bool cleanTransactionLogs(uint32_t tick);

bool db_insert_vtick_to_kvrocks(uint32_t tick, const FullTickStruct& fullTick);
bool db_get_vtick_from_kvrocks(uint32_t tick, FullTickStruct& outFullTick);

std::vector<TickVote> db_try_get_tick_vote(uint32_t tick);

void db_kvrocks_close();

bool db_insert_cLogRange_to_kvrocks(uint32_t tick, const LogRangesPerTxInTick& logRange);
bool db_insert_TickLogRange_to_kvrocks(uint32_t tick, long long& logStart, long long& logLen);
bool db_get_cLogRange_from_kvrocks(uint32_t tick, LogRangesPerTxInTick& outLogRange);

bool db_copy_transaction_to_kvrocks(const std::string &tx_hash);

bool db_move_logs_to_kvrocks_by_range(uint16_t epoch, long long fromLogId, long long toLogId);
bool db_delete_transaction(std::string hash);
bool db_delete_logs(uint16_t epoch, long long start, long long end);

bool db_get_endepoch_log_range_info(const uint16_t epoch, long long &start, long long &length, LogRangesPerTxInTick &lr);

bool db_copy(const std::string &key1, const std::string &key2);
bool db_hcopy(const std::string &key1, const std::string &key2);