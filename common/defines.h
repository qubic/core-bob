#include "commonFunctions.h"

// Canonical (post-cutover) max transactions per tick.
// Core raised this from 1024 to 4096 starting at epoch 214 (2026-05-20).
#define NUMBER_OF_TRANSACTIONS_PER_TICK 4096

// Pre-epoch-214 wire / on-disk layout. Bob keeps the legacy size so it can
// read historical ticks (stored in keydb/kvrocks under the old layout) and
// receive legacy-format tick packets that may still arrive during catch-up.
#define LEGACY_NUMBER_OF_TRANSACTIONS_PER_TICK 1024

// First epoch where core uses the 4096-slot tick layout. Ticks in earlier
// epochs are signed/serialized using the legacy 1024-slot layout.
#define EPOCH_FIRST_4096_TX_PER_TICK 214

#define NUMBER_OF_SPECIAL_EVENT_PER_TICK 6
#define SIGNATURE_SIZE 64
#define SPECTRUM_DEPTH 24 // Is derived from SPECTRUM_CAPACITY (=N)
#define ASSETS_DEPTH 24 // Is derived from ASSETS_CAPACITY (=N)
#define NUMBER_OF_COMPUTORS 676
#define MAX_NUMBER_OF_CONTRACTS 1024
#define REQUEST_TICK_DATA 16
#define BROADCAST_TRANSACTION 24
#define REQUEST_CURRENT_TICK_INFO 27
#define RESPOND_CURRENT_TICK_INFO 28
#define REQUEST_TICK_TRANSACTIONS 29
#define REQUEST_COMPUTOR_LIST 11
#define RESPOND_COMPUTOR_LIST 2
#define BROADCAST_TICK_VOTE 3

#define SC_INITIALIZE_TX (NUMBER_OF_TRANSACTIONS_PER_TICK + 0)
#define SC_BEGIN_EPOCH_TX (NUMBER_OF_TRANSACTIONS_PER_TICK + 1)
#define SC_BEGIN_TICK_TX (NUMBER_OF_TRANSACTIONS_PER_TICK + 2)
#define SC_END_TICK_TX (NUMBER_OF_TRANSACTIONS_PER_TICK + 3)
#define SC_END_EPOCH_TX (NUMBER_OF_TRANSACTIONS_PER_TICK + 4)
#define SC_NOTIFICATION_TX (NUMBER_OF_TRANSACTIONS_PER_TICK + 5)

// Signing difficulty
#define TARGET_TICK_VOTE_SIGNATURE 0x00095CBEU // around 7000 signing operations per ID