#include "database/db.h"
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <start_tick> <end_tick> <epoch> [redis_address]" << std::endl;
        std::cerr << "Example: " << argv[0] << " 1000 2000 1 tcp://127.0.0.1:6379" << std::endl;
        return 1;
    }
    Logger::init("info");
    uint32_t startTick = 0;
    uint32_t endTick = 0;
    uint16_t epoch = 0;

    try {
        startTick = std::stoul(argv[1]);
        endTick = std::stoul(argv[2]);
        epoch = static_cast<uint16_t>(std::stoul(argv[3]));
    } catch (...) {
        std::cerr << "Invalid arguments" << std::endl;
        return 1;
    }

    std::string redisAddress = "tcp://127.0.0.1:6379";
    if (argc > 4) {
        redisAddress = argv[4];
    }

    std::cout << "Connecting to KeyDB at " << redisAddress << "..." << std::endl;
    try {
        db_connect(redisAddress);
    } catch (const std::exception& e) {
        std::cerr << "Failed to connect to database: " << e.what() << std::endl;
        return 1;
    }

    long long latestVerifiedTick = db_get_latest_verified_tick();
    if (latestVerifiedTick > startTick) {
        std::cerr << "Error: latest_verified_tick (" << latestVerifiedTick 
                  << ") is greater than start_tick (" << startTick << ")." << std::endl;
        std::cerr << "Aborting operation to prevent data corruption." << std::endl;
        db_close();
        return 1;
    }

    std::cout << "Deleting data from tick " << startTick << " to " << endTick << " (Epoch: " << epoch << ")" << std::endl;

    for (uint32_t tick = startTick; tick <= endTick; ++tick) {
        // 1. Delete Log Events
        // We must retrieve the log range *before* deleting the metadata so we know which log IDs to delete.
        long long fromLogId = -1;
        long long length = -1;

        if (db_try_get_log_range_for_tick(tick, fromLogId, length)) {
            if (fromLogId != -1 && length > 0) {
                // Deletes keys "log:<epoch>:<logId>"
                db_delete_logs(epoch, fromLogId, fromLogId + length - 1);
            }
        }

        // 2. Delete Log Ranges
        // Deletes keys "log_ranges:<tick>" and "tick_log_range:<tick>"
        db_delete_log_ranges(tick);

        // 3. Delete Tick Data
        // Deletes key "tick_data:<tick>"
        db_delete_tick_data(tick);

        // 4. Delete Tick Votes
        // Deletes keys "tick_vote:<tick>:<0..675>"
        db_delete_tick_vote(tick);

        if (tick % 1000 == 0) {
            std::cout << "Processed tick " << tick << std::endl;
        }
    }

    // After deletion, rollback the latest status to start_tick - 1
    if (startTick > 0) {
        uint32_t newLatestTick = startTick - 1;
        std::string val = std::to_string(newLatestTick);
        std::cout << "Updating db_status: latest_event_tick=" << val << ", latest_tick=" << val << std::endl;

        if (!db_update_field("db_status", "latest_event_tick", val)) {
            std::cerr << "Failed to update latest_event_tick" << std::endl;
        }
        if (!db_update_field("db_status", "latest_tick", val)) {
            std::cerr << "Failed to update latest_tick" << std::endl;
        }
    } else {
        std::cout << "start_tick is 0, skipping db_status update." << std::endl;
    }

    db_close();
    std::cout << "Deletion complete." << std::endl;

    return 0;
}