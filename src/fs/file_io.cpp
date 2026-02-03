#include "file_io.h"

void saveFiles(const std::string tickSpectrum, const std::string tickUniverse) {
    FILE *f = fopen(tickSpectrum.c_str(), "wb");
    if (!f) {
        Logger::get()->error("Failed to open spectrum file for writing: {}",
                             tickSpectrum);
    } else {
        if (fwrite(spectrum, sizeof(EntityRecord), SPECTRUM_CAPACITY, f) !=
            SPECTRUM_CAPACITY) {
            Logger::get()->error("Failed to write spectrum file: {}", tickSpectrum);
        }
        fclose(f);
    }

    f = fopen(tickUniverse.c_str(), "wb");
    if (!f) {
        Logger::get()->error("Failed to open universe file for writing: {}",
                             tickUniverse);
    } else {
        if (fwrite(assets, sizeof(AssetRecord), ASSETS_CAPACITY, f) !=
            ASSETS_CAPACITY) {
            Logger::get()->error("Failed to write universe file: {}", tickUniverse);
        }
        fclose(f);
    }
}

void saveState(uint32_t &tracker, uint32_t lastVerified) {
    Logger::get()->info("Saving verified universe/spectrum {} - Do not shutdown",
                        lastVerified);
    std::string tickSpectrum = "spectrum." + std::to_string(lastVerified);
    std::string tickUniverse = "universe." + std::to_string(lastVerified);
    saveFiles(tickSpectrum, tickUniverse);
    db_update_latest_verified_tick(lastVerified);
    tickSpectrum = "spectrum." + std::to_string(tracker);
    tickUniverse = "universe." + std::to_string(tracker);
    if (std::filesystem::exists(tickSpectrum) &&
        std::filesystem::exists(tickUniverse)) {
        std::filesystem::remove(tickSpectrum);
        std::filesystem::remove(tickUniverse);
    }
    Logger::get()->info(
            "Saved checkpoints. Deleted old verified universe/spectrum {}. ",
            lastVerified);
    tracker = lastVerified;
    db_insert_u32("verified_history:" + std::to_string(gCurrentProcessingEpoch),
                  lastVerified);
}

// Small helper to load a fixed-size array from a binary file with uniform
// logging.
bool loadFile(const std::string &path, void *outBuffer,
                     size_t elementSize, size_t elementCount,
                     const char *label) {
    Logger::get()->info("Loading file {}", path);
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) {
        Logger::get()->error("Failed to open {} file: {}", label, path);
        return false;
    }
    size_t readCount = fread(outBuffer, elementSize, elementCount, f);
    fclose(f);
    if (readCount != elementCount) {
        Logger::get()->error("Failed to read {} file. Expected {} records, got {}",
                             label, elementCount, readCount);
        return false;
    }
    return true;
}
