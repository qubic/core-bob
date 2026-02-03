#pragma once

#define SAVE_PERIOD 1000

#include "src/database/db.h"
#include "src/core/asset.h"
#include "src/core/entity.h"

#include <filesystem>
#include <string>

void saveFiles(const std::string tickSpectrum, const std::string tickUniverse);

void saveState(uint32_t &tracker, uint32_t lastVerified);

// Small helper to load a fixed-size array from a binary file with uniform
// logging.
bool loadFile(const std::string &path, void *outBuffer,
                     size_t elementSize, size_t elementCount,
                     const char *label);