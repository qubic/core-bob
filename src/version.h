
#pragma once

#define BOB_VERSION "1.2.0"

// These will be defined by CMake during build
#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "unknown"
#endif

#ifndef COMPILER_NAME
#define COMPILER_NAME "unknown"
#endif