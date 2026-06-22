#!/usr/bin/env bash
# Build the standalone bob_probe tool. No redis/spdlog/drogon needed —
# it only uses bob's header-only protocol + crypto code.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
echo "Building bob_probe ..."
g++ -std=c++17 -mavx2 -O2 \
    -I common -I . \
    tools/bob_probe.cpp \
    -o bob_probe \
    -lpthread
echo "Done. Binary: $ROOT/bob_probe"
echo "Run it from the repo root:"
echo "  cd $ROOT && ./bob_probe <ip> <port> [options]"
echo "Example: ./bob_probe 65.109.122.174 21841"
