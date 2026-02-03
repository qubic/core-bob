// Profiler.h
#pragma once
#include <cstdint>
#include <chrono>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <cstdio>

// Optional Logger integration if available
#ifdef __has_include
#  if __has_include("Logger.h")
#    include "Logger.h"
#    define PROFLOG_INFO(fmt, ...) Logger::get()->info(fmt, ##__VA_ARGS__)
#    define PROFLOG_WARN(fmt, ...) Logger::get()->warn(fmt, ##__VA_ARGS__)
#  else
#    define PROFLOG_INFO(fmt, ...) do { } while(0)
#    define PROFLOG_WARN(fmt, ...) do { } while(0)
#  endif
#else
#  define PROFLOG_INFO(fmt, ...) do { } while(0)
#  define PROFLOG_WARN(fmt, ...) do { } while(0)
#endif

class ProfilerRegistry {
public:
    static ProfilerRegistry& instance() {
        static ProfilerRegistry inst;
        return inst;
    }

    void addSample(const char* name, uint64_t ns) {
        // Fast path with double-checked lookup
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto& s = stats_[name];
            s.total_ns += ns;
            s.count += 1;
            if (ns > s.max_ns) s.max_ns = ns;
        }
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.clear();
    }

    void printSummary() {
        // Snapshot under lock
        std::vector<Entry> snapshot;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            snapshot.reserve(stats_.size());
            for (const auto& kv : stats_) {
                snapshot.push_back({kv.first, kv.second.total_ns, kv.second.count, kv.second.max_ns});
            }
        }

        // Sort by total time desc
        std::sort(snapshot.begin(), snapshot.end(),
                  [](const Entry& a, const Entry& b){ return a.total_ns > b.total_ns; });

        // Build a compact textual report
        std::string report;
        report += "\n=== Profiling Summary ===\n";
        report += "section,total_ms,count,avg_us,max_us\n";
        char line[256];
        for (const auto& e : snapshot) {
            double total_ms = e.total_ns / 1e6;
            double avg_us = (e.count ? (double(e.total_ns) / e.count) / 1e3 : 0.0);
            double max_us = e.max_ns / 1e3;
            int n = std::snprintf(line, sizeof(line), "%s,%.3f,%llu,%.3f,%.3f\n",
                                  e.name.c_str(),
                                  total_ms,
                                  static_cast<unsigned long long>(e.count),
                                  avg_us,
                                  max_us);
            if (n > 0) report.append(line, line + std::min<int>(n, sizeof(line)));
        }
        report += "=========================\n";

        // Try logger first, also dump to stderr to ensure visibility on Ctrl+C
        PROFLOG_INFO("{}", report);
        std::fwrite(report.data(), 1, report.size(), stderr);
        std::fflush(stderr);
    }

private:
    struct Stats {
        uint64_t total_ns{0};
        uint64_t count{0};
        uint64_t max_ns{0};
    };
    struct Entry {
        std::string name;
        uint64_t total_ns;
        uint64_t count;
        uint64_t max_ns;
    };

    std::mutex mutex_;
    std::unordered_map<std::string, Stats> stats_;
};

class ScopedProfiler {
public:
    explicit ScopedProfiler(const char* name)
            : name_(name),
              start_(std::chrono::high_resolution_clock::now()) {}

    ~ScopedProfiler() {
        auto end = std::chrono::high_resolution_clock::now();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_).count();
        ProfilerRegistry::instance().addSample(name_, static_cast<uint64_t>(ns));
    }

private:
    const char* name_;
    std::chrono::high_resolution_clock::time_point start_;
};

// Convenience macro for scoping
#define PROFILE_SCOPE(name_literal) ScopedProfiler _prof_scope_##__LINE__(name_literal)