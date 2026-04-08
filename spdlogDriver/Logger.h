#pragma once

#include "spdlog/spdlog.h"
#include <memory>

class Logger {
public:
    static void init(const std::string& level_str);
    inline static std::shared_ptr<spdlog::logger>& get() { return s_logger; }

private:
    static std::shared_ptr<spdlog::logger> s_logger;
};