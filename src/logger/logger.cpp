#include "logger.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <map>
#include <vector>

// Define the static member
std::shared_ptr<spdlog::logger> Logger::s_logger;

// Updated to accept a log level string
void Logger::init(const std::string& level_str) {
    // Sink 1: A colorized console sink
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_pattern("%^[%Y-%m-%d %H:%M:%S.%e] [%l] [%s:%#] %v%$");

    // Sink 2: A rotating file sink
    size_t max_size = 1024 * 1024 * 100;
    size_t max_files = 5;
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("bob.log", max_size, max_files);
    file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%s:%#] %v");

    // Create a logger with both sinks
    std::vector<spdlog::sink_ptr> sinks { console_sink, file_sink };
    s_logger = std::make_shared<spdlog::logger>("bob", begin(sinks), end(sinks));

    spdlog::register_logger(s_logger);

    // --- SET LOG LEVEL FROM STRING ---
    s_logger->set_level(spdlog::level::from_str(level_str));
    s_logger->flush_on(spdlog::level::from_str(level_str));

    s_logger->info("Logger initialized with level: {}", level_str);
}