#pragma once
#include <cstdio>

enum class LogLevel { ALL = 0, VERBOSE = 1, INFO = 2 };

inline LogLevel g_logLevel = LogLevel::INFO;

#define LOG_ALL(fmt, ...)     do { if (LogLevel::ALL     >= g_logLevel) printf(fmt, ##__VA_ARGS__); } while (0)
#define LOG_VERBOSE(fmt, ...) do { if (LogLevel::VERBOSE >= g_logLevel) printf(fmt, ##__VA_ARGS__); } while (0)
#define LOG_INFO(fmt, ...)    do { if (LogLevel::INFO    >= g_logLevel) printf(fmt, ##__VA_ARGS__); } while (0)
