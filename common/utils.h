#ifndef AMOE_COMMON_UTILS_H
#define AMOE_COMMON_UTILS_H

#include "common/types.h"

#include <optional>
#include <string>
#include <vector>

namespace amoe::utils {

std::string trim(const std::string& value);
std::string to_lower(std::string value);
std::vector<std::string> split(const std::string& value, char delimiter);
std::string join(const std::vector<std::string>& values, const std::string& delimiter);
std::optional<int> to_int(const std::string& value);
std::optional<double> to_double(const std::string& value);
std::string format_timestamp(const TimePoint& timestamp);
std::string format_now();
std::string format_age(const TimePoint& timestamp);
std::string escape_json(const std::string& value);
std::string unescape_json(const std::string& value);
std::string format_mb(double mb);
double kb_to_mb(std::uint64_t kb);
Mode parse_mode(const std::string& value, Mode fallback);
std::optional<ActionType> parse_action(const std::string& value);
std::optional<AlgorithmType> parse_algorithm(const std::string& value);
std::string repeat(char value, std::size_t count);

} // namespace amoe::utils

#endif
