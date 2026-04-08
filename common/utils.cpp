#include "common/utils.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <optional>
#include <sstream>

namespace amoe::utils {

std::string trim(const std::string& value) {
    const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch) != 0; });
    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch) != 0; }).base();
    if (begin >= end) {
        return {};
    }
    return std::string(begin, end);
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

std::vector<std::string> split(const std::string& value, const char delimiter) {
    std::vector<std::string> parts;
    std::stringstream stream(value);
    std::string item;
    while (std::getline(stream, item, delimiter)) {
        parts.push_back(trim(item));
    }
    return parts;
}

std::string join(const std::vector<std::string>& values, const std::string& delimiter) {
    std::ostringstream out;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            out << delimiter;
        }
        out << values[index];
    }
    return out.str();
}

std::optional<int> to_int(const std::string& value) {
    try {
        std::size_t parsed = 0;
        const int result = std::stoi(trim(value), &parsed);
        if (parsed != trim(value).size()) {
            return std::nullopt;
        }
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<double> to_double(const std::string& value) {
    try {
        std::size_t parsed = 0;
        const double result = std::stod(trim(value), &parsed);
        if (parsed != trim(value).size()) {
            return std::nullopt;
        }
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::string format_timestamp(const TimePoint& timestamp) {
    if (timestamp.time_since_epoch().count() == 0) {
        return "n/a";
    }
    const std::time_t time = Clock::to_time_t(timestamp);
    std::tm local_tm {};
#if defined(_WIN32)
    localtime_s(&local_tm, &time);
#else
    localtime_r(&time, &local_tm);
#endif
    std::ostringstream out;
    out << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

std::string format_now() {
    return format_timestamp(Clock::now());
}

std::string format_age(const TimePoint& timestamp) {
    if (timestamp.time_since_epoch().count() == 0) {
        return "unknown";
    }
    const auto delta = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - timestamp).count();
    if (delta < 60) {
        return std::to_string(delta) + " sec ago";
    }
    if (delta < 3600) {
        return std::to_string(delta / 60) + " min ago";
    }
    return std::to_string(delta / 3600) + " hr ago";
}

std::string escape_json(const std::string& value) {
    std::ostringstream out;
    for (const char ch : value) {
        switch (ch) {
        case '\\':
            out << "\\\\";
            break;
        case '"':
            out << "\\\"";
            break;
        case '\n':
            out << "\\n";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\t':
            out << "\\t";
            break;
        default:
            out << ch;
            break;
        }
    }
    return out.str();
}

std::string unescape_json(const std::string& value) {
    std::ostringstream out;
    bool escape = false;
    for (const char ch : value) {
        if (escape) {
            switch (ch) {
            case 'n':
                out << '\n';
                break;
            case 'r':
                out << '\r';
                break;
            case 't':
                out << '\t';
                break;
            case '\\':
                out << '\\';
                break;
            case '"':
                out << '"';
                break;
            default:
                out << ch;
                break;
            }
            escape = false;
        } else if (ch == '\\') {
            escape = true;
        } else {
            out << ch;
        }
    }
    return out.str();
}

std::string format_mb(const double mb) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << mb << " MB";
    return out.str();
}

double kb_to_mb(const std::uint64_t kb) {
    return static_cast<double>(kb) / 1024.0;
}

Mode parse_mode(const std::string& value, const Mode fallback) {
    const auto lowered = to_lower(trim(value));
    if (lowered == "beginner") {
        return Mode::Beginner;
    }
    if (lowered == "advanced") {
        return Mode::Advanced;
    }
    if (lowered == "auto") {
        return Mode::Auto;
    }
    if (lowered == "dryrun" || lowered == "dry-run" || lowered == "dry_run") {
        return Mode::DryRun;
    }
    return fallback;
}

std::optional<ActionType> parse_action(const std::string& value) {
    const auto lowered = to_lower(trim(value));
    if (lowered == "none") {
        return ActionType::None;
    }
    if (lowered == "suspend") {
        return ActionType::Suspend;
    }
    if (lowered == "kill") {
        return ActionType::Kill;
    }
    if (lowered == "lower_priority" || lowered == "lower-priority" || lowered == "lowerpriority") {
        return ActionType::LowerPriority;
    }
    if (lowered == "resume") {
        return ActionType::Resume;
    }
    return std::nullopt;
}

std::optional<AlgorithmType> parse_algorithm(const std::string& value) {
    const auto lowered = to_lower(trim(value));
    if (lowered == "fcfs") {
        return AlgorithmType::FCFS;
    }
    if (lowered == "lru") {
        return AlgorithmType::LRU;
    }
    if (lowered == "optimal") {
        return AlgorithmType::Optimal;
    }
    if (lowered == "hybrid") {
        return AlgorithmType::Hybrid;
    }
    return std::nullopt;
}

std::string repeat(const char value, const std::size_t count) {
    return std::string(count, value);
}

} // namespace amoe::utils
