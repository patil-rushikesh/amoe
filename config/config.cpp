#include "config/config.h"

#include "common/utils.h"

#include <fstream>
#include <sstream>

namespace amoe {

namespace {

void insert_name_set(std::unordered_set<std::string>& target, const std::string& value) {
    for (const auto& item : utils::split(value, ',')) {
        if (!item.empty()) {
            target.insert(item);
        }
    }
}

void insert_pid_set(std::unordered_set<int>& target, const std::string& value) {
    for (const auto& item : utils::split(value, ',')) {
        const auto parsed = utils::to_int(item);
        if (parsed.has_value()) {
            target.insert(*parsed);
        }
    }
}

} // namespace

RuntimeConfig ConfigManager::load(const std::string& path) const {
    RuntimeConfig config;
    std::ifstream input(path);
    if (!input.is_open()) {
        return config;
    }

    std::string section = "general";
    std::string line;
    while (std::getline(input, line)) {
        line = utils::trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        if (line.front() == '[' && line.back() == ']') {
            section = utils::to_lower(utils::trim(line.substr(1, line.size() - 2)));
            continue;
        }

        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }

        const auto key = utils::to_lower(utils::trim(line.substr(0, separator)));
        const auto value = utils::trim(line.substr(separator + 1));

        if (section == "general") {
            if (key == "frames") {
                if (const auto parsed = utils::to_int(value)) {
                    config.frames = static_cast<std::size_t>(*parsed);
                }
            } else if (key == "samples") {
                if (const auto parsed = utils::to_int(value)) {
                    config.samples = static_cast<std::size_t>(*parsed);
                }
            } else if (key == "interval_ms") {
                if (const auto parsed = utils::to_int(value)) {
                    config.interval_ms = static_cast<std::size_t>(*parsed);
                }
            } else if (key == "max_recommendations") {
                if (const auto parsed = utils::to_int(value)) {
                    config.max_recommendations = static_cast<std::size_t>(*parsed);
                }
            } else if (key == "mode") {
                config.mode = utils::parse_mode(value, config.mode);
            } else if (key == "audit_log_path") {
                config.audit_log_path = value;
            } else if (key == "high_memory_threshold") {
                if (const auto parsed = utils::to_double(value)) {
                    config.high_memory_threshold = *parsed;
                }
            } else if (key == "stable_memory_threshold") {
                if (const auto parsed = utils::to_double(value)) {
                    config.stable_memory_threshold = *parsed;
                }
            } else if (key == "burst_cpu_threshold") {
                if (const auto parsed = utils::to_double(value)) {
                    config.burst_cpu_threshold = *parsed;
                }
            } else if (key == "background_cpu_threshold") {
                if (const auto parsed = utils::to_double(value)) {
                    config.background_cpu_threshold = *parsed;
                }
            } else if (key == "minimum_candidate_rss_kb") {
                if (const auto parsed = utils::to_int(value)) {
                    config.minimum_candidate_rss_kb = static_cast<std::uint64_t>(*parsed);
                }
            }
        } else if (section == "hybrid") {
            if (key == "w1_recency") {
                if (const auto parsed = utils::to_double(value)) {
                    config.weights.recency = *parsed;
                }
            } else if (key == "w2_frequency") {
                if (const auto parsed = utils::to_double(value)) {
                    config.weights.frequency = *parsed;
                }
            } else if (key == "w3_memory_usage") {
                if (const auto parsed = utils::to_double(value)) {
                    config.weights.memory_usage = *parsed;
                }
            }
        } else if (section == "protected") {
            if (key == "names") {
                insert_name_set(config.protected_names, value);
            } else if (key == "pids") {
                insert_pid_set(config.protected_pids, value);
            }
        } else if (section == "critical") {
            if (key == "names") {
                config.critical_names.clear();
                for (const auto& item : utils::split(value, ',')) {
                    if (!item.empty()) {
                        config.critical_names.push_back(item);
                    }
                }
            }
        }
    }

    return config;
}

bool ConfigManager::save(const std::string& path, const RuntimeConfig& config, std::string& error) const {
    std::ofstream output(path, std::ios::trunc);
    if (!output.is_open()) {
        error = "unable to open config path for writing";
        return false;
    }

    std::vector<std::string> protected_names(config.protected_names.begin(), config.protected_names.end());
    std::vector<std::string> protected_pids;
    protected_pids.reserve(config.protected_pids.size());
    for (const int pid : config.protected_pids) {
        protected_pids.push_back(std::to_string(pid));
    }

    output << "# Adaptive Memory Optimization Engine configuration\n";
    output << "[general]\n";
    output << "frames=" << config.frames << '\n';
    output << "samples=" << config.samples << '\n';
    output << "interval_ms=" << config.interval_ms << '\n';
    output << "max_recommendations=" << config.max_recommendations << '\n';
    output << "mode=" << utils::to_lower(to_string(config.mode)) << '\n';
    output << "audit_log_path=" << config.audit_log_path << '\n';
    output << "high_memory_threshold=" << config.high_memory_threshold << '\n';
    output << "stable_memory_threshold=" << config.stable_memory_threshold << '\n';
    output << "burst_cpu_threshold=" << config.burst_cpu_threshold << '\n';
    output << "background_cpu_threshold=" << config.background_cpu_threshold << '\n';
    output << "minimum_candidate_rss_kb=" << config.minimum_candidate_rss_kb << "\n\n";

    output << "[hybrid]\n";
    output << "w1_recency=" << config.weights.recency << '\n';
    output << "w2_frequency=" << config.weights.frequency << '\n';
    output << "w3_memory_usage=" << config.weights.memory_usage << "\n\n";

    output << "[protected]\n";
    output << "names=" << utils::join(protected_names, ",") << '\n';
    output << "pids=" << utils::join(protected_pids, ",") << "\n\n";

    output << "[critical]\n";
    output << "names=" << utils::join(config.critical_names, ",") << '\n';

    return true;
}

bool ConfigManager::add_protected_process(const std::string& path,
                                          RuntimeConfig& config,
                                          const ProcessInfo& process,
                                          std::string& error) const {
    if (!process.name.empty()) {
        config.protected_names.insert(process.name);
    }
    if (process.pid > 0) {
        config.protected_pids.insert(process.pid);
    }
    return save(path, config, error);
}

} // namespace amoe
