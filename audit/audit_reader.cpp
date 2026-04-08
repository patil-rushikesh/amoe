#include "audit/audit_reader.h"

#include "common/utils.h"

#include <fstream>
#include <regex>
#include <unordered_set>

namespace amoe {

namespace {

std::optional<std::string> extract_string(const std::string& line, const std::string& key) {
    const std::regex pattern("\"" + key + "\":\"((?:\\\\.|[^\"])*)\"");
    std::smatch match;
    if (std::regex_search(line, match, pattern)) {
        return utils::unescape_json(match[1].str());
    }
    return std::nullopt;
}

std::optional<int> extract_int(const std::string& line, const std::string& key) {
    const std::regex pattern("\"" + key + "\":(-?\\d+)");
    std::smatch match;
    if (std::regex_search(line, match, pattern)) {
        return std::stoi(match[1].str());
    }
    return std::nullopt;
}

std::optional<double> extract_double(const std::string& line, const std::string& key) {
    const std::regex pattern("\"" + key + "\":(-?\\d+(?:\\.\\d+)?)");
    std::smatch match;
    if (std::regex_search(line, match, pattern)) {
        return std::stod(match[1].str());
    }
    return std::nullopt;
}

std::optional<bool> extract_bool(const std::string& line, const std::string& key) {
    const std::regex pattern("\"" + key + "\":(true|false)");
    std::smatch match;
    if (std::regex_search(line, match, pattern)) {
        return match[1].str() == "true";
    }
    return std::nullopt;
}

} // namespace

AuditReader::AuditReader(std::string log_path) : log_path_(std::move(log_path)) {}

std::vector<AuditEntry> AuditReader::read(const AuditFilter& filter) const {
    std::vector<AuditEntry> entries;
    std::ifstream input(log_path_);
    std::string line;
    while (std::getline(input, line)) {
        const auto entry = parse_line(line);
        if (!entry.has_value()) {
            continue;
        }
        if (filter.pid > 0 && entry->pid != filter.pid) {
            continue;
        }
        if (filter.action.has_value() && entry->action != *filter.action) {
            continue;
        }
        if (!filter.decision.empty() && utils::to_lower(entry->user_decision) != utils::to_lower(filter.decision)) {
            continue;
        }
        entries.push_back(*entry);
    }
    return entries;
}

std::optional<AuditEntry> AuditReader::last_reversible_action() const {
    const auto entries = read({});
    std::unordered_set<int> undone_pids;

    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        if ((it->action == ActionType::Resume || (it->action == ActionType::LowerPriority && it->user_decision == "UNDO")) &&
            it->success) {
            undone_pids.insert(it->pid);
            continue;
        }

        if (is_reversible(it->action) && it->executed && it->success) {
            if (undone_pids.find(it->pid) != undone_pids.end()) {
                undone_pids.erase(it->pid);
                continue;
            }
            return *it;
        }
    }
    return std::nullopt;
}

std::optional<AuditEntry> AuditReader::parse_line(const std::string& line) const {
    AuditEntry entry;

    const auto timestamp = extract_string(line, "timestamp");
    const auto process = extract_string(line, "process");
    const auto pid = extract_int(line, "pid");
    const auto action = extract_string(line, "action");
    const auto decision = extract_string(line, "user_decision");
    const auto algorithm = extract_string(line, "algorithm");
    const auto reason = extract_string(line, "reason");
    const auto risk = extract_string(line, "risk");
    const auto confidence = extract_double(line, "confidence");
    const auto executed = extract_bool(line, "executed");
    const auto success = extract_bool(line, "success");
    const auto memory_mb = extract_double(line, "memory_mb");
    const auto previous_priority = extract_int(line, "previous_priority");
    const auto new_priority = extract_int(line, "new_priority");

    if (!timestamp || !process || !pid || !action || !decision || !algorithm || !reason || !risk || !confidence || !executed ||
        !success || !memory_mb || !previous_priority || !new_priority) {
        return std::nullopt;
    }

    const auto parsed_action = utils::parse_action(*action);
    const auto parsed_algorithm = utils::parse_algorithm(*algorithm);
    if (!parsed_action.has_value() || !parsed_algorithm.has_value()) {
        return std::nullopt;
    }

    entry.timestamp = *timestamp;
    entry.process_name = *process;
    entry.pid = *pid;
    entry.action = *parsed_action;
    entry.user_decision = *decision;
    entry.algorithm = *parsed_algorithm;
    entry.reason = *reason;
    entry.confidence = *confidence;
    entry.executed = *executed;
    entry.success = *success;
    entry.memory_mb = *memory_mb;
    entry.previous_priority = *previous_priority;
    entry.new_priority = *new_priority;

    const auto risk_value = utils::to_lower(*risk);
    if (risk_value == "high") {
        entry.risk = RiskLevel::High;
    } else if (risk_value == "medium") {
        entry.risk = RiskLevel::Medium;
    } else {
        entry.risk = RiskLevel::Low;
    }

    return entry;
}

} // namespace amoe
