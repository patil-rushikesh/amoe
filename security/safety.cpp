#include "security/safety.h"

#include "common/utils.h"

#include <algorithm>

namespace amoe {

namespace {

bool name_in_list(const std::string& name, const std::vector<std::string>& candidates) {
    const auto lowered_name = utils::to_lower(name);
    return std::any_of(candidates.begin(), candidates.end(), [&](const std::string& candidate) {
        return lowered_name == utils::to_lower(candidate);
    });
}

bool name_in_set(const std::string& name, const std::unordered_set<std::string>& candidates) {
    const auto lowered_name = utils::to_lower(name);
    return std::any_of(candidates.begin(), candidates.end(),
                       [&](const std::string& candidate) { return lowered_name == utils::to_lower(candidate); });
}

} // namespace

SafetyManager::SafetyManager(const RuntimeConfig& config, PermissionStatus permissions)
    : config_(config), permissions_(std::move(permissions)) {}

void SafetyManager::annotate_processes(std::vector<ProcessInfo>& processes) const {
    for (auto& process : processes) {
        process.classification = classify(process);
        std::string reason;
        process.manageable = can_execute(ActionType::Suspend, process, reason);
    }
}

ProcessClassification SafetyManager::classify(const ProcessInfo& process) const {
    if (process.pid == 0 || process.pid == 1 || process.system_process || name_in_list(process.name, config_.critical_names)) {
        return ProcessClassification::Critical;
    }
    if (config_.protected_pids.find(process.pid) != config_.protected_pids.end() ||
        name_in_set(process.name, config_.protected_names)) {
        return ProcessClassification::Protected;
    }
    return ProcessClassification::Normal;
}

bool SafetyManager::validate_pid(const int pid, std::string& reason) const {
    if (pid <= 1) {
        reason = "Refusing to operate on PID 0 or PID 1.";
        return false;
    }
    return true;
}

bool SafetyManager::can_execute(const ActionType action, const ProcessInfo& process, std::string& reason) const {
    if (!validate_pid(process.pid, reason)) {
        return false;
    }
    if (classify(process) == ProcessClassification::Critical) {
        reason = "Critical system process. AMOE will not manage it.";
        return false;
    }
    if (classify(process) == ProcessClassification::Protected) {
        reason = "Protected process from user whitelist.";
        return false;
    }
    if ((utils::to_lower(process.name) == "systemd" || utils::to_lower(process.name) == "init") && action == ActionType::Kill) {
        reason = "init/systemd must never be killed.";
        return false;
    }
    if (!permissions_.elevated && !permissions_.current_user.empty() && !process.owner.empty() &&
        utils::to_lower(process.owner) != utils::to_lower(permissions_.current_user)) {
        reason = "Insufficient privileges to manage a process owned by another user.";
        return false;
    }
    if (action == ActionType::Kill && process.cpu_percent > 10.0 && process.rss_kb < (config_.minimum_candidate_rss_kb * 2ULL)) {
        reason = "Kill action blocked for an active process with limited reclaim potential.";
        return false;
    }
    return true;
}

} // namespace amoe
