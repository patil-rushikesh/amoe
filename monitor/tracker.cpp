#include "monitor/tracker.h"

#include "common/utils.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace amoe {

namespace {

double clamp01(const double value) {
    return std::max(0.0, std::min(1.0, value));
}

double activity_score(const ProcessInfo& process, const std::uint64_t max_rss_kb) {
    const double cpu_component = process.cpu_percent * 4.0;
    const double memory_component = max_rss_kb == 0 ? 0.0 : (static_cast<double>(process.rss_kb) / static_cast<double>(max_rss_kb)) * 100.0;
    return cpu_component + memory_component;
}

bool detect_predictable_pattern(const std::vector<int>& references) {
    if (references.size() < 6) {
        return false;
    }

    std::unordered_map<std::string, int> windows;
    for (std::size_t index = 0; index + 2 < references.size(); ++index) {
        const std::string key = std::to_string(references[index]) + "|" + std::to_string(references[index + 1]) + "|" +
                                std::to_string(references[index + 2]);
        ++windows[key];
    }

    const auto repeated = std::count_if(windows.begin(), windows.end(), [](const auto& item) { return item.second >= 2; });
    std::unordered_set<int> uniques(references.begin(), references.end());
    return repeated >= 1 && uniques.size() * 2 <= references.size();
}

} // namespace

ProcessTracker::ProcessTracker(ProcessManager& process_manager, const SafetyManager& safety_manager, const RuntimeConfig& config)
    : process_manager_(process_manager), safety_manager_(safety_manager), config_(config) {}

MonitoringReport ProcessTracker::collect() const {
    MonitoringReport report;
    report.snapshots.reserve(config_.samples);

    std::unordered_map<int, TimePoint> last_active_by_pid;

    for (std::size_t sample = 0; sample < config_.samples; ++sample) {
        ProcessSnapshot snapshot;
        snapshot.timestamp = Clock::now();
        snapshot.processes = process_manager_.list_processes();
        snapshot.memory = process_manager_.memory_status();
        safety_manager_.annotate_processes(snapshot.processes);

        for (auto& process : snapshot.processes) {
            const bool active = process.cpu_percent >= 1.0 || process.rss_kb >= (config_.minimum_candidate_rss_kb / 2ULL);
            auto found = last_active_by_pid.find(process.pid);
            if (active || found == last_active_by_pid.end()) {
                last_active_by_pid[process.pid] = snapshot.timestamp;
                process.last_active = snapshot.timestamp;
            } else {
                process.last_active = found->second;
            }
        }

        report.snapshots.push_back(snapshot);

        if (sample + 1 < config_.samples) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.interval_ms));
        }
    }

    if (!report.snapshots.empty()) {
        report.current_processes = report.snapshots.back().processes;
        report.reference_profile = build_reference_profile(report.snapshots);
        report.system_state = assess_system_state(report.snapshots, report.reference_profile);
    }

    return report;
}

ReferenceProfile ProcessTracker::build_reference_profile(const std::vector<ProcessSnapshot>& snapshots) const {
    ReferenceProfile profile;
    if (snapshots.empty()) {
        return profile;
    }

    const auto now = snapshots.back().timestamp;
    std::uint64_t max_rss_kb = 0;

    for (const auto& snapshot : snapshots) {
        std::vector<ProcessInfo> ranked = snapshot.processes;
        for (const auto& process : ranked) {
            max_rss_kb = std::max(max_rss_kb, process.rss_kb);
        }

        std::sort(ranked.begin(), ranked.end(), [&](const ProcessInfo& left, const ProcessInfo& right) {
            return activity_score(left, max_rss_kb) > activity_score(right, max_rss_kb);
        });

        const std::size_t limit = std::min<std::size_t>(std::max<std::size_t>(5, config_.frames * 2), ranked.size());
        std::size_t selected = 0;
        for (const auto& process : ranked) {
            const bool include = process.cpu_percent >= 0.5 || process.rss_kb >= (config_.minimum_candidate_rss_kb / 2ULL) || selected < 3;
            if (!include) {
                continue;
            }

            profile.reference_string.push_back(process.pid);
            ++profile.touches[process.pid];
            profile.latest_processes[process.pid] = process;
            ++selected;

            if (selected >= limit) {
                break;
            }
        }
    }

    std::size_t max_touches = 1;
    for (const auto& [pid, count] : profile.touches) {
        (void)pid;
        max_touches = std::max(max_touches, count);
    }

    for (const auto& [pid, process] : profile.latest_processes) {
        const auto age_seconds = std::max<std::int64_t>(0, std::chrono::duration_cast<std::chrono::seconds>(now - process.last_active).count());
        const double recency_score = 1.0 / (1.0 + (static_cast<double>(age_seconds) / std::max(1.0, config_.interval_ms / 1000.0)));
        const double frequency_score = static_cast<double>(profile.touches[pid]) / static_cast<double>(max_touches);

        // Lower memory component should make a heavy process easier to evict in the hybrid algorithm.
        const double memory_ratio = max_rss_kb == 0 ? 0.0 : static_cast<double>(process.rss_kb) / static_cast<double>(max_rss_kb);
        const double memory_score = 1.0 - clamp01(memory_ratio);

        profile.context.recency[pid] = clamp01(recency_score);
        profile.context.frequency[pid] = clamp01(frequency_score);
        profile.context.memory_usage[pid] = clamp01(memory_score);
    }
    profile.context.weights = config_.weights;

    return profile;
}

SystemState ProcessTracker::assess_system_state(const std::vector<ProcessSnapshot>& snapshots, const ReferenceProfile& profile) const {
    SystemState state;
    if (snapshots.empty()) {
        state.summary = "No snapshots collected.";
        return state;
    }

    const auto& latest = snapshots.back();
    state.memory_pressure_percent = latest.memory.pressure_percent;
    state.total_processes = latest.processes.size();

    std::uint64_t background_rss = 0;
    std::uint64_t total_rss = 0;
    std::size_t background_count = 0;
    double max_cpu = 0.0;

    for (const auto& process : latest.processes) {
        total_rss += process.rss_kb;
        max_cpu = std::max(max_cpu, process.cpu_percent);

        if (process.cpu_percent >= 1.0 || process.last_active == latest.timestamp) {
            ++state.active_processes;
        }
        if (process.cpu_percent <= config_.background_cpu_threshold && process.rss_kb >= config_.minimum_candidate_rss_kb) {
            ++background_count;
            background_rss += process.rss_kb;
        }
    }

    state.high_memory_pressure = state.memory_pressure_percent >= config_.high_memory_threshold;
    state.stable = state.memory_pressure_percent < config_.stable_memory_threshold;
    state.burst_activity = max_cpu >= config_.burst_cpu_threshold ||
                           (state.total_processes > 0 && static_cast<double>(state.active_processes) / state.total_processes > 0.45);
    state.background_overload =
        background_count >= 3 || (total_rss > 0 && static_cast<double>(background_rss) / static_cast<double>(total_rss) > 0.30);
    state.predictable_pattern = detect_predictable_pattern(profile.reference_string);

    if (state.high_memory_pressure) {
        state.reasons.push_back("High memory pressure detected above configured threshold.");
    }
    if (state.stable) {
        state.reasons.push_back("System memory pressure is within the stable range.");
    }
    if (state.burst_activity) {
        state.reasons.push_back("Burst activity detected from active process density and CPU spikes.");
    }
    if (state.background_overload) {
        state.reasons.push_back("Background overload detected from low-CPU, high-RSS processes.");
    }
    if (state.predictable_pattern) {
        state.reasons.push_back("Reference stream contains repeating access windows.");
    }
    if (state.reasons.empty()) {
        state.reasons.push_back("No dominant memory pressure signal detected.");
    }

    state.summary = utils::join(state.reasons, " ");
    return state;
}

} // namespace amoe
