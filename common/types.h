#ifndef AMOE_COMMON_TYPES_H
#define AMOE_COMMON_TYPES_H

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace amoe {

using Clock = std::chrono::system_clock;
using TimePoint = std::chrono::time_point<Clock>;

enum class AlgorithmType {
    FCFS,
    LRU,
    Optimal,
    Hybrid,
};

enum class ActionType {
    None,
    Suspend,
    Kill,
    LowerPriority,
    Resume,
};

enum class ProcessClassification {
    Critical,
    Protected,
    Normal,
};

enum class RiskLevel {
    Low,
    Medium,
    High,
};

enum class Mode {
    Beginner,
    Advanced,
    Auto,
    DryRun,
};

struct HybridWeights {
    double recency {0.45};
    double frequency {0.30};
    double memory_usage {0.25};
};

struct ProcessInfo {
    int pid {-1};
    std::string name;
    std::string owner;
    std::uint64_t rss_kb {0};
    double cpu_percent {0.0};
    TimePoint observed_at {};
    TimePoint last_active {};
    std::uint64_t cpu_time_ticks {0};
    int priority {0};
    ProcessClassification classification {ProcessClassification::Normal};
    bool manageable {true};
    bool system_process {false};
    std::string state;
};

struct MemoryStatus {
    std::uint64_t total_kb {0};
    std::uint64_t available_kb {0};
    std::uint64_t used_kb {0};
    double pressure_percent {0.0};
};

struct ProcessSnapshot {
    TimePoint timestamp {};
    std::vector<ProcessInfo> processes;
    MemoryStatus memory;
};

struct AlgorithmContext {
    std::unordered_map<int, double> recency;
    std::unordered_map<int, double> frequency;
    std::unordered_map<int, double> memory_usage;
    HybridWeights weights;
};

struct ReferenceProfile {
    std::vector<int> reference_string;
    AlgorithmContext context;
    std::unordered_map<int, ProcessInfo> latest_processes;
    std::unordered_map<int, std::size_t> touches;
};

struct SimulationStep {
    std::size_t index {0};
    int page {-1};
    std::vector<int> frames;
    bool page_fault {false};
    std::optional<int> evicted_page;
    std::string note;
};

struct SimulationResult {
    AlgorithmType algorithm {AlgorithmType::FCFS};
    std::size_t page_faults {0};
    std::vector<SimulationStep> steps;
    std::unordered_map<int, std::size_t> eviction_counts;
};

struct SystemState {
    double memory_pressure_percent {0.0};
    bool high_memory_pressure {false};
    bool stable {false};
    bool burst_activity {false};
    bool background_overload {false};
    bool predictable_pattern {false};
    std::size_t total_processes {0};
    std::size_t active_processes {0};
    std::string summary;
    std::vector<std::string> reasons;
};

struct Recommendation {
    ProcessInfo process;
    ActionType action {ActionType::None};
    AlgorithmType selected_algorithm {AlgorithmType::FCFS};
    RiskLevel risk {RiskLevel::Low};
    double confidence {0.0};
    double estimated_memory_reclaim_mb {0.0};
    std::string reason;
    std::vector<std::string> evidence;
    std::size_t eviction_count {0};
    bool requires_confirmation {true};
    int previous_priority {0};
    int proposed_priority {0};
};

struct AuditEntry {
    std::string timestamp;
    std::string process_name;
    int pid {-1};
    ActionType action {ActionType::None};
    std::string user_decision;
    AlgorithmType algorithm {AlgorithmType::FCFS};
    std::string reason;
    RiskLevel risk {RiskLevel::Low};
    double confidence {0.0};
    bool executed {false};
    bool success {false};
    double memory_mb {0.0};
    int previous_priority {0};
    int new_priority {0};
};

struct AppOptions {
    std::string config_path {"amoe.conf"};
    std::size_t frames {5};
    std::size_t samples {4};
    std::size_t interval_ms {750};
    Mode mode {Mode::Beginner};
    bool show_logs {false};
    bool undo_last {false};
    bool list_only {false};
    int filter_pid {-1};
    std::string filter_action;
    std::string filter_decision;
    std::size_t max_recommendations {5};
};

struct RuntimeConfig {
    std::size_t frames {5};
    std::size_t samples {4};
    std::size_t interval_ms {750};
    std::size_t max_recommendations {5};
    Mode mode {Mode::Beginner};
    HybridWeights weights {};
    std::unordered_set<std::string> protected_names;
    std::unordered_set<int> protected_pids;
    std::vector<std::string> critical_names {"systemd", "init", "launchd", "kernel_task", "WindowServer",
                                             "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"};
    std::string audit_log_path {"amoe_audit.log"};
    double high_memory_threshold {80.0};
    double stable_memory_threshold {60.0};
    double burst_cpu_threshold {35.0};
    double background_cpu_threshold {5.0};
    std::uint64_t minimum_candidate_rss_kb {128 * 1024};
};

inline bool is_reversible(ActionType action) {
    return action == ActionType::Suspend || action == ActionType::LowerPriority;
}

inline std::string to_string(AlgorithmType algorithm) {
    switch (algorithm) {
    case AlgorithmType::FCFS:
        return "FCFS";
    case AlgorithmType::LRU:
        return "LRU";
    case AlgorithmType::Optimal:
        return "OPTIMAL";
    case AlgorithmType::Hybrid:
        return "HYBRID";
    }
    return "UNKNOWN";
}

inline std::string to_string(ActionType action) {
    switch (action) {
    case ActionType::None:
        return "NONE";
    case ActionType::Suspend:
        return "SUSPEND";
    case ActionType::Kill:
        return "KILL";
    case ActionType::LowerPriority:
        return "LOWER_PRIORITY";
    case ActionType::Resume:
        return "RESUME";
    }
    return "UNKNOWN";
}

inline std::string to_string(ProcessClassification classification) {
    switch (classification) {
    case ProcessClassification::Critical:
        return "CRITICAL";
    case ProcessClassification::Protected:
        return "PROTECTED";
    case ProcessClassification::Normal:
        return "NORMAL";
    }
    return "UNKNOWN";
}

inline std::string to_string(RiskLevel risk) {
    switch (risk) {
    case RiskLevel::Low:
        return "LOW";
    case RiskLevel::Medium:
        return "MEDIUM";
    case RiskLevel::High:
        return "HIGH";
    }
    return "UNKNOWN";
}

inline std::string to_string(Mode mode) {
    switch (mode) {
    case Mode::Beginner:
        return "BEGINNER";
    case Mode::Advanced:
        return "ADVANCED";
    case Mode::Auto:
        return "AUTO";
    case Mode::DryRun:
        return "DRY_RUN";
    }
    return "UNKNOWN";
}

} // namespace amoe

#endif
