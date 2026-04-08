#include "ui/cli.h"

#include "common/utils.h"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace amoe {

namespace {

std::string frames_to_string(const std::vector<int>& frames) {
    if (frames.empty()) {
        return "-";
    }
    std::ostringstream out;
    for (std::size_t index = 0; index < frames.size(); ++index) {
        if (index != 0) {
            out << ' ';
        }
        out << frames[index];
    }
    return out.str();
}

std::string confidence_label(const double confidence) {
    if (confidence >= 0.80) {
        return "HIGH";
    }
    if (confidence >= 0.60) {
        return "MEDIUM";
    }
    return "LOW";
}

} // namespace

void Cli::print_banner() const {
    std::cout << "====================================\n";
    std::cout << "Adaptive Memory Optimization Engine\n";
    std::cout << "====================================\n";
}

void Cli::print_environment(const ProcessSnapshot& snapshot,
                            const RuntimeConfig& config,
                            const std::string& platform,
                            const PermissionStatus& permissions) const {
    std::cout << "Processes: " << snapshot.processes.size() << '\n';
    std::cout << "Frames: " << config.frames << '\n';
    std::cout << "Mode: " << to_string(config.mode) << '\n';
    std::cout << "Platform: " << platform << '\n';
    std::cout << "Memory Pressure: " << std::fixed << std::setprecision(1) << snapshot.memory.pressure_percent << "%\n";
    std::cout << "Privileges: " << (permissions.elevated ? "elevated" : "standard user") << "\n\n";
}

void Cli::print_algorithm_comparison(const AnalysisReport& analysis, const SystemState& state) const {
    std::cout << "Algorithm Comparison\n";
    std::cout << "--------------------\n";
    for (const auto& [algorithm, simulation] : analysis.simulations) {
        std::cout << std::left << std::setw(8) << to_string(algorithm) << ": " << simulation.page_faults << " faults";
        if (algorithm == analysis.selected_algorithm) {
            std::cout << "  <== selected";
        }
        std::cout << '\n';
    }
    std::cout << "System State: " << state.summary << "\n";
    for (const auto& reason : analysis.selection_reasons) {
        std::cout << "  - " << reason << '\n';
    }
    std::cout << '\n';
}

void Cli::print_recommendation(const Recommendation& recommendation) const {
    std::cout << "Process: " << recommendation.process.name << '\n';
    std::cout << "PID: " << recommendation.process.pid << '\n';
    std::cout << "Memory: " << utils::format_mb(utils::kb_to_mb(recommendation.process.rss_kb)) << '\n';
    std::cout << "Last Active: " << utils::format_age(recommendation.process.last_active) << '\n';
    std::cout << "Confidence: " << confidence_label(recommendation.confidence) << '\n';
    std::cout << "Recommended: " << to_string(recommendation.action) << '\n';
    std::cout << "--------------------\n";
    std::cout << '\n';
}

void Cli::print_details(const Recommendation& recommendation, const AnalysisReport& analysis, const SystemState& state) const {
    std::cout << "Recommendation Details\n";
    std::cout << "----------------------\n";
    std::cout << "Selected Algorithm: " << to_string(recommendation.selected_algorithm) << '\n';
    std::cout << "Reason: " << recommendation.reason << '\n';
    std::cout << "Estimated Memory Impact: " << utils::format_mb(recommendation.estimated_memory_reclaim_mb) << '\n';
    std::cout << "Confidence: " << confidence_label(recommendation.confidence) << '\n';
    std::cout << "Risk: " << to_string(recommendation.risk) << '\n';
    std::cout << "System Summary: " << state.summary << '\n';
    std::cout << "Evidence:\n";
    for (const auto& item : recommendation.evidence) {
        std::cout << "  - " << item << '\n';
    }
    std::cout << '\n';

    const auto selected = analysis.simulations.find(recommendation.selected_algorithm);
    if (selected == analysis.simulations.end()) {
        return;
    }

    std::cout << "Step-by-step simulation for " << to_string(recommendation.selected_algorithm) << '\n';
    std::cout << "Idx  Page  Fault  Evicted  Frames  Note\n";
    for (const auto& step : selected->second.steps) {
        std::cout << std::setw(4) << step.index << ' '
                  << std::setw(5) << step.page << ' '
                  << std::setw(6) << (step.page_fault ? "YES" : "NO") << ' '
                  << std::setw(8) << (step.evicted_page.has_value() ? std::to_string(*step.evicted_page) : "-") << ' '
                  << std::setw(10) << frames_to_string(step.frames) << ' '
                  << step.note << '\n';
    }
    std::cout << '\n';
}

void Cli::print_action_result(const std::string& message, const bool success) const {
    std::cout << (success ? "[OK] " : "[FAILED] ") << message << "\n\n";
}

void Cli::print_log_entries(const std::vector<AuditEntry>& entries) const {
    if (entries.empty()) {
        std::cout << "No audit entries matched the requested filter.\n";
        return;
    }

    std::cout << "Timestamp              PID   Action          Decision         Algorithm  Success  Memory\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    for (const auto& entry : entries) {
        std::cout << std::left << std::setw(22) << entry.timestamp
                  << std::setw(6) << entry.pid
                  << std::setw(16) << to_string(entry.action)
                  << std::setw(17) << entry.user_decision
                  << std::setw(11) << to_string(entry.algorithm)
                  << std::setw(9) << (entry.success ? "yes" : "no")
                  << utils::format_mb(entry.memory_mb) << '\n';
    }
}

void Cli::print_no_recommendations(const SystemState& state) const {
    std::cout << "No safe action candidates were found.\n";
    std::cout << "Reason: " << state.summary << '\n';
}

int Cli::prompt_choice(const Recommendation& recommendation, const Mode mode) const {
    (void)recommendation;
    if (mode == Mode::Auto) {
        std::cout << "Auto mode preselected [1] Apply; confirmation is still required.\n";
        return 1;
    }

    std::cout << "Options:\n";
    std::cout << "[1] Apply\n";
    std::cout << "[2] Skip\n";
    std::cout << "[3] Always ignore\n";
    std::cout << "[4] View details\n";
    std::cout << "\nChoice: ";

    std::string input;
    if (!std::getline(std::cin, input)) {
        return 2;
    }
    const auto parsed = utils::to_int(input);
    if (!parsed.has_value() || *parsed < 1 || *parsed > 4) {
        return 2;
    }
    std::cout << '\n';
    return *parsed;
}

bool Cli::confirm_action(const Recommendation& recommendation) const {
    std::cout << "About to execute live action\n";
    std::cout << "---------------------------\n";
    std::cout << "Process: " << recommendation.process.name << '\n';
    std::cout << "PID: " << recommendation.process.pid << '\n';
    std::cout << "Memory: " << utils::format_mb(utils::kb_to_mb(recommendation.process.rss_kb)) << '\n';
    std::cout << "Reason: " << recommendation.reason << '\n';
    std::cout << "Risk Level: " << to_string(recommendation.risk) << '\n';
    std::cout << "Type YES to confirm:\n";
    std::cout << "Type NO to cancel:\n";
    std::cout << "> ";

    std::string input;
    if (!std::getline(std::cin, input)) {
        return false;
    }
    std::cout << '\n';
    return utils::to_lower(utils::trim(input)) == "yes";
}

} // namespace amoe
