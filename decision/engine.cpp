#include "decision/engine.h"

#include "algorithms/fcfs.h"
#include "algorithms/hybrid.h"
#include "algorithms/lru.h"
#include "algorithms/optimal.h"
#include "common/utils.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <sstream>

namespace amoe {

namespace {

double clamp01(const double value) {
    return std::max(0.0, std::min(1.0, value));
}

double normalized_value(const double value, const double maximum) {
    if (maximum <= 0.0) {
        return 0.0;
    }
    return clamp01(value / maximum);
}

ActionType choose_action(const ProcessInfo& process,
                         const double score,
                         const double memory_pressure,
                         const double staleness,
                         const double eviction_norm) {
    if (memory_pressure >= 93.0 && score >= 0.88 && process.cpu_percent < 0.5 && staleness > 0.80 && eviction_norm > 0.50) {
        return ActionType::Kill;
    }
    if (score >= 0.62 && process.cpu_percent < 15.0) {
        return ActionType::Suspend;
    }
    if (process.cpu_percent >= 10.0 || score >= 0.48) {
        return ActionType::LowerPriority;
    }
    return ActionType::None;
}

RiskLevel risk_for_action(const ActionType action) {
    switch (action) {
    case ActionType::Kill:
        return RiskLevel::High;
    case ActionType::Suspend:
        return RiskLevel::Medium;
    case ActionType::LowerPriority:
        return RiskLevel::Low;
    default:
        return RiskLevel::Low;
    }
}

} // namespace

DecisionEngine::DecisionEngine(const RuntimeConfig& config, PermissionStatus permissions)
    : config_(config), permissions_(std::move(permissions)) {}

AnalysisReport DecisionEngine::evaluate(const MonitoringReport& monitoring) const {
    AnalysisReport report;

    const auto& refs = monitoring.reference_profile.reference_string;
    report.simulations[AlgorithmType::FCFS] = algorithms::run_fcfs(refs, config_.frames);
    report.simulations[AlgorithmType::LRU] = algorithms::run_lru(refs, config_.frames);
    report.simulations[AlgorithmType::Optimal] = algorithms::run_optimal(refs, config_.frames);
    report.simulations[AlgorithmType::Hybrid] =
        algorithms::run_hybrid(refs, config_.frames, monitoring.reference_profile.context);

    report.selected_algorithm = select_algorithm(monitoring.system_state, report.simulations, report.selection_reasons);

    const auto chosen = report.simulations.find(report.selected_algorithm);
    if (chosen != report.simulations.end()) {
        report.recommendations = build_recommendations(monitoring, chosen->second, report.selected_algorithm);
    }

    return report;
}

AlgorithmType DecisionEngine::select_algorithm(const SystemState& state,
                                               const std::map<AlgorithmType, SimulationResult>& simulations,
                                               std::vector<std::string>& reasons) const {
    std::vector<AlgorithmType> preferred;
    if (state.background_overload) {
        preferred = {AlgorithmType::Hybrid};
        reasons.push_back("Background overload favors the Hybrid policy.");
    } else if (state.high_memory_pressure) {
        preferred = {AlgorithmType::Hybrid, AlgorithmType::LRU};
        reasons.push_back("High memory pressure prefers Hybrid or LRU.");
    } else if (state.burst_activity) {
        preferred = {AlgorithmType::LRU};
        reasons.push_back("Burst activity prefers LRU for recent working-set protection.");
    } else if (state.predictable_pattern) {
        preferred = {AlgorithmType::Optimal};
        reasons.push_back("Predictable reference patterns favor observed-window Optimal.");
    } else if (state.stable) {
        preferred = {AlgorithmType::FCFS, AlgorithmType::LRU};
        reasons.push_back("Stable memory conditions permit FCFS or LRU.");
    } else {
        preferred = {AlgorithmType::Hybrid, AlgorithmType::LRU};
        reasons.push_back("Defaulting to adaptive policies for mixed system signals.");
    }

    AlgorithmType best = preferred.front();
    std::size_t best_faults = std::numeric_limits<std::size_t>::max();

    for (const auto algorithm : preferred) {
        const auto found = simulations.find(algorithm);
        if (found != simulations.end() && found->second.page_faults < best_faults) {
            best = algorithm;
            best_faults = found->second.page_faults;
        }
    }

    std::ostringstream explanation;
    explanation << "Selected " << to_string(best) << " with " << best_faults << " page faults inside the preferred policy set.";
    reasons.push_back(explanation.str());

    return best;
}

std::vector<Recommendation> DecisionEngine::build_recommendations(const MonitoringReport& monitoring,
                                                                  const SimulationResult& selected_simulation,
                                                                  const AlgorithmType selected_algorithm) const {
    std::vector<Recommendation> recommendations;
    if (monitoring.current_processes.empty()) {
        return recommendations;
    }

    const auto max_rss = static_cast<double>(
        std::max_element(monitoring.current_processes.begin(), monitoring.current_processes.end(),
                         [](const ProcessInfo& left, const ProcessInfo& right) { return left.rss_kb < right.rss_kb; })
            ->rss_kb);

    std::size_t max_eviction_count = 1;
    for (const auto& [pid, count] : selected_simulation.eviction_counts) {
        (void)pid;
        max_eviction_count = std::max(max_eviction_count, count);
    }

    for (const auto& process : monitoring.current_processes) {
        if (process.classification != ProcessClassification::Normal || !process.manageable || process.pid <= 1 ||
            process.rss_kb < config_.minimum_candidate_rss_kb) {
            continue;
        }

        const double memory_norm = normalized_value(static_cast<double>(process.rss_kb), max_rss);
        const double cpu_idle_score = clamp01(1.0 - normalized_value(process.cpu_percent, 25.0));
        const double recency = monitoring.reference_profile.context.recency.count(process.pid)
                                   ? monitoring.reference_profile.context.recency.at(process.pid)
                                   : 0.0;
        const double staleness = clamp01(1.0 - recency);
        const double frequency = monitoring.reference_profile.context.frequency.count(process.pid)
                                     ? monitoring.reference_profile.context.frequency.at(process.pid)
                                     : 0.0;
        const double eviction_norm =
            normalized_value(static_cast<double>(selected_simulation.eviction_counts.count(process.pid)
                                                     ? selected_simulation.eviction_counts.at(process.pid)
                                                     : 0),
                             static_cast<double>(max_eviction_count));

        double score = (0.40 * memory_norm) + (0.25 * cpu_idle_score) + (0.20 * staleness) + (0.15 * eviction_norm);
        if (monitoring.system_state.high_memory_pressure) {
            score += 0.10 * memory_norm;
        }
        score = clamp01(score);

        const ActionType action = choose_action(process, score, monitoring.system_state.memory_pressure_percent, staleness, eviction_norm);
        if (action == ActionType::None) {
            continue;
        }

        Recommendation recommendation;
        recommendation.process = process;
        recommendation.action = action;
        recommendation.selected_algorithm = selected_algorithm;
        recommendation.risk = risk_for_action(action);
        recommendation.confidence =
            clamp01(score + (monitoring.system_state.high_memory_pressure ? 0.10 : 0.0) + (eviction_norm > 0.0 ? 0.05 : 0.0));
        recommendation.estimated_memory_reclaim_mb = utils::kb_to_mb(process.rss_kb);
        recommendation.eviction_count =
            selected_simulation.eviction_counts.count(process.pid) ? selected_simulation.eviction_counts.at(process.pid) : 0;
        recommendation.previous_priority = process.priority;
        recommendation.proposed_priority = std::min(process.priority + 5, 19);

        std::ostringstream reason;
        reason << "Selected " << to_string(selected_algorithm) << " marked this process as low-retention and high-reclaim under the current "
               << "system state.";
        recommendation.reason = reason.str();

        recommendation.evidence.push_back("Memory footprint: " + utils::format_mb(utils::kb_to_mb(process.rss_kb)));
        recommendation.evidence.push_back("Approx CPU usage: " + std::to_string(process.cpu_percent) + "%");
        recommendation.evidence.push_back("Staleness score: " + std::to_string(staleness));
        recommendation.evidence.push_back("Eviction count in selected simulation: " + std::to_string(recommendation.eviction_count));
        recommendation.evidence.push_back("Reference frequency score: " + std::to_string(frequency));
        if (!permissions_.elevated) {
            recommendation.evidence.push_back("Running without elevated permissions; execution may be limited.");
        }

        recommendations.push_back(recommendation);
    }

    std::sort(recommendations.begin(), recommendations.end(), [](const Recommendation& left, const Recommendation& right) {
        if (left.confidence == right.confidence) {
            return left.estimated_memory_reclaim_mb > right.estimated_memory_reclaim_mb;
        }
        return left.confidence > right.confidence;
    });

    if (recommendations.size() > config_.max_recommendations) {
        recommendations.resize(config_.max_recommendations);
    }

    return recommendations;
}

} // namespace amoe
