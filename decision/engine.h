#ifndef AMOE_DECISION_ENGINE_H
#define AMOE_DECISION_ENGINE_H

#include "monitor/tracker.h"
#include "security/permissions.h"

#include <map>
#include <vector>

namespace amoe {

struct AnalysisReport {
    std::map<AlgorithmType, SimulationResult> simulations;
    AlgorithmType selected_algorithm {AlgorithmType::FCFS};
    std::vector<std::string> selection_reasons;
    std::vector<Recommendation> recommendations;
};

class DecisionEngine {
  public:
    DecisionEngine(const RuntimeConfig& config, PermissionStatus permissions);

    AnalysisReport evaluate(const MonitoringReport& monitoring) const;

  private:
    AlgorithmType select_algorithm(const SystemState& state, const std::map<AlgorithmType, SimulationResult>& simulations,
                                   std::vector<std::string>& reasons) const;
    std::vector<Recommendation> build_recommendations(const MonitoringReport& monitoring,
                                                      const SimulationResult& selected_simulation,
                                                      AlgorithmType selected_algorithm) const;

    const RuntimeConfig& config_;
    PermissionStatus permissions_;
};

} // namespace amoe

#endif
