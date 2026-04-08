#ifndef AMOE_UI_CLI_H
#define AMOE_UI_CLI_H

#include "audit/audit_reader.h"
#include "decision/engine.h"
#include "monitor/tracker.h"
#include "security/permissions.h"

namespace amoe {

class Cli {
  public:
    void print_banner() const;
    void print_environment(const ProcessSnapshot& snapshot, const RuntimeConfig& config, const std::string& platform,
                           const PermissionStatus& permissions) const;
    void print_algorithm_comparison(const AnalysisReport& analysis, const SystemState& state) const;
    void print_recommendation(const Recommendation& recommendation) const;
    void print_details(const Recommendation& recommendation, const AnalysisReport& analysis, const SystemState& state) const;
    void print_action_result(const std::string& message, bool success) const;
    void print_log_entries(const std::vector<AuditEntry>& entries) const;
    void print_no_recommendations(const SystemState& state) const;
    int prompt_choice(const Recommendation& recommendation, Mode mode) const;
    bool confirm_action(const Recommendation& recommendation) const;
};

} // namespace amoe

#endif
