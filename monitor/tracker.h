#ifndef AMOE_MONITOR_TRACKER_H
#define AMOE_MONITOR_TRACKER_H

#include "common/types.h"
#include "security/safety.h"
#include "system/process_manager.h"

#include <vector>

namespace amoe {

struct MonitoringReport {
    std::vector<ProcessSnapshot> snapshots;
    ReferenceProfile reference_profile;
    SystemState system_state;
    std::vector<ProcessInfo> current_processes;
};

class ProcessTracker {
  public:
    ProcessTracker(ProcessManager& process_manager, const SafetyManager& safety_manager, const RuntimeConfig& config);

    MonitoringReport collect() const;

  private:
    ReferenceProfile build_reference_profile(const std::vector<ProcessSnapshot>& snapshots) const;
    SystemState assess_system_state(const std::vector<ProcessSnapshot>& snapshots, const ReferenceProfile& profile) const;

    ProcessManager& process_manager_;
    const SafetyManager& safety_manager_;
    const RuntimeConfig& config_;
};

} // namespace amoe

#endif
