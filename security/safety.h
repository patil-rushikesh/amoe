#ifndef AMOE_SECURITY_SAFETY_H
#define AMOE_SECURITY_SAFETY_H

#include "common/types.h"
#include "security/permissions.h"

#include <string>
#include <vector>

namespace amoe {

class SafetyManager {
  public:
    SafetyManager(const RuntimeConfig& config, PermissionStatus permissions);

    void annotate_processes(std::vector<ProcessInfo>& processes) const;
    ProcessClassification classify(const ProcessInfo& process) const;
    bool validate_pid(int pid, std::string& reason) const;
    bool can_execute(ActionType action, const ProcessInfo& process, std::string& reason) const;

  private:
    const RuntimeConfig& config_;
    PermissionStatus permissions_;
};

} // namespace amoe

#endif
