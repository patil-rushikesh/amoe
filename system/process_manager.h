#ifndef AMOE_SYSTEM_PROCESS_MANAGER_H
#define AMOE_SYSTEM_PROCESS_MANAGER_H

#include "common/types.h"

#include <memory>
#include <string>
#include <vector>

namespace amoe {

class ProcessManager {
  public:
    virtual ~ProcessManager() = default;

    virtual std::vector<ProcessInfo> list_processes() = 0;
    virtual MemoryStatus memory_status() = 0;
    virtual bool suspend_process(int pid, std::string& error) = 0;
    virtual bool resume_process(int pid, std::string& error) = 0;
    virtual bool kill_process(int pid, std::string& error) = 0;
    virtual bool change_priority(int pid, int priority, std::string& error) = 0;
    virtual std::string platform_name() const = 0;

    static std::unique_ptr<ProcessManager> create();
};

} // namespace amoe

#endif
