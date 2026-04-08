#ifndef AMOE_CONFIG_CONFIG_H
#define AMOE_CONFIG_CONFIG_H

#include "common/types.h"

#include <string>

namespace amoe {

class ConfigManager {
  public:
    RuntimeConfig load(const std::string& path) const;
    bool save(const std::string& path, const RuntimeConfig& config, std::string& error) const;
    bool add_protected_process(const std::string& path, RuntimeConfig& config, const ProcessInfo& process, std::string& error) const;
};

} // namespace amoe

#endif
