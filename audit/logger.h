#ifndef AMOE_AUDIT_LOGGER_H
#define AMOE_AUDIT_LOGGER_H

#include "common/types.h"

#include <string>

namespace amoe {

class AuditLogger {
  public:
    explicit AuditLogger(std::string log_path);

    bool log(const AuditEntry& entry, std::string& error) const;
    const std::string& path() const;

  private:
    std::string log_path_;
};

} // namespace amoe

#endif
