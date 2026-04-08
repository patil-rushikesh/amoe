#ifndef AMOE_AUDIT_AUDIT_READER_H
#define AMOE_AUDIT_AUDIT_READER_H

#include "common/types.h"

#include <optional>
#include <string>
#include <vector>

namespace amoe {

struct AuditFilter {
    int pid {-1};
    std::optional<ActionType> action;
    std::string decision;
};

class AuditReader {
  public:
    explicit AuditReader(std::string log_path);

    std::vector<AuditEntry> read(const AuditFilter& filter) const;
    std::optional<AuditEntry> last_reversible_action() const;

  private:
    std::optional<AuditEntry> parse_line(const std::string& line) const;

    std::string log_path_;
};

} // namespace amoe

#endif
