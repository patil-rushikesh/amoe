#ifndef AMOE_SECURITY_PERMISSIONS_H
#define AMOE_SECURITY_PERMISSIONS_H

#include <string>
#include <vector>

namespace amoe {

struct PermissionStatus {
    bool elevated {false};
    std::string current_user;
    std::string platform;
    std::vector<std::string> limitations;
};

class PermissionManager {
  public:
    PermissionStatus query() const;
};

} // namespace amoe

#endif
