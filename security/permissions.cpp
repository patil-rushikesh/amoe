#include "security/permissions.h"

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace amoe {

PermissionStatus PermissionManager::query() const {
    PermissionStatus status;

#if defined(_WIN32)
    status.platform = "Windows";
    status.current_user = "unknown";

    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID admin_group = nullptr;
    BOOL is_admin = FALSE;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    status.elevated = (is_admin == TRUE);
    if (!status.elevated) {
        status.limitations.push_back("Administrative privileges are not available. Some process actions may fail.");
    }
#else
    status.elevated = (geteuid() == 0);
    status.platform = "POSIX";
    if (const passwd* pw = getpwuid(geteuid())) {
        status.current_user = pw->pw_name;
    } else {
        status.current_user = std::to_string(geteuid());
    }
    if (!status.elevated) {
        status.limitations.push_back("Running without root privileges. AMOE will only recommend safe, user-owned actions.");
    }
#endif

    return status;
}

} // namespace amoe
