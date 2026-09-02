#include "privs.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

// Accepts a name or a numeric id, so an image without /etc/passwd still works.
bool lookup_user(const std::string& user, uid_t& uid, gid_t& gid) {
    std::vector<char> buf(4096);
    passwd            pw{};
    passwd*           found = nullptr;

    if (getpwnam_r(user.c_str(), &pw, buf.data(), buf.size(), &found) == 0 && found) {
        uid = pw.pw_uid;
        gid = pw.pw_gid;
        return true;
    }

    char* end = nullptr;
    long  id  = std::strtol(user.c_str(), &end, 10);
    if (end && *end == '\0' && id >= 0) {
        uid = static_cast<uid_t>(id);
        gid = static_cast<gid_t>(id);
        if (getpwuid_r(uid, &pw, buf.data(), buf.size(), &found) == 0 && found)
            gid = pw.pw_gid;
        return true;
    }

    return false;
}

bool lookup_group(const std::string& group, gid_t& gid) {
    std::vector<char> buf(4096);
    ::group           gr{};
    ::group*          found = nullptr;

    if (getgrnam_r(group.c_str(), &gr, buf.data(), buf.size(), &found) == 0 && found) {
        gid = gr.gr_gid;
        return true;
    }

    char* end = nullptr;
    long  id  = std::strtol(group.c_str(), &end, 10);
    if (end && *end == '\0' && id >= 0) {
        gid = static_cast<gid_t>(id);
        return true;
    }

    return false;
}

void fail(const char* what) {
    std::cerr << "Failed to drop privileges: " << what << ": "
              << std::strerror(errno) << "\n";
}

}  // namespace

bool drop_privileges(const std::string& user, const std::string& group) {
    if (user.empty()) return true;

    if (geteuid() != 0) {
        std::cerr << "RUN_AS_USER is set but the process is not root, "
                     "staying as uid "
                  << geteuid() << "\n";
        return true;
    }

    uid_t uid = 0;
    gid_t gid = 0;
    if (!lookup_user(user, uid, gid)) {
        std::cerr << "Unknown RUN_AS_USER: " << user << "\n";
        return false;
    }
    if (!group.empty() && !lookup_group(group, gid)) {
        std::cerr << "Unknown RUN_AS_GROUP: " << group << "\n";
        return false;
    }
    if (uid == 0) {
        std::cerr << "RUN_AS_USER resolves to root, refusing\n";
        return false;
    }

    // Supplementary groups survive setuid, so clear them first: root's groups
    // are the ones worth keeping away from the daemon.
    if (setgroups(0, nullptr) != 0) {
        fail("setgroups");
        return false;
    }
    if (setgid(gid) != 0) {
        fail("setgid");
        return false;
    }
    if (setuid(uid) != 0) {
        fail("setuid");
        return false;
    }

    // A saved set-user-ID left behind would let the process return to root.
    if (setuid(0) == 0 || geteuid() != uid || getuid() != uid) {
        std::cerr << "Failed to drop privileges: root is still reachable\n";
        return false;
    }

    std::cout << "Dropped to uid " << uid << " gid " << gid << "\n";
    return true;
}
