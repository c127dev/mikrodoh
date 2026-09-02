#pragma once

#include <string>

// Switches to `user` (and `group`, or the user's primary group when empty)
// once the listeners are bound. A no-op when `user` is empty or the process
// is not root. False means the switch was asked for and failed, which must
// abort startup rather than keep running as root.
bool drop_privileges(const std::string& user, const std::string& group);
