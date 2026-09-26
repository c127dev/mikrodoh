#pragma once

#include <string>

bool drop_privileges(const std::string& user, const std::string& group);
