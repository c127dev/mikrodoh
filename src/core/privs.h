// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <string>

bool drop_privileges(const std::string& user, const std::string& group);
