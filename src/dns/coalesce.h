// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

struct Transfer;

class Coalescer {
public:
    bool join(Transfer* t);

    std::vector<Transfer*> release(Transfer* leader);

private:
    struct Pending {
        Transfer*              leader;
        std::vector<Transfer*> followers;
    };

    std::unordered_map<std::string, Pending> pending_;
};
