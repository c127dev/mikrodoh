#include "harness.h"

#include <cstdio>
#include <vector>

namespace th {

namespace {

struct Case {
    const char* name;
    Fn          fn;
};

// Function-local so registration during static init cannot outrun the
// container's own construction.
std::vector<Case>& cases() {
    static std::vector<Case> v;
    return v;
}

int         g_case_failures = 0;
const char* g_current       = "";

}  // namespace

Registrar::Registrar(const char* name, Fn fn) { cases().push_back(Case{name, fn}); }

void fail(const char* file, int line, const char* expr) {
    g_case_failures++;
    std::printf("    %s:%d: CHECK(%s)\n", file, line, expr);
}

int run_all() {
    int failed = 0;

    for (const Case& c : cases()) {
        g_current       = c.name;
        g_case_failures = 0;

        c.fn();

        if (g_case_failures == 0) {
            std::printf("ok   %s\n", c.name);
        } else {
            std::printf("FAIL %s (%d checks)\n", c.name, g_case_failures);
            failed++;
        }
    }

    std::printf("\n%zu cases, %d failed\n", cases().size(), failed);
    return failed == 0 ? 0 : 1;
}

}  // namespace th

int main() { return th::run_all(); }
