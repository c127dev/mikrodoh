# MikroDoH unit tests

Unit tests for the code on `main`. They build against a checkout of that
branch; nothing here is needed to build or run the daemon.

## Run them

```bash
git worktree add .tests tests
cmake -S .tests -B build-tests -DMIKRODOH_SRC="$PWD"
cmake --build build-tests -j "$(nproc)"
./build-tests/mikrodoh_tests
```

`MIKRODOH_SRC` is the checkout of `main` to test, and defaults to the parent
directory of this one. ASan and UBSan are on; `-DMIKRODOH_SANITIZE=OFF` turns
them off.

## Add a case

```cpp
#include "harness.h"

TEST(what_the_code_should_do) {
    CHECK(some_expression);
}
```

Cases register themselves, so a new file only has to be listed in
`CMakeLists.txt`. A failing `CHECK` prints its file, line and expression, and
the run exits non-zero.

Only code that can be tested without a network or a listening socket belongs
here. `scripts/test.sh` on `main` covers the end-to-end path.

## CI

`.github/workflows/test.yml` runs on `workflow_dispatch`, naming the source ref
to test. It also has a `push` trigger on this branch whose only job is to get
the workflow indexed, because GitHub will not dispatch a workflow it has never
seen; that run gates itself off and does nothing.

Pushes to `main` cannot trigger it directly, since a push only ever runs
workflows present on the ref that was pushed. A poller watching `main`
dispatches this workflow with `source_ref` pinned to the commit.
