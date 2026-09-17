#include "harness.h"

#include "sandbox.h"

#include <cerrno>

#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

// Runs `f` in a child that has entered the sandbox and returns its exit code,
// so the filter never reaches the test process itself. -1 when the child did
// not exit normally.
template <typename F>
int in_sandbox(F f) {
    pid_t pid = fork();
    if (pid == 0) {
        if (!enter_sandbox()) _exit(100);
        _exit(f());
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

}  // namespace

TEST(the_sandbox_sets_no_new_privs) {
    CHECK(in_sandbox([] { return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 0 : 1; }) == 0);
}

TEST(the_sandbox_denies_exec) {
    CHECK(in_sandbox([] {
        char* const argv[] = {const_cast<char*>("/bin/true"), nullptr};
        execv("/bin/true", argv);
        return errno == EPERM ? 0 : 1;
    }) == 0);
}

TEST(the_sandbox_denies_a_uid_change) {
    CHECK(in_sandbox([] { return setuid(getuid()) != 0 && errno == EPERM ? 0 : 1; }) == 0);
}

TEST(the_sandbox_allows_ordinary_calls) {
    CHECK(in_sandbox([] {
        int fds[2];
        if (pipe(fds) != 0) return 1;
        if (write(fds[1], "x", 1) != 1) return 1;
        char c = 0;
        return read(fds[0], &c, 1) == 1 && c == 'x' ? 0 : 1;
    }) == 0);
}
