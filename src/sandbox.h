#pragma once

// Sets no_new_privs and installs a seccomp filter that fails the syscalls this
// daemon never makes: exec, ptrace, mount and namespace changes, credential
// changes, module and kexec loading, bpf, keyrings. Threads started afterwards
// inherit it. False means it could not be applied, which must abort startup.
bool enter_sandbox();
