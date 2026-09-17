#include "sandbox.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <vector>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

namespace {

#if defined(__x86_64__)
constexpr unsigned kArch = AUDIT_ARCH_X86_64;
#elif defined(__i386__)
constexpr unsigned kArch = AUDIT_ARCH_I386;
#elif defined(__aarch64__)
constexpr unsigned kArch = AUDIT_ARCH_AARCH64;
#elif defined(__arm__)
constexpr unsigned kArch = AUDIT_ARCH_ARM;
#elif defined(__riscv) && __riscv_xlen == 64
constexpr unsigned kArch = AUDIT_ARCH_RISCV64;
#else
constexpr unsigned kArch = 0;
#endif

// Numbers differ per architecture and some calls do not exist on every one,
// hence the guards.
const std::vector<unsigned> denied = {
#ifdef __NR_execve
    __NR_execve,
#endif
#ifdef __NR_execveat
    __NR_execveat,
#endif
#ifdef __NR_ptrace
    __NR_ptrace,
#endif
#ifdef __NR_process_vm_readv
    __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
    __NR_process_vm_writev,
#endif
#ifdef __NR_mount
    __NR_mount,
#endif
#ifdef __NR_umount2
    __NR_umount2,
#endif
#ifdef __NR_pivot_root
    __NR_pivot_root,
#endif
#ifdef __NR_chroot
    __NR_chroot,
#endif
#ifdef __NR_unshare
    __NR_unshare,
#endif
#ifdef __NR_setns
    __NR_setns,
#endif
#ifdef __NR_setuid
    __NR_setuid,
#endif
#ifdef __NR_setgid
    __NR_setgid,
#endif
#ifdef __NR_setreuid
    __NR_setreuid,
#endif
#ifdef __NR_setregid
    __NR_setregid,
#endif
#ifdef __NR_setresuid
    __NR_setresuid,
#endif
#ifdef __NR_setresgid
    __NR_setresgid,
#endif
#ifdef __NR_setgroups
    __NR_setgroups,
#endif
#ifdef __NR_setuid32
    __NR_setuid32,
#endif
#ifdef __NR_setgid32
    __NR_setgid32,
#endif
#ifdef __NR_setreuid32
    __NR_setreuid32,
#endif
#ifdef __NR_setregid32
    __NR_setregid32,
#endif
#ifdef __NR_setresuid32
    __NR_setresuid32,
#endif
#ifdef __NR_setresgid32
    __NR_setresgid32,
#endif
#ifdef __NR_setgroups32
    __NR_setgroups32,
#endif
#ifdef __NR_init_module
    __NR_init_module,
#endif
#ifdef __NR_finit_module
    __NR_finit_module,
#endif
#ifdef __NR_delete_module
    __NR_delete_module,
#endif
#ifdef __NR_kexec_load
    __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
    __NR_kexec_file_load,
#endif
#ifdef __NR_reboot
    __NR_reboot,
#endif
#ifdef __NR_swapon
    __NR_swapon,
#endif
#ifdef __NR_swapoff
    __NR_swapoff,
#endif
#ifdef __NR_bpf
    __NR_bpf,
#endif
#ifdef __NR_perf_event_open
    __NR_perf_event_open,
#endif
#ifdef __NR_userfaultfd
    __NR_userfaultfd,
#endif
#ifdef __NR_keyctl
    __NR_keyctl,
#endif
#ifdef __NR_add_key
    __NR_add_key,
#endif
#ifdef __NR_request_key
    __NR_request_key,
#endif
#ifdef __NR_personality
    __NR_personality,
#endif
#ifdef __NR_acct
    __NR_acct,
#endif
};

void fail(const char* what) {
    std::cerr << "Failed to enter the sandbox: " << what << ": " << std::strerror(errno) << "\n";
}

}  // namespace

bool enter_sandbox() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fail("no_new_privs");
        return false;
    }

    if (kArch == 0) {
        std::cerr << "No seccomp filter for this architecture, no_new_privs only\n";
        return true;
    }

    std::vector<sock_filter> prog;

    // A syscall made through another ABI (x32, a 32-bit compat entry) has other
    // numbers, so it is killed rather than matched against the wrong list.
    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)));
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kArch, 1, 0));
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)));
#if defined(__x86_64__)
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1));  // __X32_SYSCALL_BIT
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#endif

    for (unsigned nr : denied) {
        prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    }
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    sock_fprog fprog{static_cast<unsigned short>(prog.size()), prog.data()};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) != 0) {
        fail("seccomp");
        return false;
    }

    std::cout << "Sandbox: no_new_privs, seccomp denies " << denied.size() << " syscalls\n";
    return true;
}
