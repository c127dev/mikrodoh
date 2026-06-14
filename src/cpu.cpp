#include "cpu.h"

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#elif defined(__aarch64__) || defined(__arm__)
#include <sys/auxv.h>

// Values from the kernel uapi. Defined here so the build does not need the
// kernel headers package just for asm/hwcap.h.
#if defined(__aarch64__) && !defined(HWCAP_AES)
#define HWCAP_AES (1u << 3)
#endif
#if defined(__arm__) && !defined(HWCAP2_AES)
#define HWCAP2_AES (1u << 0)
#endif
#endif

namespace cpu {

bool has_aes() {
#if defined(__x86_64__) || defined(__i386__)
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
    return (ecx & bit_AES) != 0;
#elif defined(__aarch64__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#elif defined(__arm__)
    // 32-bit ARM reports the v8 crypto extensions in HWCAP2, not HWCAP.
    return (getauxval(AT_HWCAP2) & HWCAP2_AES) != 0;
#else
    // RISC-V and anything else: no probe, so ChaCha20 is chosen. The RISC-V
    // AES extensions (Zkne, Zvkned) are absent from the SoCs this runs on, and
    // OpenSSL falls back to table-driven AES there anyway.
    return false;
#endif
}

const char* arch() {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "i386";
#elif defined(__aarch64__)
    return "aarch64";
#elif defined(__arm__)
    return "arm";
#elif defined(__riscv) && __riscv_xlen == 64
    return "riscv64";
#elif defined(__riscv)
    return "riscv32";
#else
    return "unknown";
#endif
}

}  // namespace cpu
