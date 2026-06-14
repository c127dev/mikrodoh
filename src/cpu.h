#pragma once

namespace cpu {

// True when the CPU has an AES engine: x86 AES-NI or the ARMv8 crypto
// extensions. False on ARMv7 cores such as the Cortex-A15.
bool has_aes();

const char* arch();

}  // namespace cpu
