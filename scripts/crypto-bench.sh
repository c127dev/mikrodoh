#!/bin/sh
# Measures the two AEADs the daemon chooses between, on this device, and
# reports whether the OpenSSL in use has its assembly paths compiled in.
# Run it on the target board: the numbers are what CIPHER=auto is guessing at.
set -eu

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl not found" >&2
    exit 1
fi

echo "== openssl =="
openssl version

if openssl version -f | grep -q -- '-DOPENSSL_NO_ASM'; then
    echo "assembly: DISABLED (built no-asm) - ChaCha20 and Poly1305 run as portable C"
else
    echo "assembly: enabled"
fi

echo
echo "== cpu =="
if [ -r /proc/cpuinfo ]; then
    grep -m1 -E '^(model name|Processor|CPU part)' /proc/cpuinfo || true
    grep -m1 -E '^(Features|flags)' /proc/cpuinfo | tr ' \t' '\n\n' \
        | grep -xE 'aes|neon|asimd|pmull' | sort -u | paste -sd' ' - || true
fi

echo
echo "== speed, 1500-byte records, 1000s of bytes/s =="
for alg in chacha20-poly1305 aes-128-gcm aes-256-gcm; do
    printf '%-20s ' "$alg"
    openssl speed -elapsed -evp "$alg" -bytes 1500 2>/dev/null \
        | tail -1 | awk '{ print $NF }'
done

echo
echo "Highest number wins. Set CIPHER accordingly if it disagrees with auto."
echo "A/B the assembly path on ARM with: OPENSSL_armcap=0 $0"
