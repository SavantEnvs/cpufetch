/* Stand-in for the Linux <asm/hwcap.h> the ARM backend includes (src/arm/midr.c). x86 kernel headers
 * have no such file; the values are the arm64 (HWCAP_x, HWCAP2_SVE2) and arm32 (HWCAP_NEON, HWCAP2_x)
 * uapi bits. The bits are tested against getauxval(), which the fuzz harness answers from the input. */
#ifndef CPUFETCH_STUB_ASM_HWCAP_H
#define CPUFETCH_STUB_ASM_HWCAP_H
#define HWCAP_FP     (1 << 0)
#define HWCAP_ASIMD  (1 << 1)
#define HWCAP_AES    (1 << 3)
#define HWCAP_SHA1   (1 << 5)
#define HWCAP_SHA2   (1 << 6)
#define HWCAP_CRC32  (1 << 7)
#define HWCAP_SVE    (1 << 22)
#define HWCAP_NEON   (1 << 12)
#define HWCAP2_SVE2  (1 << 1)
#define HWCAP2_AES   (1 << 0)
#define HWCAP2_SHA1  (1 << 2)
#define HWCAP2_SHA2  (1 << 3)
#define HWCAP2_CRC32 (1 << 4)
#endif
