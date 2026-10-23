#ifndef PORTABLE_HINT_H__
#define PORTABLE_HINT_H__

#define ARCH_VERSION_NUMBER(major, minor, patch) ((((major) % 100) * 10000000) + (((minor) % 100) * 100000) + ((patch) % 100000))

#define ARCH_VERSION_NUMBER_MAX ARCH_VERSION_NUMBER(99, 99, 99999)

#define ARCH_VERSION_NUMBER_ZERO ARCH_VERSION_NUMBER(0, 0, 0)

#define ARCH_VERSION_NUMBER_MIN ARCH_VERSION_NUMBER(0, 0, 1)

#define ARCH_VERSION_NUMBER_AVAILABLE ARCH_VERSION_NUMBER_MIN

#define ARCH_VERSION_NUMBER_NOT_AVAILABLE ARCH_VERSION_NUMBER_ZERO

// arm.h

#define ARCH_ARM ARCH_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__ARM_ARCH) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(_M_ARM) || defined(__arm__) ||    \
    defined(__arm64) || defined(__thumb__) || defined(_M_ARM64) || defined(__aarch64__) || defined(__AARCH64EL__) ||               \
    defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) ||                 \
    defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6KZ__) || defined(__ARM_ARCH_6T2__) ||              \
    defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_4T__) || defined(__ARM_ARCH_4__)
#undef ARCH_ARM
#if !defined(ARCH_ARM) && defined(__ARM_ARCH)
#define ARCH_ARM ARCH_VERSION_NUMBER(__ARM_ARCH, 0, 0)
#endif
#if !defined(ARCH_ARM) && defined(__TARGET_ARCH_ARM)
#define ARCH_ARM ARCH_VERSION_NUMBER(__TARGET_ARCH_ARM, 0, 0)
#endif
#if !defined(ARCH_ARM) && defined(__TARGET_ARCH_THUMB)
#define ARCH_ARM ARCH_VERSION_NUMBER(__TARGET_ARCH_THUMB, 0, 0)
#endif
#if !defined(ARCH_ARM) && defined(_M_ARM)
#define ARCH_ARM ARCH_VERSION_NUMBER(_M_ARM, 0, 0)
#endif
#if !defined(ARCH_ARM) && (defined(__arm64) || defined(_M_ARM64) || defined(__aarch64__) || defined(__AARCH64EL__))
#define ARCH_ARM ARCH_VERSION_NUMBER(8, 0, 0)
#endif
#if !defined(ARCH_ARM) &&                                                                                                          \
    (defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__))
#define ARCH_ARM ARCH_VERSION_NUMBER(7, 0, 0)
#endif
#if !defined(ARCH_ARM) &&                                                                                                          \
    (defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6KZ__) || defined(__ARM_ARCH_6T2__))
#define ARCH_ARM ARCH_VERSION_NUMBER(6, 0, 0)
#endif
#if !defined(ARCH_ARM) && (defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__))
#define ARCH_ARM ARCH_VERSION_NUMBER(5, 0, 0)
#endif
#if !defined(ARCH_ARM) && (defined(__ARM_ARCH_4T__) || defined(__ARM_ARCH_4__))
#define ARCH_ARM ARCH_VERSION_NUMBER(4, 0, 0)
#endif
#if !defined(ARCH_ARM)
#define ARCH_ARM ARCH_VERSION_NUMBER_AVAILABLE
#endif
#endif

#if ARCH_ARM
#define ARCH_ARM_AVAILABLE
#endif

#if ARCH_ARM
#if ARCH_ARM >= ARCH_VERSION_NUMBER(8, 0, 0)
#undef ARCH_WORD_BITS_64
#define ARCH_WORD_BITS_64 ARCH_VERSION_NUMBER_AVAILABLE
#else
#undef ARCH_WORD_BITS_32
#define ARCH_WORD_BITS_32 ARCH_VERSION_NUMBER_AVAILABLE
#endif
#endif

#define ARCH_ARM_NAME "ARM"

// x86/32.h

#define ARCH_X86_32 ARCH_VERSION_NUMBER_NOT_AVAILABLE

#if defined(i386) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || defined(__i386) ||        \
    defined(_M_IX86) || defined(_X86_) || defined(__THW_INTEL__) || defined(__I86__) || defined(__INTEL__)
#undef ARCH_X86_32
#if !defined(ARCH_X86_32) && defined(__I86__)
#define ARCH_X86_32 ARCH_VERSION_NUMBER(__I86__, 0, 0)
#endif
#if !defined(ARCH_X86_32) && defined(_M_IX86)
#define ARCH_X86_32 PREDEF_MAKE_10_VV00(_M_IX86)
#endif
#if !defined(ARCH_X86_32) && defined(__i686__)
#define ARCH_X86_32 ARCH_VERSION_NUMBER(6, 0, 0)
#endif
#if !defined(ARCH_X86_32) && defined(__i586__)
#define ARCH_X86_32 ARCH_VERSION_NUMBER(5, 0, 0)
#endif
#if !defined(ARCH_X86_32) && defined(__i486__)
#define ARCH_X86_32 ARCH_VERSION_NUMBER(4, 0, 0)
#endif
#if !defined(ARCH_X86_32) && defined(__i386__)
#define ARCH_X86_32 ARCH_VERSION_NUMBER(3, 0, 0)
#endif
#if !defined(ARCH_X86_32)
#define ARCH_X86_32 ARCH_VERSION_NUMBER_AVAILABLE
#endif
#endif

#if ARCH_X86_32
#define ARCH_X86_32_AVAILABLE
#endif

#if ARCH_X86_32
#undef ARCH_WORD_BITS_32
#define ARCH_WORD_BITS_32 ARCH_VERSION_NUMBER_AVAILABLE
#endif

#define ARCH_X86_32_NAME "Intel x86-32"

// x86/64.h

#define ARCH_X86_64 ARCH_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__x86_64) || defined(__x86_64__) || defined(__amd64__) || defined(__amd64) || defined(_M_X64)
#undef ARCH_X86_64
#define ARCH_X86_64 ARCH_VERSION_NUMBER_AVAILABLE
#endif

#if ARCH_X86_64
#define ARCH_X86_64_AVAILABLE
#endif

#if ARCH_X86_64
#undef ARCH_WORD_BITS_64
#define ARCH_WORD_BITS_64 ARCH_VERSION_NUMBER_AVAILABLE
#endif

#define ARCH_X86_64_NAME "Intel x86-64"

#define ARCH_X86 ARCH_VERSION_NUMBER_NOT_AVAILABLE

#if ARCH_X86_32 || ARCH_X86_64
#undef ARCH_X86
#define ARCH_X86 ARCH_VERSION_NUMBER_AVAILABLE
#endif

#if ARCH_X86
#define ARCH_X86_AVAILABLE
#endif

#define ARCH_X86_NAME "Intel x86"

#if defined(ARCH_ARM_AVAILABLE)
#if defined(ARCH_WORD_BITS_64)
#define HINT_SPIN_LOOP() __asm__ __volatile__("yield" ::: "memory")
#elif defined(ARCH_WORD_BITS_32)
#define HINT_SPIN_LOOP() __asm__ __volatile__("yield" ::: "memory")
#else
#error architecture not supported: ARM must be 32-bit or 64-bit
#endif
#elif defined(ARCH_X86_AVAILABLE)
#if defined(ARCH_WORD_BITS_64)
#define HINT_SPIN_LOOP() __asm__ __volatile__("pause" ::: "memory")
#elif defined(ARCH_WORD_BITS_32)
#define HINT_SPIN_LOOP() __asm__ __volatile__("pause" ::: "memory")
#else
#define HINT_SPIN_LOOP() __asm__ __volatile__("" ::: "memory");
#endif
#else
#define HINT_SPIN_LOOP() __asm__ __volatile__("" ::: "memory");
#endif

#endif
