/**
 * @file decaf/common.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Common utility headers for Decaf library.
 */

#ifndef __DECAF_COMMON_H__
#define __DECAF_COMMON_H__ 1

#include <stdint.h>
#if defined (__GNUC__)  // File only exists for GNU compilers
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Goldilocks' build flags default to hidden and stripping executables. */
/** @cond internal */
#if DOXYGEN || defined(__attribute__)
#define __attribute__(x)
#define NOINLINE
#endif

/* Aliasing MSVC preprocessing to GNU preprocessing */
#if defined _MSC_VER
#   define __attribute__(x)        // Turn off attribute code
#   define __attribute(x)
#   define __restrict__ __restrict  // Use MSVC restrict code
#   if defined _DLL
#       define DECAF_API_VIS __declspec(dllexport)  // MSVC for visibility
#   else
#       define DECAF_API_VIS __declspec(dllimport)
#   endif

//#   define DECAF_NOINLINE __declspec(noinline) // MSVC for noinline
//#   define DECAF_INLINE __forceinline // MSVC for always inline
//#   define DECAF_WARN_UNUSED _Check_return_    
#else // MSVC
#define DECAF_API_VIS __attribute__((visibility("default")))
#define DECAF_API_IMPORT
#endif

// The following are disabled for MSVC
#define DECAF_NOINLINE  __attribute__((noinline))
#define DECAF_INLINE inline __attribute__((always_inline,unused))
#define DECAF_WARN_UNUSED __attribute__((warn_unused_result))
#define DECAF_NONNULL __attribute__((nonnull))  
// Cribbed from libnotmuch
#if defined (__clang_major__) && __clang_major__ >= 3 \
    || defined (__GNUC__) && __GNUC__ >= 5 \
    || defined (__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ >= 5
#define DECAF_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
#else
#define DECAF_DEPRECATED(msg) __attribute__ ((deprecated))
#endif
/** @endcond */

/* Internal word types.
 *
 * Somewhat tricky.  This could be decided separately per platform.  However,
 * the structs do need to be all the same size and alignment on a given
 * platform to support dynamic linking, since even if you header was built
 * with eg arch_neon, you might end up linking a library built with arch_arm32.
 */
#ifndef DECAF_WORD_BITS
    #if (defined(__ILP64__) || defined(__amd64__) || defined(__x86_64__) || (((__UINT_FAST32_MAX__)>>30)>>30))
        #define DECAF_WORD_BITS 64 /**< The number of bits in a word */
    #else
        #define DECAF_WORD_BITS 32 /**< The number of bits in a word */
    #endif
#endif
    
#if DECAF_WORD_BITS == 64
typedef uint64_t decaf_word_t;      /**< Word size for internal computations */
typedef int64_t decaf_sword_t;      /**< Signed word size for internal computations */
typedef uint64_t decaf_bool_t;      /**< "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef __uint128_t decaf_dword_t;  /**< Double-word size for internal computations */
typedef __int128_t decaf_dsword_t;  /**< Signed double-word size for internal computations */
#elif DECAF_WORD_BITS == 32         /**< The number of bits in a word */
typedef uint32_t decaf_word_t;      /**< Word size for internal computations */
typedef int32_t decaf_sword_t;      /**< Signed word size for internal computations */
typedef uint32_t decaf_bool_t;      /**< "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef uint64_t decaf_dword_t;     /**< Double-word size for internal computations */
typedef int64_t decaf_dsword_t;     /**< Signed double-word size for internal computations */
#else
#error "Only supporting DECAF_WORD_BITS = 32 or 64 for now"
#endif
    
/* MSCV compiler doesn't like the trick to have -1 assigned to an unsigned int to
 * set it to all ones, so do it openly */
#if DECAF_WORD_BITS == 64
/** DECAF_TRUE = all ones so that DECAF_TRUE & x = x */
static const decaf_bool_t DECAF_TRUE = (decaf_bool_t)0xFFFFFFFFFFFFFFFF;
/** DECAF_WORD_ALL_SET : all ones */
static const decaf_word_t DECAF_WORD_ALL_SET = (decaf_word_t)0xFFFFFFFFFFFFFFFF;
/** DECAF_WORD_ALL_UNSET : all zeros */
static const decaf_word_t DECAF_WORD_ALL_UNSET = (decaf_word_t)0x0;
#elif DECAF_WORD_BITS == 32         /**< The number of bits in a word */
/** DECAF_TRUE = all ones so that DECAF_TRUE & x = x */
static const decaf_bool_t DECAF_TRUE = (decaf_bool_t)0xFFFFFFFF;
/** DECAF_WORD_ALL_SET : all ones */
static const decaf_word_t DECAF_WORD_ALL_SET = (decaf_word_t)0xFFFFFFFF;
/** DECAF_WORD_ALL_UNSET : all zeros */
static const decaf_word_t DECAF_WORD_ALL_UNSET = (decaf_word_t)0x0;
#else
#error "Only supporting DECAF_WORD_BITS = 32 or 64 for now"
#endif

/** DECAF_FALSE = 0 so that DECAF_FALSE & x = 0 */
static const decaf_bool_t DECAF_FALSE = 0;

/** Another boolean type used to indicate success or failure. */
typedef enum {
    DECAF_SUCCESS = -1, /**< The operation succeeded. */
    DECAF_FAILURE = 0   /**< The operation failed. */
} decaf_error_t;


/** Return success if x is true */
static DECAF_INLINE decaf_error_t
decaf_succeed_if(decaf_bool_t x) {
    return (decaf_error_t)x;
}

/** Return DECAF_TRUE iff x == DECAF_SUCCESS */
static DECAF_INLINE decaf_bool_t
decaf_successful(decaf_error_t e) {
    decaf_word_t succ = DECAF_SUCCESS;
    decaf_dword_t w = ((decaf_word_t)e) ^  succ;
    return (w-1)>>DECAF_WORD_BITS;
}
    
/** Overwrite data with zeros.  Uses memset_s if available. */
void DECAF_API_VIS decaf_bzero (
    void *data,
    size_t size
) DECAF_NONNULL;

/** Compare two buffers, returning DECAF_TRUE if they are equal. */
decaf_bool_t DECAF_API_VIS decaf_memeq (
    const void *data1,
    const void *data2,
    size_t size
) DECAF_NONNULL DECAF_WARN_UNUSED;
    
#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __DECAF_COMMON_H__ */
