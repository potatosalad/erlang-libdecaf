#ifndef SPINLOCK_H
#define SPINLOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdatomic.h>

#include "portable_hint.h"

/* Type Definitions */

typedef struct spinlock_s spinlock_t;

struct spinlock_s {
    atomic_flag value;
};

/* Function Declarations */

static void spinlock_init(volatile spinlock_t *s);
static void spinlock_lock(volatile spinlock_t *s);
static void spinlock_unlock(volatile spinlock_t *s);

/* Inline Function Definitions */

inline void
spinlock_init(volatile spinlock_t *s)
{
    (void)atomic_flag_clear_explicit(&s->value, memory_order_seq_cst);
}

inline void
spinlock_lock(volatile spinlock_t *s)
{

#if defined(__GNUC__)
#define INTRINSICS_UNLIKELY(x) (__builtin_expect(!!(x), 0))
#else
#define INTRINSICS_UNLIKELY(x) x
#endif

    while (INTRINSICS_UNLIKELY(atomic_flag_test_and_set_explicit(&s->value, memory_order_acquire))) {
        HINT_SPIN_LOOP();
    }
    return;

#undef INTRINSICS_UNLIKELY
}

inline void
spinlock_unlock(volatile spinlock_t *s)
{
    (void)atomic_flag_clear_explicit(&s->value, memory_order_release);
    return;
}

#ifdef __cplusplus
}
#endif

#endif
