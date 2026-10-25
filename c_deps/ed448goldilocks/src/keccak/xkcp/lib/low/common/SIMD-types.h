/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _SIMD_types_h_
#define _SIMD_types_h_

/*
 * Common SIMD vector type definitions to avoid C99 typedef redefinition errors.
 * Include this header instead of defining V128/V256/V512 locally in headers.
 */

#include <immintrin.h>

#ifndef V128_typedef_defined
#define V128_typedef_defined
typedef __m128i V128;
#endif

#ifndef V256_typedef_defined
#define V256_typedef_defined
typedef __m256i V256;
#endif

#ifndef V512_typedef_defined
#define V512_typedef_defined
typedef __m512i V512;
#endif

#endif /* _SIMD_types_h_ */
