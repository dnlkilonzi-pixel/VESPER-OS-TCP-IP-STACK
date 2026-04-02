/*
 * types.h - Fundamental type definitions for VESPER OS
 *
 * In bare-metal mode (no libc) we define our own stdint-compatible types.
 * In TEST_HOST mode (host compiler + libc) we delegate to <stdint.h> so
 * there are no duplicate-typedef conflicts.
 */

#ifndef VESPER_TYPES_H
#define VESPER_TYPES_H

#ifdef TEST_HOST
/* Host build: use the system stdint / stdbool / stddef headers */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t bool;
#ifndef true
#define true  1
#endif
#ifndef false
#define false 0
#endif
#else
/* Bare-metal build: define our own minimal type set */

/* Fixed-width integer types */
typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;

typedef signed char         int8_t;
typedef signed short        int16_t;
typedef signed int          int32_t;
typedef signed long long    int64_t;

/* Boolean type */
typedef uint8_t bool;
#define true  1
#define false 0

/* NULL pointer */
#ifndef NULL
#define NULL ((void *)0)
#endif

/* Size type (pointer-width on x86) */
typedef unsigned long size_t;

#endif /* TEST_HOST */

/* Convenience aliases (available in both modes) */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/*
 * Network byte order helpers (big-endian ↔ little-endian).
 *
 * x86 is little-endian; network protocols are big-endian.
 * We implement these as inline macros rather than function calls
 * to keep overhead zero in a bare-metal kernel.
 */
#define HTONS(x) ((uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8)))
#define NTOHS(x) HTONS(x)

#define HTONL(x) \
    ((uint32_t)( \
        (((uint32_t)(x) & 0x000000FFU) << 24) | \
        (((uint32_t)(x) & 0x0000FF00U) <<  8) | \
        (((uint32_t)(x) & 0x00FF0000U) >>  8) | \
        (((uint32_t)(x) & 0xFF000000U) >> 24)   \
    ))
#define NTOHL(x) HTONL(x)

#endif /* VESPER_TYPES_H */
