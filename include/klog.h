/*
 * klog.h - Minimal kernel logging for VESPER OS
 *
 * Since we have no printf(), we implement a minimal serial/VGA logger.
 * All network stack components use klog_* macros for diagnostics.
 */

#ifndef VESPER_KLOG_H
#define VESPER_KLOG_H

#include "types.h"

/* Log levels */
#define KLOG_DEBUG  0
#define KLOG_INFO   1
#define KLOG_WARN   2
#define KLOG_ERROR  3

/*
 * klog_level - current minimum log level
 *
 * Messages below this level are suppressed.  Set to KLOG_DEBUG to see
 * all network tracing output.
 */
extern int klog_level;

/* ------------------------------------------------------------------ */
/* Core output primitives                                              */
/* ------------------------------------------------------------------ */

/* Write a single character to the serial port (COM1) */
void klog_putchar(char c);

/* Write a NUL-terminated string */
void klog_puts(const char *s);

/* Write an unsigned 8-bit value as two hex digits */
void klog_hex8(uint8_t v);

/* Write an unsigned 16-bit value as four hex digits */
void klog_hex16(uint16_t v);

/* Write an unsigned 32-bit value as eight hex digits */
void klog_hex32(uint32_t v);

/* Write an unsigned decimal integer */
void klog_udec(uint32_t v);

/* Write a 6-byte MAC address as "AA:BB:CC:DD:EE:FF" */
void klog_mac(const uint8_t *mac);

/* Write a 4-byte IPv4 address (host byte order) as "A.B.C.D" */
void klog_ipv4(uint32_t ip);

/* ------------------------------------------------------------------ */
/* Level-tagged log macros                                             */
/* ------------------------------------------------------------------ */

#define KLOG(level, msg) \
    do { if ((level) >= klog_level) { klog_puts(msg); klog_puts("\r\n"); } } while (0)

#define KLOG_INFO_STR(msg)   KLOG(KLOG_INFO,  "[INFO]  " msg)
#define KLOG_WARN_STR(msg)   KLOG(KLOG_WARN,  "[WARN]  " msg)
#define KLOG_ERROR_STR(msg)  KLOG(KLOG_ERROR, "[ERROR] " msg)
#define KLOG_DEBUG_STR(msg)  KLOG(KLOG_DEBUG, "[DEBUG] " msg)

#endif /* VESPER_KLOG_H */
