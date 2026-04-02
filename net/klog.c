/*
 * klog.c - Minimal kernel logging for VESPER OS
 *
 * In bare-metal mode: outputs to COM1 serial port via x86 I/O port
 * instructions.  COM1 (I/O base 0x3F8) works without explicit init on
 * most QEMU configurations (115200 baud, 8N1 by default).
 *
 * In TEST_HOST mode: outputs to stdout via putchar() so the same code
 * can be exercised under a Linux host compiler for unit testing.
 */

#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                        */
/* ------------------------------------------------------------------ */

/* Default: show DEBUG and above */
int klog_level = KLOG_DEBUG;

/* ------------------------------------------------------------------ */
/* Output primitive: write one character                               */
/* ------------------------------------------------------------------ */

#ifdef TEST_HOST
#include <stdio.h>

void klog_putchar(char c)
{
    putchar((unsigned char)c);
}

#else /* bare-metal */

/* COM1 base I/O port */
#define COM1_PORT  0x3F8

static inline void outb(uint16_t port, uint8_t val)
{
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t ret;
    __asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

/* Poll until the transmit holding register is empty */
static void serial_wait_tx(void)
{
    /* Bit 5 of the Line Status Register: Transmitter Holding Register Empty */
    while ((inb(COM1_PORT + 5) & 0x20) == 0)
        ;
}

void klog_putchar(char c)
{
    serial_wait_tx();
    outb(COM1_PORT, (uint8_t)c);
}

#endif /* TEST_HOST */

void klog_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            klog_putchar('\r');   /* CRLF for serial terminals */
        klog_putchar(*s);
        s++;
    }
}

/* Hex digit lookup table */
static const char hex_digits[] = "0123456789ABCDEF";

void klog_hex8(uint8_t v)
{
    klog_putchar(hex_digits[(v >> 4) & 0xF]);
    klog_putchar(hex_digits[v & 0xF]);
}

void klog_hex16(uint16_t v)
{
    klog_hex8((uint8_t)(v >> 8));
    klog_hex8((uint8_t)(v & 0xFF));
}

void klog_hex32(uint32_t v)
{
    klog_hex16((uint16_t)(v >> 16));
    klog_hex16((uint16_t)(v & 0xFFFF));
}

void klog_udec(uint32_t v)
{
    char buf[11]; /* max 10 digits for UINT32_MAX + NUL */
    int  i = 10;
    buf[10] = '\0';
    if (v == 0) {
        klog_putchar('0');
        return;
    }
    while (v > 0 && i > 0) {
        buf[--i] = '0' + (char)(v % 10);
        v /= 10;
    }
    klog_puts(buf + i);
}

void klog_mac(const uint8_t *mac)
{
    int i;
    for (i = 0; i < 6; i++) {
        if (i > 0)
            klog_putchar(':');
        klog_hex8(mac[i]);
    }
}

void klog_ipv4(uint32_t ip)
{
    /* ip is in host byte order: octet A is in bits [31:24] */
    klog_udec((ip >> 24) & 0xFF);
    klog_putchar('.');
    klog_udec((ip >> 16) & 0xFF);
    klog_putchar('.');
    klog_udec((ip >>  8) & 0xFF);
    klog_putchar('.');
    klog_udec(ip & 0xFF);
}
