/*
 * test_main.c - Test runner for VESPER OS TCP/IP stack unit tests
 *
 * A minimal test harness: no external libraries required.
 * Results are printed to stdout (which maps to COM1 in VESPER OS, but
 * on a host build simply goes to the terminal).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "test_framework.h"

/* ------------------------------------------------------------------ */
/* Test counters (non-static — test files reference them via extern)  */
/* ------------------------------------------------------------------ */

int g_tests_run    = 0;
int g_tests_passed = 0;
int g_tests_failed = 0;

/* ------------------------------------------------------------------ */
/* External test suites                                                */
/* ------------------------------------------------------------------ */

void test_ethernet(void);
void test_ip(void);
void test_tcp(void);
void test_arp(void);

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("====================================\n");
    printf("  VESPER OS Network Stack Tests\n");
    printf("====================================\n\n");

    test_ethernet();
    test_ip();
    test_tcp();
    test_arp();

    printf("\n====================================\n");
    printf("  Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf(", %d FAILED", g_tests_failed);
    printf("\n====================================\n");

    return (g_tests_failed == 0) ? 0 : 1;
}
