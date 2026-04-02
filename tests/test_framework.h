/*
 * test_framework.h - Minimal test framework for VESPER OS
 *
 * Shared by all test files.  Counter variables are defined in test_main.c
 * and declared extern here.
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>

/* Counters defined in test_main.c */
extern int g_tests_run;
extern int g_tests_passed;
extern int g_tests_failed;

#define TEST_PASS(name) \
    do { g_tests_run++; g_tests_passed++; \
         printf("  PASS: %s\n", (name)); } while (0)

#define TEST_FAIL(name, msg) \
    do { g_tests_run++; g_tests_failed++; \
         printf("  FAIL: %s - %s\n", (name), (msg)); } while (0)

#define ASSERT(name, expr) \
    do { if (expr) TEST_PASS(name); \
         else      TEST_FAIL(name, #expr " was false"); } while (0)

#endif /* TEST_FRAMEWORK_H */
