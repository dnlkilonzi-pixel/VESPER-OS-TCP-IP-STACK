/*
 * test_host_shim.h - Host-build compatibility shim for VESPER OS tests
 *
 * When building tests on a Linux host (TEST_HOST defined), this header
 * provides any test-specific convenience helpers.  The actual klog and
 * type definitions handle TEST_HOST themselves via #ifdef guards.
 */

#ifndef TEST_HOST_SHIM_H
#define TEST_HOST_SHIM_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#endif /* TEST_HOST_SHIM_H */
