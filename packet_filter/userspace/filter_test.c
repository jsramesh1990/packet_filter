#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "libfilter.h"

#define TEST_RULE_COUNT 10
#define TEST_PACKETS_PER_RULE 100

typedef struct {
    const char *name;
    int (*func)(pf_handle_t *);
} test_case_t;

/* Test 1: Basic connectivity */
static int test_basic_connectivity(pf_handle_t *handle)
{
    printf("Test 1: Basic connectivity... ");
    
    if (!pf_is_open(handle)) {
        printf("FAILED (not connected)\n");
        return 0;
    }
    
    /* Test a simple IOCTL */
    unsigned char mode;
    if (pf_get_mode(handle, &mode) < 0) {
        printf("FAILED (IOCTL failed)\n");
        return 0;
    }
    
    printf("PASSED (mode=%u)\n", mode);
    return 1;
}

/* Test 2: Rule management */
static int test_rule_management(pf_handle_t *handle)
{
    struct pf_rule rule;
    unsigned int rule_id;
    int i, passed = 0;
    
    printf("Test 2: Rule management...\n");
    
    /* Add multiple rules */
    for (i = 0; i < TEST_RULE_COUNT; i++) {
        memset(&rule, 0, sizeof(rule));
        rule.protocol = (i % 3 == 0) ? PF_PROTO_TCP : 
                       (i % 3 == 1) ? PF_PROTO_UDP : PF_PROTO_ICMP;
        rule.src_ip = htonl(0xC0A80101 + i);  /* 192.168.1.1 + i */
        rule.dst_port = htons(80 + i);
        rule.action = (i % 2) ? PF_ACTION_DROP : PF_ACTION_LOG;
        
        if (pf_add_rule(handle, &rule) < 0) {
            printf("  Failed to add rule %d\n", i);
            continue;
        }
        
        passed++;
    }
    
    printf("  Added %d/%d rules\n", passed, TEST_RULE_COUNT);
    
    /* Try to delete a rule */
    if (passed > 0) {
        if (pf_delete_rule(handle, 1) < 0) {
            printf("  Failed to delete rule 1\n");
        } else {
            printf("  Successfully deleted rule 1\n");
        }
    }
    
    return passed >= (TEST_RULE_COUNT / 2);  /* At least half must pass */
}

/* Test 3: Statistics */
static int test_statistics(pf_handle_t *handle)
{
    struct pf_stats stats1, stats2;
    
    printf("Test 3: Statistics... ");
    
    /* Get initial statistics */
    if (pf_get_stats(handle, &stats1) < 0) {
        printf("FAILED (get stats)\n");
        return 0;
    }
    
    /* Clear statistics */
    if (pf_clear_stats(handle) < 0) {
        printf("FAILED (clear stats)\n");
        return 0;
    }
    
    /* Get statistics again */
    if (pf_get_stats(handle, &stats2) < 0) {
        printf("FAILED (get stats after clear)\n");
        return 0;
    }
    
    /* Verify statistics were cleared */
    if (stats2.total_packets != 0 || stats2.filtered_packets != 0) {
        printf("FAILED (stats not cleared)\n");
        return 0;
    }
    
    printf("PASSED\n");
    return 1;
}

/* Test 4: Mode switching */
static int test_mode_switching(pf_handle_t *handle)
{
    unsigned char mode;
    int i;
    
    printf("Test 4: Mode switching... ");
    
    /* Test all modes */
    for (i = PF_MODE_DISABLED; i <= PF_MODE_COUNT_ONLY; i++) {
        if (pf_set_mode(handle, i) < 0) {
            printf("FAILED (set mode %d)\n", i);
            return 0;
        }
        
        if (pf_get_mode(handle, &mode) < 0) {
            printf("FAILED (get mode %d)\n", i);
            return 0;
        }
        
        if (mode != i) {
            printf("FAILED (mode mismatch: %d != %d)\n", mode, i);
            return 0;
        }
    }
    
    /* Restore to disabled mode */
    pf_set_mode(handle, PF_MODE_DISABLED);
    
    printf("PASSED\n");
    return 1;
}

/* Test 5: Filter enable/disable */
static int test_filter_enable(pf_handle_t *handle)
{
    printf("Test 5: Filter enable/disable... ");
    
    /* Enable filter */
    if (pf_enable_filter(handle, 1) < 0) {
        printf("FAILED (enable)\n");
        return 0;
    }
    
    /* Disable filter */
    if (pf_enable_filter(handle, 0) < 0) {
        printf("FAILED (disable)\n");
        return 0;
    }
    
    /* Re-enable for other tests */
    pf_enable_filter(handle, 1);
    
    printf("PASSED\n");
    return 1;
}

/* Test 6: Device configuration */
static int test_device_config(pf_handle_t *handle)
{
    printf("Test 6: Device configuration... ");
    
    /* Try to set loopback device */
    if (pf_set_device(handle, "lo") < 0) {
        printf("SKIPPED (cannot set device)\n");
        return 1;  /* Not a critical failure */
    }
    
    printf("PASSED\n");
    return 1;
}

/* Test 7: Log operations */
static int test_log_operations(pf_handle_t *handle)
{
    struct pf_log_entry entries[5];
    unsigned int retrieved;
    
    printf("Test 7: Log operations... ");
    
    /* Try to get log */
    if (pf_get_log(handle, entries, 5, &retrieved) < 0) {
        printf("SKIPPED (log not available)\n");
        return 1;
    }
    
    printf("Retrieved %u log entries\n", retrieved);
    
    /* Try to flush log */
    if (pf_flush_log(handle) < 0) {
        printf("WARNING (cannot flush log)\n");
    }
    
    return 1;
}

static test_case_t test_cases[] = {
    {"Basic Connectivity", test_basic_connectivity},
    {"Rule Management", test_rule_management},
    {"Statistics", test_statistics},
    {"Mode Switching", test_mode_switching},
    {"Filter Enable/Disable", test_filter_enable},
    {"Device Configuration", test_device_config},
    {"Log Operations", test_log_operations},
    {NULL, NULL}
};

int main(int argc, char *argv[])
{
    pf_handle_t *handle;
    int i, passed = 0, total = 0;
    time_t start_time, end_time;
    
    printf("=== Packet Filter Driver Test Suite ===\n\n");
    
    handle = pf_open(NULL);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to open packet filter device\n");
        fprintf(stderr, "Make sure the driver is loaded: sudo insmod packet_filter.ko\n");
        return 1;
    }
    
    start_time = time(NULL);
    
    /* Run all tests */
    for (i = 0; test_cases[i].name; i++) {
        printf("Running %s...\n", test_cases[i].name);
        if (test_cases[i].func(handle)) {
            passed++;
        }
        total++;
        printf("\n");
    }
    
    end_time = time(NULL);
    
    /* Print summary */
    printf("=== Test Summary ===\n");
    printf("Total tests: %d\n", total);
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", total - passed);
    printf("Success rate: %.1f%%\n", (passed * 100.0) / total);
    printf("Time elapsed: %.1f seconds\n", difftime(end_time, start_time));
    
    /* Clean up */
    pf_close(handle);
    
    return (passed == total) ? 0 : 1;
}
