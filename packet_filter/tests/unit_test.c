/*
 * Kernel Module Unit Tests for Packet Filter
 * 
 * These tests are built into the kernel module and can be
 * run via debugfs or module parameters.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include "packet_filter.h"

#define TEST_MAX_RULES 100
#define TEST_MAX_PACKETS 1000

struct test_context {
    struct packet_filter *pf;
    int test_count;
    int passed_count;
    int failed_count;
};

static struct dentry *test_dir;
static struct test_context test_ctx;

/* Test 1: Rule validation */
static int test_rule_validation(struct test_context *ctx)
{
    struct pf_rule rule;
    int i;
    
    pr_info("Test 1: Rule validation...\n");
    
    /* Test valid rule */
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_TCP;
    rule.src_port = htons(1000);
    rule.dst_port = htons(80);
    rule.action = PF_ACTION_DROP;
    
    if (pf_add_rule(ctx->pf, &rule) < 0) {
        pr_err("  FAILED: Valid rule rejected\n");
        return -1;
    }
    
    pr_info("  PASSED: Valid rule accepted\n");
    return 0;
}

/* Test 2: Memory allocation */
static int test_memory_allocation(struct test_context *ctx)
{
    struct pf_rule *rules;
    int i;
    
    pr_info("Test 2: Memory allocation...\n");
    
    rules = kmalloc_array(TEST_MAX_RULES, sizeof(struct pf_rule), GFP_KERNEL);
    if (!rules) {
        pr_err("  FAILED: kmalloc_array failed\n");
        return -1;
    }
    
    /* Fill with test data */
    for (i = 0; i < TEST_MAX_RULES; i++) {
        rules[i].protocol = (i % 3) + 1;
        rules[i].src_port = htons(1000 + i);
        rules[i].dst_port = htons(80 + (i % 10));
        rules[i].action = (i % 2) ? PF_ACTION_DROP : PF_ACTION_LOG;
    }
    
    kfree(rules);
    pr_info("  PASSED: Memory allocation test\n");
    return 0;
}

/* Test 3: Locking behavior */
static int test_locking(struct test_context *ctx)
{
    unsigned long flags;
    
    pr_info("Test 3: Locking behavior...\n");
    
    /* Test spinlock */
    spin_lock_irqsave(&ctx->pf->lock, flags);
    
    /* Critical section - just verify lock is held */
    if (!spin_is_locked(&ctx->pf->lock)) {
        pr_err("  FAILED: Spinlock not held\n");
        spin_unlock_irqrestore(&ctx->pf->lock, flags);
        return -1;
    }
    
    spin_unlock_irqrestore(&ctx->pf->lock, flags);
    
    /* Test mutex */
    mutex_lock(&ctx->pf->config_lock);
    
    if (!mutex_is_locked(&ctx->pf->config_lock)) {
        pr_err("  FAILED: Mutex not held\n");
        mutex_unlock(&ctx->pf->config_lock);
        return -1;
    }
    
    mutex_unlock(&ctx->pf->config_lock);
    
    pr_info("  PASSED: Locking behavior test\n");
    return 0;
}

/* Test 4: Statistics tracking */
static int test_statistics(struct test_context *ctx)
{
    struct pf_stats initial_stats, current_stats;
    
    pr_info("Test 4: Statistics tracking...\n");
    
    /* Save initial stats */
    spin_lock(&ctx->pf->lock);
    memcpy(&initial_stats, &ctx->pf->stats, sizeof(initial_stats));
    spin_unlock(&ctx->pf->lock);
    
    /* Clear stats */
    spin_lock(&ctx->pf->lock);
    memset(&ctx->pf->stats, 0, sizeof(ctx->pf->stats));
    spin_unlock(&ctx->pf->lock);
    
    /* Verify cleared */
    spin_lock(&ctx->pf->lock);
    memcpy(&current_stats, &ctx->pf->stats, sizeof(current_stats));
    spin_unlock(&ctx->pf->lock);
    
    if (current_stats.total_packets != 0 ||
        current_stats.filtered_packets != 0) {
        pr_err("  FAILED: Statistics not cleared\n");
        return -1;
    }
    
    /* Restore stats */
    spin_lock(&ctx->pf->lock);
    memcpy(&ctx->pf->stats, &initial_stats, sizeof(initial_stats));
    spin_unlock(&ctx->pf->lock);
    
    pr_info("  PASSED: Statistics tracking test\n");
    return 0;
}

/* Test 5: FIFO operations */
static int test_fifo_operations(struct test_context *ctx)
{
    struct pf_packet_info packet;
    int i, ret;
    
    pr_info("Test 5: FIFO operations...\n");
    
    /* Test FIFO put */
    for (i = 0; i < 10; i++) {
        memset(&packet, 0, sizeof(packet));
        packet.timestamp = ktime_get_ns();
        packet.src_ip = htonl(0xC0A80101 + i);
        packet.dst_ip = htonl(0x08080808);  /* 8.8.8.8 */
        packet.protocol = IPPROTO_TCP;
        packet.length = 100 + i;
        packet.action = PF_ACTION_LOG;
        
        ret = kfifo_in(&ctx->pf->log_fifo, &packet, 1);
        if (ret != 1) {
            pr_err("  FAILED: FIFO put failed at iteration %d\n", i);
            return -1;
        }
    }
    
    /* Test FIFO get */
    for (i = 0; i < 10; i++) {
        ret = kfifo_out(&ctx->pf->log_fifo, &packet, 1);
        if (ret != 1) {
            pr_err("  FAILED: FIFO get failed at iteration %d\n", i);
            return -1;
        }
    }
    
    pr_info("  PASSED: FIFO operations test\n");
    return 0;
}

/* Run all tests */
static void run_all_tests(struct test_context *ctx)
{
    int (*test_functions[])(struct test_context *) = {
        test_rule_validation,
        test_memory_allocation,
        test_locking,
        test_statistics,
        test_fifo_operations,
        NULL
    };
    
    int i, result;
    
    ctx->test_count = 0;
    ctx->passed_count = 0;
    ctx->failed_count = 0;
    
    pr_info("=== Starting Packet Filter Unit Tests ===\n");
    
    for (i = 0; test_functions[i]; i++) {
        ctx->test_count++;
        
        result = test_functions[i](ctx);
        if (result == 0) {
            ctx->passed_count++;
        } else {
            ctx->failed_count++;
        }
    }
    
    pr_info("=== Test Results ===\n");
    pr_info("Total tests: %d\n", ctx->test_count);
    pr_info("Passed: %d\n", ctx->passed_count);
    pr_info("Failed: %d\n", ctx->failed_count);
    
    if (ctx->failed_count == 0) {
        pr_info("ALL TESTS PASSED\n");
    } else {
        pr_info("SOME TESTS FAILED\n");
    }
}

/* Debugfs interface */
static int test_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Packet Filter Unit Tests\n");
    seq_printf(m, "=======================\n\n");
    
    seq_printf(m, "Test Context:\n");
    seq_printf(m, "  Module: %p\n", test_ctx.pf);
    seq_printf(m, "  Test Count: %d\n", test_ctx.test_count);
    seq_printf(m, "  Passed: %d\n", test_ctx.passed_count);
    seq_printf(m, "  Failed: %d\n", test_ctx.failed_count);
    
    seq_printf(m, "\nAvailable Commands:\n");
    seq_printf(m, "  echo run > /sys/kernel/debug/packet_filter/test\n");
    seq_printf(m, "  echo reset > /sys/kernel/debug/packet_filter/test\n");
    
    return 0;
}

static int test_open(struct inode *inode, struct file *file)
{
    return single_open(file, test_show, NULL);
}

static ssize_t test_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
    char cmd[32];
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buf, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    /* Remove newline */
    if (cmd[count - 1] == '\n')
        cmd[count - 1] = '\0';
    
    if (strcmp(cmd, "run") == 0) {
        run_all_tests(&test_ctx);
        pr_info("Tests executed via debugfs\n");
    } else if (strcmp(cmd, "reset") == 0) {
        memset(&test_ctx, 0, sizeof(test_ctx));
        pr_info("Test context reset\n");
    } else {
        pr_warn("Unknown test command: %s\n", cmd);
        return -EINVAL;
    }
    
    return count;
}

static const struct file_operations test_fops = {
    .owner = THIS_MODULE,
    .open = test_open,
    .read = seq_read,
    .write = test_write,
    .llseek = seq_lseek,
    .release = single_release,
};

/* Module parameter for running tests on load */
static bool run_tests_on_load = false;
module_param(run_tests_on_load, bool, 0644);
MODULE_PARM_DESC(run_tests_on_load, "Run unit tests when module loads");

/* Initialize testing subsystem */
int pf_test_init(struct packet_filter *pf)
{
    test_ctx.pf = pf;
    
    /* Create debugfs directory */
    test_dir = debugfs_create_dir("packet_filter", NULL);
    if (!test_dir) {
        pr_err("Failed to create debugfs directory\n");
        return -ENOMEM;
    }
    
    /* Create test file */
    debugfs_create_file("test", 0644, test_dir, NULL, &test_fops);
    
    /* Create statistics file */
    debugfs_create_u64("tests_run", 0444, test_dir, &test_ctx.test_count);
    debugfs_create_u64("tests_passed", 0444, test_dir, &test_ctx.passed_count);
    debugfs_create_u64("tests_failed", 0444, test_dir, &test_ctx.failed_count);
    
    pr_info("Unit test subsystem initialized\n");
    
    /* Run tests if requested */
    if (run_tests_on_load) {
        pr_info("Running tests on module load...\n");
        run_all_tests(&test_ctx);
    }
    
    return 0;
}

/* Cleanup testing subsystem */
void pf_test_cleanup(void)
{
    if (test_dir)
        debugfs_remove_recursive(test_dir);
    
    pr_info("Unit test subsystem cleaned up\n");
}
