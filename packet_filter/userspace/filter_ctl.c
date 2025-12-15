#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "libfilter.h"

#define VERSION "1.0.0"

static struct option long_options[] = {
    {"add-rule", required_argument, 0, 'a'},
    {"del-rule", required_argument, 0, 'd'},
    {"get-stats", no_argument, 0, 's'},
    {"clear-stats", no_argument, 0, 'S'},
    {"set-mode", required_argument, 0, 'm'},
    {"get-mode", no_argument, 0, 'M'},
    {"enable-filter", required_argument, 0, 'e'},
    {"get-log", optional_argument, 0, 'l'},
    {"flush-log", no_argument, 0, 'L'},
    {"set-device", required_argument, 0, 'i'},
    {"list-rules", no_argument, 0, 'r'},
    {"clear-rules", no_argument, 0, 'R'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"verbose", no_argument, 0, 'V'},
    {0, 0, 0, 0}
};

static void print_help(const char *progname)
{
    printf("Packet Filter Control Utility v%s\n\n", VERSION);
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -a, --add-rule RULE          Add a filter rule\n");
    printf("  -d, --del-rule ID            Delete rule by ID\n");
    printf("  -r, --list-rules             List all rules\n");
    printf("  -R, --clear-rules            Clear all rules\n");
    printf("  -s, --get-stats              Get filter statistics\n");
    printf("  -S, --clear-stats            Clear statistics\n");
    printf("  -m, --set-mode MODE          Set filter mode (0-3)\n");
    printf("  -M, --get-mode               Get current filter mode\n");
    printf("  -e, --enable-filter 0|1      Enable/disable filtering\n");
    printf("  -l, --get-log [COUNT]        Get packet log (default: 10)\n");
    printf("  -L, --flush-log              Flush packet log\n");
    printf("  -i, --set-device DEVICE      Set target network device\n");
    printf("  -h, --help                   Show this help message\n");
    printf("  -v, --version                Show version information\n");
    printf("  -V, --verbose                Verbose output\n");
    printf("\nRule format: proto:src_ip:src_port:dst_ip:dst_port:action\n");
    printf("  proto: tcp, udp, icmp, any\n");
    printf("  ports: number or 'any'\n");
    printf("  ips: dotted decimal or 'any'\n");
    printf("  action: pass(0), drop(1), log(2)\n");
    printf("\nModes: 0=disabled, 1=blacklist, 2=whitelist, 3=count-only\n");
}

static void print_version()
{
    printf("Packet Filter Control Utility v%s\n", VERSION);
    printf("Copyright (C) 2024 Network Driver Project\n");
    printf("License: GPL v2.0\n");
}

static int parse_rule_string(const char *str, struct pf_rule *rule)
{
    char *copy, *token, *saveptr;
    char *parts[6];
    int i = 0;
    
    if (!str || !rule)
        return -1;
    
    copy = strdup(str);
    if (!copy)
        return -1;
    
    token = strtok_r(copy, ":", &saveptr);
    while (token && i < 6) {
        parts[i++] = token;
        token = strtok_r(NULL, ":", &saveptr);
    }
    
    if (i != 6) {
        free(copy);
        return -1;
    }
    
    memset(rule, 0, sizeof(*rule));
    
    /* Parse protocol */
    if (strcmp(parts[0], "tcp") == 0) rule->protocol = PF_PROTO_TCP;
    else if (strcmp(parts[0], "udp") == 0) rule->protocol = PF_PROTO_UDP;
    else if (strcmp(parts[0], "icmp") == 0) rule->protocol = PF_PROTO_ICMP;
    else if (strcmp(parts[0], "any") == 0) rule->protocol = PF_PROTO_ANY;
    else rule->protocol = atoi(parts[0]);
    
    /* Parse source IP */
    if (pf_parse_ip(parts[1], &rule->src_ip) < 0) {
        free(copy);
        return -1;
    }
    
    /* Parse source port */
    if (strcmp(parts[2], "any") == 0) rule->src_port = 0;
    else rule->src_port = htons(atoi(parts[2]));
    
    /* Parse destination IP */
    if (pf_parse_ip(parts[3], &rule->dst_ip) < 0) {
        free(copy);
        return -1;
    }
    
    /* Parse destination port */
    if (strcmp(parts[4], "any") == 0) rule->dst_port = 0;
    else rule->dst_port = htons(atoi(parts[4]));
    
    /* Parse action */
    if (strcmp(parts[5], "pass") == 0) rule->action = PF_ACTION_PASS;
    else if (strcmp(parts[5], "drop") == 0) rule->action = PF_ACTION_DROP;
    else if (strcmp(parts[5], "log") == 0) rule->action = PF_ACTION_LOG;
    else rule->action = atoi(parts[5]);
    
    free(copy);
    return 0;
}

int main(int argc, char *argv[])
{
    pf_handle_t *handle;
    int opt, long_index = 0;
    int verbose = 0;
    int ret = 0;
    
    handle = pf_open(NULL);
    if (!handle) {
        fprintf(stderr, "Error: Failed to open packet filter device\n");
        fprintf(stderr, "Make sure the driver is loaded: sudo insmod packet_filter.ko\n");
        return 1;
    }
    
    while ((opt = getopt_long(argc, argv, "a:d:sSm:M:e:l:Li:rRhvV",
                              long_options, &long_index)) != -1) {
        switch (opt) {
            case 'a': { /* Add rule */
                struct pf_rule rule;
                if (parse_rule_string(optarg, &rule) < 0) {
                    fprintf(stderr, "Error: Invalid rule format\n");
                    ret = 1;
                } else {
                    if (pf_add_rule(handle, &rule) < 0) {
                        fprintf(stderr, "Error: Failed to add rule: %s\n",
                                pf_strerror(ret));
                        ret = 1;
                    } else if (verbose) {
                        printf("Rule added successfully\n");
                    }
                }
                break;
            }
            
            case 'd': { /* Delete rule */
                unsigned int rule_id = atoi(optarg);
                if (pf_delete_rule(handle, rule_id) < 0) {
                    fprintf(stderr, "Error: Failed to delete rule %u\n", rule_id);
                    ret = 1;
                } else if (verbose) {
                    printf("Rule %u deleted successfully\n", rule_id);
                }
                break;
            }
            
            case 's': { /* Get stats */
                struct pf_stats stats;
                if (pf_get_stats(handle, &stats) < 0) {
                    fprintf(stderr, "Error: Failed to get statistics\n");
                    ret = 1;
                } else {
                    pf_print_stats(&stats, stdout);
                }
                break;
            }
            
            case 'S': /* Clear stats */
                if (pf_clear_stats(handle) < 0) {
                    fprintf(stderr, "Error: Failed to clear statistics\n");
                    ret = 1;
                } else if (verbose) {
                    printf("Statistics cleared\n");
                }
                break;
            
            case 'm': { /* Set mode */
                unsigned char mode = atoi(optarg);
                if (pf_set_mode(handle, mode) < 0) {
                    fprintf(stderr, "Error: Failed to set mode\n");
                    ret = 1;
                } else if (verbose) {
                    printf("Mode set to %u (%s)\n", mode, pf_mode_to_str(mode));
                }
                break;
            }
            
            case 'M': { /* Get mode */
                unsigned char mode;
                if (pf_get_mode(handle, &mode) < 0) {
                    fprintf(stderr, "Error: Failed to get mode\n");
                    ret = 1;
                } else {
                    printf("Current mode: %u (%s)\n", mode, pf_mode_to_str(mode));
                }
                break;
            }
            
            case 'e': { /* Enable filter */
                unsigned char enable = atoi(optarg);
                if (pf_enable_filter(handle, enable) < 0) {
                    fprintf(stderr, "Error: Failed to %s filter\n",
                            enable ? "enable" : "disable");
                    ret = 1;
                } else if (verbose) {
                    printf("Filter %s\n", enable ? "enabled" : "disabled");
                }
                break;
            }
            
            case 'l': { /* Get log */
                unsigned int max_entries = optarg ? atoi(optarg) : 10;
                struct pf_log_entry *entries;
                unsigned int retrieved;
                
                if (max_entries == 0)
                    max_entries = 10;
                
                entries = malloc(max_entries * sizeof(struct pf_log_entry));
                if (!entries) {
                    fprintf(stderr, "Error: Out of memory\n");
                    ret = 1;
                    break;
                }
                
                if (pf_get_log(handle, entries, max_entries, &retrieved) < 0) {
                    fprintf(stderr, "Error: Failed to get log\n");
                    ret = 1;
                } else {
                    printf("=== Packet Log (%u entries) ===\n", retrieved);
                    for (unsigned int i = 0; i < retrieved; i++) {
                        pf_print_log_entry(&entries[i], stdout);
                    }
                }
                
                free(entries);
                break;
            }
            
            case 'L': /* Flush log */
                if (pf_flush_log(handle) < 0) {
                    fprintf(stderr, "Error: Failed to flush log\n");
                    ret = 1;
                } else if (verbose) {
                    printf("Log flushed\n");
                }
                break;
            
            case 'i': /* Set device */
                if (pf_set_device(handle, optarg) < 0) {
                    fprintf(stderr, "Error: Failed to set device\n");
                    ret = 1;
                } else if (verbose) {
                    printf("Target device set to %s\n", optarg);
                }
                break;
            
            case 'r': /* List rules */
                printf("Note: Rule listing not implemented in this version\n");
                printf("Use kernel debugfs or sysfs for rule inspection\n");
                break;
            
            case 'R': /* Clear rules */
                printf("Note: Rule clearing not implemented in this version\n");
                printf("Delete rules individually using --del-rule\n");
                break;
            
            case 'h': /* Help */
                print_help(argv[0]);
                break;
            
            case 'v': /* Version */
                print_version();
                break;
            
            case 'V': /* Verbose */
                verbose = 1;
                break;
            
            default:
                print_help(argv[0]);
                ret = 1;
                break;
        }
    }
    
    pf_close(handle);
    
    if (optind < argc && ret == 0) {
        fprintf(stderr, "Error: Unexpected arguments: ");
        while (optind < argc)
            fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n");
        ret = 1;
    }
    
    return ret;
}
