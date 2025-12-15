#ifndef LIBFILTER_H
#define LIBFILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <errno.h>
#include <time.h>

#define PF_DEVICE_PATH "/dev/packet_filter"

/* Protocol definitions */
#define PF_PROTO_ANY    0
#define PF_PROTO_TCP    6
#define PF_PROTO_UDP    17
#define PF_PROTO_ICMP   1

/* Action definitions */
#define PF_ACTION_PASS  0
#define PF_ACTION_DROP  1
#define PF_ACTION_LOG   2

/* Mode definitions */
#define PF_MODE_DISABLED     0
#define PF_MODE_BLACKLIST    1
#define PF_MODE_WHITELIST    2
#define PF_MODE_COUNT_ONLY   3

/* IOCTL command numbers - must match kernel */
#define PF_IOC_MAGIC      'P'
#define PF_ADD_RULE       _IOW(PF_IOC_MAGIC, 1, struct pf_rule)
#define PF_DEL_RULE       _IOW(PF_IOC_MAGIC, 2, unsigned int)
#define PF_GET_STATS      _IOR(PF_IOC_MAGIC, 3, struct pf_stats)
#define PF_CLEAR_STATS    _IO(PF_IOC_MAGIC, 4)
#define PF_SET_MODE       _IOW(PF_IOC_MAGIC, 5, unsigned char)
#define PF_GET_MODE       _IOR(PF_IOC_MAGIC, 6, unsigned char)
#define PF_ENABLE_FILTER  _IOW(PF_IOC_MAGIC, 7, unsigned char)
#define PF_GET_LOG        _IOWR(PF_IOC_MAGIC, 8, struct pf_log_data)
#define PF_FLUSH_LOG      _IO(PF_IOC_MAGIC, 9)
#define PF_SET_DEVICE     _IOW(PF_IOC_MAGIC, 10, char[IFNAMSIZ])

/* Structures matching kernel driver */
#pragma pack(push, 1)
struct pf_rule {
    unsigned char protocol;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned char action;
    unsigned int id;
};

struct pf_stats {
    unsigned long long total_packets;
    unsigned long long filtered_packets;
    unsigned long long tcp_packets;
    unsigned long long udp_packets;
    unsigned long long icmp_packets;
    unsigned long long dropped_packets;
    unsigned long long logged_packets;
    unsigned long long bytes_processed;
    unsigned long long errors;
};

struct pf_log_entry {
    unsigned long long timestamp;
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
    unsigned short length;
    unsigned char action;
    unsigned char reason;
    unsigned int rule_id;
};

struct pf_log_data {
    unsigned int count;
    unsigned int max_count;
    struct pf_log_entry entries[0];  /* Flexible array */
};
#pragma pack(pop)

/* Library API */
typedef struct {
    int fd;
    char device_path[256];
} pf_handle_t;

/* Connection management */
pf_handle_t* pf_open(const char *device_path);
void pf_close(pf_handle_t *handle);
int pf_is_open(pf_handle_t *handle);

/* Rule management */
int pf_add_rule(pf_handle_t *handle, const struct pf_rule *rule);
int pf_delete_rule(pf_handle_t *handle, unsigned int rule_id);
int pf_list_rules(pf_handle_t *handle, struct pf_rule **rules, int *count);
int pf_clear_rules(pf_handle_t *handle);

/* Statistics */
int pf_get_stats(pf_handle_t *handle, struct pf_stats *stats);
int pf_clear_stats(pf_handle_t *handle);
void pf_print_stats(const struct pf_stats *stats, FILE *stream);

/* Configuration */
int pf_set_mode(pf_handle_t *handle, unsigned char mode);
int pf_get_mode(pf_handle_t *handle, unsigned char *mode);
int pf_enable_filter(pf_handle_t *handle, unsigned char enable);
int pf_set_device(pf_handle_t *handle, const char *device_name);

/* Logging */
int pf_get_log(pf_handle_t *handle, struct pf_log_entry *entries, 
               unsigned int max_entries, unsigned int *retrieved);
int pf_flush_log(pf_handle_t *handle);
void pf_print_log_entry(const struct pf_log_entry *entry, FILE *stream);

/* Utility functions */
const char* pf_protocol_to_str(unsigned char protocol);
const char* pf_action_to_str(unsigned char action);
const char* pf_mode_to_str(unsigned char mode);
void pf_print_rule(const struct pf_rule *rule, FILE *stream);
int pf_parse_ip(const char *ip_str, unsigned int *ip_addr);
int pf_parse_rule_string(const char *str, struct pf_rule *rule);
char* pf_format_ip(unsigned int ip_addr, char *buf, size_t buf_len);

/* Error handling */
const char* pf_strerror(int err);

#endif /* LIBFILTER_H */
