#include "libfilter.h"

#define DEFAULT_BUFFER_SIZE 4096

/* Internal helper functions */
static int pf_do_ioctl(pf_handle_t *handle, unsigned long request, void *arg)
{
    if (!handle || handle->fd < 0)
        return -EBADF;
    
    return ioctl(handle->fd, request, arg);
}

/* Public API implementation */
pf_handle_t* pf_open(const char *device_path)
{
    pf_handle_t *handle;
    
    if (!device_path)
        device_path = PF_DEVICE_PATH;
    
    handle = malloc(sizeof(pf_handle_t));
    if (!handle)
        return NULL;
    
    handle->fd = open(device_path, O_RDWR);
    if (handle->fd < 0) {
        free(handle);
        return NULL;
    }
    
    strncpy(handle->device_path, device_path, sizeof(handle->device_path) - 1);
    handle->device_path[sizeof(handle->device_path) - 1] = '\0';
    
    return handle;
}

void pf_close(pf_handle_t *handle)
{
    if (handle) {
        if (handle->fd >= 0)
            close(handle->fd);
        free(handle);
    }
}

int pf_is_open(pf_handle_t *handle)
{
    return handle && handle->fd >= 0;
}

int pf_add_rule(pf_handle_t *handle, const struct pf_rule *rule)
{
    return pf_do_ioctl(handle, PF_ADD_RULE, (void*)rule);
}

int pf_delete_rule(pf_handle_t *handle, unsigned int rule_id)
{
    return pf_do_ioctl(handle, PF_DEL_RULE, &rule_id);
}

int pf_get_stats(pf_handle_t *handle, struct pf_stats *stats)
{
    return pf_do_ioctl(handle, PF_GET_STATS, stats);
}

int pf_clear_stats(pf_handle_t *handle)
{
    return pf_do_ioctl(handle, PF_CLEAR_STATS, NULL);
}

int pf_set_mode(pf_handle_t *handle, unsigned char mode)
{
    return pf_do_ioctl(handle, PF_SET_MODE, &mode);
}

int pf_get_mode(pf_handle_t *handle, unsigned char *mode)
{
    return pf_do_ioctl(handle, PF_GET_MODE, mode);
}

int pf_enable_filter(pf_handle_t *handle, unsigned char enable)
{
    return pf_do_ioctl(handle, PF_ENABLE_FILTER, &enable);
}

int pf_set_device(pf_handle_t *handle, const char *device_name)
{
    char buf[IFNAMSIZ];
    
    if (!device_name || strlen(device_name) >= IFNAMSIZ)
        return -EINVAL;
    
    strncpy(buf, device_name, IFNAMSIZ - 1);
    buf[IFNAMSIZ - 1] = '\0';
    
    return pf_do_ioctl(handle, PF_SET_DEVICE, buf);
}

int pf_get_log(pf_handle_t *handle, struct pf_log_entry *entries,
               unsigned int max_entries, unsigned int *retrieved)
{
    struct pf_log_data *log_data;
    size_t data_size;
    int ret;
    
    if (!entries || max_entries == 0 || !retrieved)
        return -EINVAL;
    
    /* Allocate buffer for log data */
    data_size = sizeof(struct pf_log_data) + 
                max_entries * sizeof(struct pf_log_entry);
    log_data = malloc(data_size);
    if (!log_data)
        return -ENOMEM;
    
    log_data->max_count = max_entries;
    
    ret = pf_do_ioctl(handle, PF_GET_LOG, log_data);
    if (ret == 0) {
        *retrieved = log_data->count;
        if (log_data->count > 0) {
            memcpy(entries, log_data->entries,
                   log_data->count * sizeof(struct pf_log_entry));
        }
    }
    
    free(log_data);
    return ret;
}

int pf_flush_log(pf_handle_t *handle)
{
    return pf_do_ioctl(handle, PF_FLUSH_LOG, NULL);
}

/* Utility function implementations */
const char* pf_protocol_to_str(unsigned char protocol)
{
    switch (protocol) {
        case PF_PROTO_TCP: return "TCP";
        case PF_PROTO_UDP: return "UDP";
        case PF_PROTO_ICMP: return "ICMP";
        case PF_PROTO_ANY: return "ANY";
        default: return "UNKNOWN";
    }
}

const char* pf_action_to_str(unsigned char action)
{
    switch (action) {
        case PF_ACTION_PASS: return "PASS";
        case PF_ACTION_DROP: return "DROP";
        case PF_ACTION_LOG: return "LOG";
        default: return "UNKNOWN";
    }
}

const char* pf_mode_to_str(unsigned char mode)
{
    switch (mode) {
        case PF_MODE_DISABLED: return "DISABLED";
        case PF_MODE_BLACKLIST: return "BLACKLIST";
        case PF_MODE_WHITELIST: return "WHITELIST";
        case PF_MODE_COUNT_ONLY: return "COUNT_ONLY";
        default: return "UNKNOWN";
    }
}

void pf_print_rule(const struct pf_rule *rule, FILE *stream)
{
    char src_ip[16], dst_ip[16];
    
    if (!rule || !stream)
        return;
    
    fprintf(stream, "Rule ID: %u\n", rule->id);
    fprintf(stream, "  Protocol: %s\n", pf_protocol_to_str(rule->protocol));
    
    pf_format_ip(rule->src_ip, src_ip, sizeof(src_ip));
    pf_format_ip(rule->dst_ip, dst_ip, sizeof(dst_ip));
    
    fprintf(stream, "  Source: %s:%u\n", src_ip, ntohs(rule->src_port));
    fprintf(stream, "  Destination: %s:%u\n", dst_ip, ntohs(rule->dst_port));
    fprintf(stream, "  Action: %s\n", pf_action_to_str(rule->action));
}

void pf_print_stats(const struct pf_stats *stats, FILE *stream)
{
    if (!stats || !stream)
        return;
    
    fprintf(stream, "=== Packet Filter Statistics ===\n");
    fprintf(stream, "Total packets:      %llu\n", stats->total_packets);
    fprintf(stream, "Filtered packets:   %llu\n", stats->filtered_packets);
    fprintf(stream, "  TCP packets:      %llu\n", stats->tcp_packets);
    fprintf(stream, "  UDP packets:      %llu\n", stats->udp_packets);
    fprintf(stream, "  ICMP packets:     %llu\n", stats->icmp_packets);
    fprintf(stream, "Dropped packets:    %llu\n", stats->dropped_packets);
    fprintf(stream, "Logged packets:     %llu\n", stats->logged_packets);
    fprintf(stream, "Bytes processed:    %llu\n", stats->bytes_processed);
    fprintf(stream, "Errors:             %llu\n", stats->errors);
}

void pf_print_log_entry(const struct pf_log_entry *entry, FILE *stream)
{
    char src_ip[16], dst_ip[16];
    time_t ts;
    struct tm *tm_info;
    char timestamp[20];
    
    if (!entry || !stream)
        return;
    
    ts = entry->timestamp / 1000000000;
    tm_info = localtime(&ts);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    pf_format_ip(entry->src_ip, src_ip, sizeof(src_ip));
    pf_format_ip(entry->dst_ip, dst_ip, sizeof(dst_ip));
    
    fprintf(stream, "[%s.%03llu] ", timestamp, 
            (entry->timestamp % 1000000000) / 1000000);
    fprintf(stream, "%s:%u -> %s:%u ", 
            src_ip, entry->src_port, dst_ip, entry->dst_port);
    fprintf(stream, "Proto: %s ", pf_protocol_to_str(entry->protocol));
    fprintf(stream, "Len: %u ", entry->length);
    fprintf(stream, "Action: %s ", pf_action_to_str(entry->action));
    fprintf(stream, "Rule: %u\n", entry->rule_id);
}

int pf_parse_ip(const char *ip_str, unsigned int *ip_addr)
{
    struct in_addr addr;
    
    if (!ip_str || !ip_addr)
        return -EINVAL;
    
    if (strcmp(ip_str, "any") == 0 || strcmp(ip_str, "*") == 0) {
        *ip_addr = 0;
        return 0;
    }
    
    if (inet_pton(AF_INET, ip_str, &addr) != 1)
        return -EINVAL;
    
    *ip_addr = addr.s_addr;
    return 0;
}

char* pf_format_ip(unsigned int ip_addr, char *buf, size_t buf_len)
{
    struct in_addr addr;
    
    if (!buf || buf_len < 16)
        return NULL;
    
    if (ip_addr == 0) {
        strncpy(buf, "any", buf_len - 1);
        buf[buf_len - 1] = '\0';
        return buf;
    }
    
    addr.s_addr = ip_addr;
    inet_ntop(AF_INET, &addr, buf, buf_len);
    
    return buf;
}

const char* pf_strerror(int err)
{
    switch (err) {
        case -EBADF: return "Invalid file descriptor";
        case -EINVAL: return "Invalid argument";
        case -ENOMEM: return "Out of memory";
        case -ENOENT: return "Rule not found";
        case -EACCES: return "Permission denied";
        case -ENODEV: return "No such device";
        case -ENOTTY: return "Invalid IOCTL command";
        default: return strerror(-err);
    }
}
