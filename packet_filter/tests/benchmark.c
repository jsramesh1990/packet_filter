#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "libfilter.h"

#define NUM_ITERATIONS 10000
#define NUM_RULES 100

double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

void benchmark_rule_addition(int fd) {
    struct pf_rule rule;
    double start, end;
    int i;
    
    printf("Benchmarking rule addition...\n");
    
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_TCP;
    rule.action = 1;
    
    start = get_time_ms();
    
    for (i = 0; i < NUM_RULES; i++) {
        rule.src_port = htons(1000 + i);
        rule.dst_port = htons(2000 + i);
        rule.src_ip = htonl(0xC0A80101 + i); // 192.168.1.1 + i
        
        if (ioctl(fd, PF_ADD_RULE, &rule) < 0) {
            perror("Failed to add rule");
            break;
        }
    }
    
    end = get_time_ms();
    printf("  Added %d rules in %.2f ms (%.2f rules/sec)\n", 
           i, end - start, (i * 1000.0) / (end - start));
}

void benchmark_packet_filtering() {
    int sock;
    struct sockaddr_in addr;
    char buffer[1024];
    double start, end;
    int i;
    
    printf("Benchmarking packet filtering throughput...\n");
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    memset(buffer, 'A', sizeof(buffer));
    
    start = get_time_ms();
    
    for (i = 0; i < NUM_ITERATIONS; i++) {
        if (sendto(sock, buffer, sizeof(buffer), 0,
                   (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("sendto");
            break;
        }
    }
    
    end = get_time_ms();
    
    close(sock);
    
    double elapsed = end - start;
    double packets_per_sec = (i * 1000.0) / elapsed;
    double mbps = (i * sizeof(buffer) * 8.0) / (elapsed * 1000.0);
    
    printf("  Sent %d packets in %.2f ms\n", i, elapsed);
    printf("  Throughput: %.2f packets/sec, %.2f Mbps\n", 
           packets_per_sec, mbps);
}

int main() {
    int fd;
    
    printf("=== Packet Filter Performance Benchmark ===\n\n");
    
    fd = open("/dev/packet_filter", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    
    // Enable filter
    u8 enable = 1;
    ioctl(fd, PF_ENABLE_FILTER, &enable);
    
    // Clear any existing rules
    ioctl(fd, PF_CLEAR_STATS, 0);
    
    // Run benchmarks
    benchmark_rule_addition(fd);
    printf("\n");
    
    // Add a test rule
    struct pf_rule rule;
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_UDP;
    rule.dst_port = htons(9999);
    rule.action = 1;
    ioctl(fd, PF_ADD_RULE, &rule);
    
    benchmark_packet_filtering();
    
    // Get final statistics
    struct pf_stats stats;
    ioctl(fd, PF_GET_STATS, &stats);
    
    printf("\n=== Final Statistics ===\n");
    printf("Total packets processed: %lu\n", stats.total_packets);
    printf("Filtered packets: %lu\n", stats.filtered_packets);
    printf("Dropped packets: %lu\n", stats.dropped_packets);
    
    close(fd);
    return 0;
}
