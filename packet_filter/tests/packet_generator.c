#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <time.h>

#define MAX_PACKETS 1000

void send_tcp_packet(const char *dst_ip, int dst_port, 
                     const char *src_ip, int src_port) {
    int sock;
    struct sockaddr_in dest;
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        return;
    }
    
    memset(packet, 0, 4096);
    
    // IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    ip->check = 0; // Should calculate
    
    // TCP header
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(1);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(5840);
    tcp->check = 0; // Should calculate
    tcp->urg_ptr = 0;
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = inet_addr(dst_ip);
    
    if (sendto(sock, packet, ntohs(ip->tot_len), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
    }
    
    close(sock);
}

int main(int argc, char *argv[]) {
    printf("Packet Generator for Filter Testing\n");
    
    if (argc != 2) {
        printf("Usage: %s <interface_ip>\n", argv[0]);
        return 1;
    }
    
    const char *target_ip = argv[1];
    
    printf("Generating test packets to %s...\n", target_ip);
    
    // Generate various packet types
    for (int i = 0; i < 100; i++) {
        // TCP packets to different ports
        send_tcp_packet(target_ip, 80, "192.168.1.100", 12345 + i);
        send_tcp_packet(target_ip, 443, "192.168.1.101", 12345 + i);
        send_tcp_packet(target_ip, 9999, "192.168.1.102", 12345 + i);
        
        // Add small delay
        usleep(1000);
    }
    
    printf("Packet generation complete\n");
    return 0;
}
