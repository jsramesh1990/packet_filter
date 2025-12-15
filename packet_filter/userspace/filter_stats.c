#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <ncurses.h>
#include "libfilter.h"

#define REFRESH_INTERVAL 1  /* seconds */
#define HISTORY_SIZE 60     /* 1 minute history */

volatile sig_atomic_t running = 1;

static void sigint_handler(int sig)
{
    running = 0;
}

static void print_stats_ncurses(pf_handle_t *handle)
{
    struct pf_stats stats, prev_stats;
    static unsigned long long prev_total = 0;
    static unsigned long long prev_dropped = 0;
    static unsigned long long prev_bytes = 0;
    static time_t prev_time = 0;
    unsigned long long delta_total, delta_dropped, delta_bytes;
    time_t now;
    double elapsed;
    double pps, bps, drop_rate;
    
    if (pf_get_stats(handle, &stats) < 0)
        return;
    
    now = time(NULL);
    
    if (prev_time == 0) {
        prev_time = now;
        prev_stats = stats;
        return;
    }
    
    elapsed = difftime(now, prev_time);
    if (elapsed < 0.5)  /* Don't update too frequently */
        return;
    
    delta_total = stats.total_packets - prev_stats.total_packets;
    delta_dropped = stats.dropped_packets - prev_stats.dropped_packets;
    delta_bytes = stats.bytes_processed - prev_stats.bytes_processed;
    
    pps = delta_total / elapsed;
    bps = (delta_bytes * 8.0) / elapsed;
    drop_rate = (delta_total > 0) ? (delta_dropped * 100.0 / delta_total) : 0;
    
    clear();
    
    /* Header */
    attron(A_BOLD);
    printw("=== Packet Filter Statistics (Real-time) ===\n");
    attroff(A_BOLD);
    
    /* Current rates */
    printw("\nCurrent Rates:\n");
    printw("  Packets/sec: %8.1f  Bits/sec: %8.1f Mbps\n", pps, bps / 1000000);
    printw("  Drop Rate:   %8.1f%%\n", drop_rate);
    
    /* Cumulative statistics */
    printw("\nCumulative Statistics:\n");
    printw("  Total Packets:    %12llu\n", stats.total_packets);
    printw("  Filtered Packets: %12llu\n", stats.filtered_packets);
    printw("  Dropped Packets:  %12llu\n", stats.dropped_packets);
    printw("  Bytes Processed:  %12llu\n", stats.bytes_processed);
    
    /* Protocol breakdown */
    printw("\nProtocol Breakdown:\n");
    printw("  TCP:  %12llu\n", stats.tcp_packets);
    printw("  UDP:  %12llu\n", stats.udp_packets);
    printw("  ICMP: %12llu\n", stats.icmp_packets);
    
    /* Footer */
    printw("\n\nPress Ctrl+C to exit\n");
    
    refresh();
    
    prev_stats = stats;
    prev_time = now;
}

int main(int argc, char *argv[])
{
    pf_handle_t *handle;
    int use_ncurses = 1;
    
    /* Check for command line arguments */
    if (argc > 1 && strcmp(argv[1], "--simple") == 0)
        use_ncurses = 0;
    
    handle = pf_open(NULL);
    if (!handle) {
        fprintf(stderr, "Error: Failed to open packet filter device\n");
        return 1;
    }
    
    /* Set up signal handler */
    signal(SIGINT, sigint_handler);
    
    if (use_ncurses) {
        /* NCurses mode */
        initscr();
        cbreak();
        noecho();
        curs_set(0);
        timeout(0);
        
        while (running) {
            print_stats_ncurses(handle);
            napms(REFRESH_INTERVAL * 1000);
            
            /* Check for key press */
            int ch = getch();
            if (ch == 'q' || ch == 'Q')
                running = 0;
        }
        
        endscr();
    } else {
        /* Simple text mode */
        struct pf_stats prev_stats, stats;
        time_t start_time = time(NULL);
        
        printf("Packet Filter Statistics - Simple Mode\n");
        printf("Press Ctrl+C to exit\n\n");
        
        pf_get_stats(handle, &prev_stats);
        
        while (running) {
            sleep(REFRESH_INTERVAL);
            
            if (pf_get_stats(handle, &stats) < 0)
                break;
            
            double elapsed = difftime(time(NULL), start_time);
            unsigned long long delta_total = stats.total_packets - prev_stats.total_packets;
            unsigned long long delta_dropped = stats.dropped_packets - prev_stats.dropped_packets;
            unsigned long long delta_bytes = stats.bytes_processed - prev_stats.bytes_processed;
            
            double pps = delta_total / REFRESH_INTERVAL;
            double bps = (delta_bytes * 8.0) / REFRESH_INTERVAL;
            double drop_rate = (delta_total > 0) ? (delta_dropped * 100.0 / delta_total) : 0;
            
            printf("\033[2J\033[H");  /* Clear screen */
            printf("Elapsed: %.0f seconds\n", elapsed);
            printf("Current Rate: %.1f pps, %.1f Mbps, Drop: %.1f%%\n", 
                   pps, bps / 1000000, drop_rate);
            printf("Total: %llu packets, %llu dropped\n", 
                   stats.total_packets, stats.dropped_packets);
            
            prev_stats = stats;
        }
        
        printf("\nExiting...\n");
    }
    
    pf_close(handle);
    return 0;
}
