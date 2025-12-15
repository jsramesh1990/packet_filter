#ifndef _PACKET_FILTER_H
#define _PACKET_FILTER_H

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/kfifo.h>

#define PF_DEVICE_NAME     "packet_filter"
#define PF_CLASS_NAME      "pf"
#define PF_DEVICE_COUNT    1
#define PF_FIFO_SIZE       1024  /* Packet log FIFO size */

/* Filtering modes */
enum pf_mode {
    PF_MODE_DISABLED = 0,
    PF_MODE_BLACKLIST,
    PF_MODE_WHITELIST,
    PF_MODE_COUNT_ONLY
};

/* Filter rules */
struct pf_rule {
    u8 protocol;           /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    u16 src_port;          /* 0 = any */
    u16 dst_port;          /* 0 = any */
    __be32 src_ip;         /* 0 = any */
    __be32 dst_ip;         /* 0 = any */
    u8 action;             /* DROP, ACCEPT, LOG */
    u32 id;                /* Rule ID */
    struct list_head list; /* Linked list */
};

/* Packet metadata for logging */
struct pf_packet_info {
    u64 timestamp;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u16 length;
    u8 action;
    u8 reason;
};

/* Driver statistics */
struct pf_stats {
    u64 total_packets;
    u64 filtered_packets;
    u64 tcp_packets;
    u64 udp_packets;
    u64 icmp_packets;
    u64 dropped_packets;
    u64 logged_packets;
    u64 bytes_processed;
    u64 errors;
};

/* Main filter structure */
struct packet_filter {
    struct net_device *target_dev;  /* Device being filtered */
    struct net_device *virt_dev;    /* Virtual device */
    struct list_head rules;         /* Filter rules list */
    struct pf_stats stats;          /* Statistics */
    struct kfifo log_fifo;          /* Packet log FIFO */
    
    /* Configuration */
    enum pf_mode mode;
    u8 log_enabled;
    u8 drop_enabled;
    u8 promisc_mode;
    
    /* Synchronization */
    spinlock_t lock;
    struct mutex config_lock;
    struct rw_semaphore rule_sem;
    
    /* Character device */
    dev_t dev_no;
    struct cdev cdev;
    struct class *class;
    
    /* Work queue for async operations */
    struct workqueue_struct *workqueue;
    struct work_struct log_work;
    
    /* Memory pools */
    struct kmem_cache *rule_cache;
};

/* IOCTL command structure */
struct pf_ioctl_cmd {
    u32 cmd;
    u32 rule_id;
    union {
        struct pf_rule rule;
        struct pf_stats stats;
        struct {
            u8 mode;
            u8 enable;
        } config;
        struct {
            u32 count;
            struct pf_packet_info *packets;
        } log_data;
    } data;
};

/* IOCTL Commands */
#define PF_IOC_MAGIC      'P'
#define PF_ADD_RULE       _IOW(PF_IOC_MAGIC, 1, struct pf_rule)
#define PF_DEL_RULE       _IOW(PF_IOC_MAGIC, 2, u32)
#define PF_GET_STATS      _IOR(PF_IOC_MAGIC, 3, struct pf_stats)
#define PF_CLEAR_STATS    _IO(PF_IOC_MAGIC, 4)
#define PF_SET_MODE       _IOW(PF_IOC_MAGIC, 5, u8)
#define PF_GET_MODE       _IOR(PF_IOC_MAGIC, 6, u8)
#define PF_ENABLE_FILTER  _IOW(PF_IOC_MAGIC, 7, u8)
#define PF_GET_LOG        _IOWR(PF_IOC_MAGIC, 8, struct pf_log_data)
#define PF_FLUSH_LOG      _IO(PF_IOC_MAGIC, 9)
#define PF_SET_DEVICE     _IOW(PF_IOC_MAGIC, 10, char[IFNAMSIZ])

#endif /* _PACKET_FILTER_H */
