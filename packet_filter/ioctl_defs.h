#ifndef _IOCTL_DEFS_H
#define _IOCTL_DEFS_H

#include <linux/ioctl.h>

/* Actions */
#define PF_ACTION_PASS     0
#define PF_ACTION_DROP     1
#define PF_ACTION_LOG      2

/* Reasons */
#define PF_REASON_RULE     0
#define PF_REASON_MODE     1
#define PF_REASON_PROTOCOL 2

/* Log entry */
struct pf_log_entry {
    u64 timestamp;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u16 length;
    u8 action;
    u8 reason;
    u32 rule_id;
};

/* Log data for userspace */
struct pf_log_data {
    u32 count;
    u32 max_count;
    struct pf_log_entry entries[0];
};

/* IOCTL commands (defined for both kernel and userspace) */
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
#define PF_MAX_IOCTL      10

#endif /* _IOCTL_DEFS_H */
