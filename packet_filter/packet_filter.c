#include "packet_filter.h"
#include "ioctl_defs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Network Driver Developer");
MODULE_DESCRIPTION("Advanced Packet Filter Driver");
MODULE_VERSION("1.0.0");

static struct packet_filter *pf = NULL;
static int major_number = 0;

/* Forward declarations */
static struct pf_rule* pf_find_rule(struct sk_buff *skb);
static void pf_log_packet(struct sk_buff *skb, u8 action, u8 reason);
static void pf_update_stats(struct sk_buff *skb, u8 action);

/* ==================== RULE MANAGEMENT ==================== */

static struct pf_rule* pf_create_rule(const struct pf_rule *user_rule)
{
    struct pf_rule *rule;
    
    rule = kmem_cache_alloc(pf->rule_cache, GFP_KERNEL);
    if (!rule)
        return NULL;
    
    memcpy(rule, user_rule, sizeof(*rule));
    INIT_LIST_HEAD(&rule->list);
    
    return rule;
}

static int pf_add_rule(const struct pf_rule *user_rule)
{
    struct pf_rule *rule;
    
    if (!user_rule)
        return -EINVAL;
    
    rule = pf_create_rule(user_rule);
    if (!rule)
        return -ENOMEM;
    
    /* Generate unique ID */
    rule->id = (u32)atomic_inc_return(&pf->rule_id_counter);
    
    down_write(&pf->rule_sem);
    list_add_tail(&rule->list, &pf->rules);
    up_write(&pf->rule_sem);
    
    printk(KERN_INFO PF_DEVICE_NAME ": Rule %u added\n", rule->id);
    return 0;
}

static int pf_delete_rule(u32 rule_id)
{
    struct pf_rule *rule, *tmp;
    int found = 0;
    
    down_write(&pf->rule_sem);
    list_for_each_entry_safe(rule, tmp, &pf->rules, list) {
        if (rule->id == rule_id) {
            list_del(&rule->list);
            kmem_cache_free(pf->rule_cache, rule);
            found = 1;
            break;
        }
    }
    up_write(&pf->rule_sem);
    
    if (found) {
        printk(KERN_INFO PF_DEVICE_NAME ": Rule %u deleted\n", rule_id);
        return 0;
    }
    
    return -ENOENT;
}

/* ==================== PACKET FILTERING ==================== */

static struct pf_rule* pf_match_packet(struct sk_buff *skb)
{
    struct pf_rule *rule;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    u16 src_port = 0, dst_port = 0;
    
    if (!skb || !skb_network_header(skb))
        return NULL;
    
    iph = ip_hdr(skb);
    
    /* Extract ports for TCP/UDP */
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        src_port = ntohs(udph->source);
        dst_port = ntohs(udph->dest);
    }
    
    /* Walk through rules */
    read_lock(&pf->rule_sem);
    list_for_each_entry(rule, &pf->rules, list) {
        /* Check protocol */
        if (rule->protocol && rule->protocol != iph->protocol)
            continue;
        
        /* Check source IP */
        if (rule->src_ip && rule->src_ip != iph->saddr)
            continue;
        
        /* Check destination IP */
        if (rule->dst_ip && rule->dst_ip != iph->daddr)
            continue;
        
        /* Check ports for TCP/UDP */
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            if (rule->src_port && rule->src_port != src_port)
                continue;
            if (rule->dst_port && rule->dst_port != dst_port)
                continue;
        }
        
        /* Match found */
        read_unlock(&pf->rule_sem);
        return rule;
    }
    read_unlock(&pf->rule_sem);
    
    return NULL;
}

static u8 pf_decide_action(struct sk_buff *skb, struct pf_rule *rule)
{
    if (!pf->drop_enabled || pf->mode == PF_MODE_COUNT_ONLY)
        return PF_ACTION_PASS;
    
    if (pf->mode == PF_MODE_BLACKLIST && rule)
        return PF_ACTION_DROP;
    
    if (pf->mode == PF_MODE_WHITELIST && !rule)
        return PF_ACTION_DROP;
    
    return PF_ACTION_PASS;
}

/* ==================== NETDEVICE OPS ==================== */

static int pf_netdev_open(struct net_device *dev)
{
    netif_carrier_on(dev);
    netif_start_queue(dev);
    return 0;
}

static int pf_netdev_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    netif_carrier_off(dev);
    return 0;
}

static netdev_tx_t pf_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct pf_rule *rule;
    u8 action;
    
    /* Update basic statistics */
    spin_lock(&pf->lock);
    pf->stats.total_packets++;
    pf->stats.bytes_processed += skb->len;
    spin_unlock(&pf->lock);
    
    /* Check if filtering is enabled */
    if (pf->mode == PF_MODE_DISABLED) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }
    
    /* Get IP header */
    if (skb->protocol != htons(ETH_P_IP)) {
        /* Non-IP packet, pass through */
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }
    
    /* Match packet against rules */
    rule = pf_match_packet(skb);
    action = pf_decide_action(skb, rule);
    
    /* Update protocol-specific stats */
    spin_lock(&pf->lock);
    switch (ip_hdr(skb)->protocol) {
        case IPPROTO_TCP:
            pf->stats.tcp_packets++;
            break;
        case IPPROTO_UDP:
            pf->stats.udp_packets++;
            break;
        case IPPROTO_ICMP:
            pf->stats.icmp_packets++;
            break;
    }
    spin_unlock(&pf->lock);
    
    /* Process action */
    switch (action) {
        case PF_ACTION_DROP:
            spin_lock(&pf->lock);
            pf->stats.dropped_packets++;
            pf->stats.filtered_packets++;
            spin_unlock(&pf->lock);
            
            if (pf->log_enabled)
                pf_log_packet(skb, PF_ACTION_DROP, PF_REASON_RULE);
            
            dev_kfree_skb(skb);
            break;
            
        case PF_ACTION_PASS:
        default:
            /* Forward to original device if needed */
            if (pf->target_dev) {
                skb->dev = pf->target_dev;
                dev_queue_xmit(skb);
            } else {
                dev_kfree_skb(skb);
            }
            break;
    }
    
    return NETDEV_TX_OK;
}

static const struct net_device_ops pf_netdev_ops = {
    .ndo_open = pf_netdev_open,
    .ndo_stop = pf_netdev_stop,
    .ndo_start_xmit = pf_netdev_xmit,
    .ndo_get_stats64 = NULL, /* Optional: for extended stats */
};

/* ==================== CHARACTER DEVICE OPS ==================== */

static long pf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct pf_ioctl_cmd ioctl_cmd;
    int err = 0;
    
    if (copy_from_user(&ioctl_cmd, (void __user *)arg, sizeof(ioctl_cmd)))
        return -EFAULT;
    
    mutex_lock(&pf->config_lock);
    
    switch (cmd) {
        case PF_ADD_RULE:
            err = pf_add_rule(&ioctl_cmd.data.rule);
            break;
            
        case PF_DEL_RULE:
            err = pf_delete_rule(ioctl_cmd.rule_id);
            break;
            
        case PF_GET_STATS:
            spin_lock(&pf->lock);
            memcpy(&ioctl_cmd.data.stats, &pf->stats, sizeof(pf->stats));
            spin_unlock(&pf->lock);
            
            if (copy_to_user((void __user *)arg, &ioctl_cmd, sizeof(ioctl_cmd)))
                err = -EFAULT;
            break;
            
        case PF_CLEAR_STATS:
            spin_lock(&pf->lock);
            memset(&pf->stats, 0, sizeof(pf->stats));
            spin_unlock(&pf->lock);
            break;
            
        case PF_SET_MODE:
            if (ioctl_cmd.data.config.mode < PF_MODE_DISABLED ||
                ioctl_cmd.data.config.mode > PF_MODE_COUNT_ONLY) {
                err = -EINVAL;
                break;
            }
            pf->mode = ioctl_cmd.data.config.mode;
            break;
            
        case PF_ENABLE_FILTER:
            pf->drop_enabled = ioctl_cmd.data.config.enable;
            break;
            
        default:
            err = -ENOTTY;
    }
    
    mutex_unlock(&pf->config_lock);
    return err;
}

static struct file_operations pf_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = pf_ioctl,
    .open = simple_open,
    .llseek = no_llseek,
};

/* ==================== MODULE INITIALIZATION ==================== */

static int __init pf_init_module(void)
{
    struct net_device *dev;
    int err;
    
    printk(KERN_INFO PF_DEVICE_NAME ": Initializing packet filter driver\n");
    
    /* Allocate main structure */
    pf = kzalloc(sizeof(*pf), GFP_KERNEL);
    if (!pf) {
        err = -ENOMEM;
        goto err_out;
    }
    
    /* Initialize lists and locks */
    INIT_LIST_HEAD(&pf->rules);
    spin_lock_init(&pf->lock);
    mutex_init(&pf->config_lock);
    init_rwsem(&pf->rule_sem);
    
    /* Allocate virtual network device */
    dev = alloc_netdev(sizeof(struct packet_filter), 
                       "pf%d", NET_NAME_UNKNOWN, ether_setup);
    if (!dev) {
        err = -ENOMEM;
        goto err_free_pf;
    }
    
    pf->virt_dev = dev;
    dev->netdev_ops = &pf_netdev_ops;
    
    /* Generate random MAC */
    eth_random_addr(dev->dev_addr);
    
    /* Register network device */
    err = register_netdev(dev);
    if (err)
        goto err_free_netdev;
    
    /* Create character device */
    err = alloc_chrdev_region(&pf->dev_no, 0, PF_DEVICE_COUNT, PF_DEVICE_NAME);
    if (err)
        goto err_unregister_netdev;
    
    cdev_init(&pf->cdev, &pf_fops);
    pf->cdev.owner = THIS_MODULE;
    
    err = cdev_add(&pf->cdev, pf->dev_no, PF_DEVICE_COUNT);
    if (err)
        goto err_unregister_chrdev;
    
    /* Create device class */
    pf->class = class_create(THIS_MODULE, PF_CLASS_NAME);
    if (IS_ERR(pf->class)) {
        err = PTR_ERR(pf->class);
        goto err_cdev_del;
    }
    
    device_create(pf->class, NULL, pf->dev_no, NULL, PF_DEVICE_NAME);
    
    /* Create rule cache */
    pf->rule_cache = kmem_cache_create("pf_rule_cache",
                                       sizeof(struct pf_rule),
                                       0, SLAB_HWCACHE_ALIGN, NULL);
    if (!pf->rule_cache) {
        err = -ENOMEM;
        goto err_device_destroy;
    }
    
    /* Initialize FIFO for packet logging */
    err = kfifo_alloc(&pf->log_fifo, 
                      PF_FIFO_SIZE * sizeof(struct pf_packet_info),
                      GFP_KERNEL);
    if (err)
        goto err_kmem_cache;
    
    /* Create workqueue */
    pf->workqueue = create_singlethread_workqueue("pf_workqueue");
    if (!pf->workqueue) {
        err = -ENOMEM;
        goto err_kfifo;
    }
    
    INIT_WORK(&pf->log_work, pf_log_worker);
    
    printk(KERN_INFO PF_DEVICE_NAME ": Driver loaded successfully\n");
    printk(KERN_INFO PF_DEVICE_NAME ": Device registered as /dev/%s\n", 
           PF_DEVICE_NAME);
    
    return 0;
    
    /* Error handling */
err_kfifo:
    kfifo_free(&pf->log_fifo);
err_kmem_cache:
    kmem_cache_destroy(pf->rule_cache);
err_device_destroy:
    device_destroy(pf->class, pf->dev_no);
err_cdev_del:
    cdev_del(&pf->cdev);
err_unregister_chrdev:
    unregister_chrdev_region(pf->dev_no, PF_DEVICE_COUNT);
err_unregister_netdev:
    unregister_netdev(dev);
err_free_netdev:
    free_netdev(dev);
err_free_pf:
    kfree(pf);
err_out:
    printk(KERN_ERR PF_DEVICE_NAME ": Failed to load driver (error %d)\n", err);
    return err;
}

static void __exit pf_cleanup_module(void)
{
    struct pf_rule *rule, *tmp;
    
    printk(KERN_INFO PF_DEVICE_NAME ": Cleaning up\n");
    
    /* Stop filtering */
    netif_stop_queue(pf->virt_dev);
    
    /* Free all rules */
    list_for_each_entry_safe(rule, tmp, &pf->rules, list) {
        list_del(&rule->list);
        kmem_cache_free(pf->rule_cache, rule);
    }
    
    /* Destroy workqueue */
    if (pf->workqueue)
        destroy_workqueue(pf->workqueue);
    
    /* Free FIFO */
    kfifo_free(&pf->log_fifo);
    
    /* Destroy rule cache */
    kmem_cache_destroy(pf->rule_cache);
    
    /* Remove character device */
    device_destroy(pf->class, pf->dev_no);
    class_destroy(pf->class);
    cdev_del(&pf->cdev);
    unregister_chrdev_region(pf->dev_no, PF_DEVICE_COUNT);
    
    /* Unregister network device */
    unregister_netdev(pf->virt_dev);
    free_netdev(pf->virt_dev);
    
    /* Free main structure */
    kfree(pf);
    
    printk(KERN_INFO PF_DEVICE_NAME ": Driver unloaded\n");
}

module_init(pf_init_module);
module_exit(pf_cleanup_module);
