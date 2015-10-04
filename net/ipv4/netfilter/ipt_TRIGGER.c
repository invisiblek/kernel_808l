/* Kernel module to match the port-ranges, trigger related port-ranges,
 * and alters the destination to a local IP address.
 *
 * Copyright (C) 2003, CyberTAN Corporation
 * All Rights Reserved.
 *
 * Description:
 *   This is kernel module for port-triggering.
 *
 *   The module follows the Netfilter framework, called extended packet 
 *   matching modules. 
 */
#include <linux/autoconf.h>

#include <linux/types.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <linux/stddef.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/tcp.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_nat.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat_rule.h>
#include <linux/netfilter/x_tables.h>
#include <linux/list.h>
#include <linux/netfilter_ipv4/ipt_TRIGGER.h>

static DEFINE_RWLOCK(ipt_trigger_lock);


#define LIST_FIND(head, cmpfn, type, args...)           \
({                                                      \
        const struct list_head *__i, *__j = NULL;       \
                                                        \
        list_for_each(__i, (head))                      \
                if (cmpfn((const type)__i , ## args)) { \
                        __j = __i;                      \
                        break;                          \
                }                                       \
        (type)__j;                                      \
})

MODULE_LICENSE("GPL");

#if 0
#define IP_NF_ASSERT(expr) \
        if(!(expr)) {					\
  			printk( "\033[33;41m%s:%d: assert(%s)\033[m\n",	\
	        __FILE__,__LINE__,#expr);		\
        }
#else
	#define IP_NF_ASSERT(expr)
#endif

static LIST_HEAD(trigger_list);	//a list

struct ipt_trigger 
{
	struct list_head 	list;		/* Trigger list */
	struct timer_list 	timeout;	/* Timer for list destroying */
	u_int32_t 			srcip;		/* Outgoing source address */
	u_int32_t 			dstip;		/* Outgoing destination address */
	u_int16_t 			mproto;		/* Trigger protocol */
	u_int16_t 			rproto;		/* Related protocol */
	struct ipt_trigger_ports ports;	/* Trigger and related ports */
	u_int8_t 			reply;		/* Confirm a reply connection */
	struct nf_nat_range range;
};

static void __del_trigger(struct ipt_trigger *trig)
{
    IP_NF_ASSERT(trig);
    write_lock_bh(&ipt_trigger_lock);

     /* delete from 'trigger_list' */
    list_del(&trig->list);
    write_unlock_bh(&ipt_trigger_lock);
    kfree(trig);
}

static void trigger_refresh(struct ipt_trigger *trig, unsigned long extra_jiffies)
{
    IP_NF_ASSERT(trig);
    write_lock_bh(&ipt_trigger_lock);
    /* Need del_timer for race avoidance (may already be dying). */
    if (del_timer(&trig->timeout)) 
	{
		trig->timeout.expires = jiffies + extra_jiffies;
		add_timer(&trig->timeout);
    }
    write_unlock_bh(&ipt_trigger_lock);
}

static void trigger_timeout(unsigned long ul_trig)
{
    struct ipt_trigger *trig = (void *) ul_trig;
	
    write_lock_bh(&ipt_trigger_lock);
    __del_trigger(trig);
    write_unlock_bh(&ipt_trigger_lock);
}

static unsigned int add_new_trigger(struct ipt_trigger *trig)
{
    struct ipt_trigger *new;

    new = (struct ipt_trigger *)kmalloc(sizeof(struct ipt_trigger), GFP_ATOMIC);

	if (!new)
	{
		return -ENOMEM;
    }
	
    memset(new, 0, sizeof(*trig));
    INIT_LIST_HEAD(&new->list);
    memcpy(new, trig, sizeof(*trig));
	
    init_timer(&new->timeout);
    new->timeout.data = (unsigned long)new;
    new->timeout.function = trigger_timeout;
    new->timeout.expires = jiffies + (TRIGGER_TIMEOUT * HZ);
    add_timer(&new->timeout);

    write_lock_bh(&ipt_trigger_lock);
	list_add(&new->list, &trigger_list);	
    write_unlock_bh(&ipt_trigger_lock);

    return 0;
}

static inline int check_info(const struct ipt_trigger *i, const void *targinfo)
{
    const struct ipt_trigger_info *info = targinfo;

	if (i->rproto != info->related || memcmp(&i->ports, &info->ports, sizeof(struct ipt_trigger_ports)))
		return 0;

	return 1;
}

static inline int trigger_out_matched(const struct ipt_trigger *i,	const u_int16_t proto, const u_int16_t dport, const void *targinfo)
{
	if (!i->mproto)
	{	
		if((i->ports.mport[0] <= dport) && (i->ports.mport[1] >= dport))
		{
			return check_info(i, targinfo);
		}
		
		return 0;
	}
	else
	{
		if ((i->mproto == proto) && (i->ports.mport[0] <= dport) && (i->ports.mport[1] >= dport))
		{
			return check_info(i, targinfo);
		}

		return 0;
	}
}

static unsigned int
trigger_out(struct sk_buff **pskb,
		    const struct net_device *in,
		    const struct net_device *out,
		    unsigned int hooknum, const void *targinfo,
		    void *userinfo)
{
    const struct ipt_trigger_info *info = targinfo;
    struct ipt_trigger trig, *found;
    const struct iphdr *iph = ip_hdr(*pskb);
    struct tcphdr *tcph = (void *)iph + (iph->ihl << 2);	/* Might be TCP, UDP */	//Leo

    /* Check if the trigger range has already existed in 'trigger_list'. */
    found = LIST_FIND(&trigger_list, trigger_out_matched, struct ipt_trigger *, iph->protocol, ntohs(tcph->dest), info);

    if (found) 
	{	
		/* Yeah, it exists. We need to update(delay) the destroying timer. */
		trigger_refresh(found, TRIGGER_TIMEOUT * HZ);
		/* In order to allow multiple hosts use the same port range, we update
	   	the 'saddr' after previous trigger has a reply connection. */
		if (found->reply)
	    	found->srcip = iph->saddr;
    }
    else 
	{		
		/* Create new trigger */
		memset(&trig, 0, sizeof(trig));
		trig.srcip = iph->saddr;
		trig.mproto = iph->protocol;
		trig.rproto = info->related;
		memcpy(&trig.ports, &info->ports, sizeof(struct ipt_trigger_ports));
		add_new_trigger(&trig);	/* Add the new 'trig' to list 'trigger_list'. */
    }
	
    return IPT_CONTINUE;	/* We don't block any packet. */
}

static inline int trigger_in_matched(const struct ipt_trigger *i, const u_int16_t proto, const u_int16_t dport)
{

    if (!i->rproto)
		return ((i->ports.rport[0] <= dport) && (i->ports.rport[1] >= dport));
	else
	    return ((i->rproto == proto) && (i->ports.rport[0] <= dport) && (i->ports.rport[1] >= dport));
}

static unsigned int
trigger_in(	struct sk_buff **pskb,
		    const struct net_device *in,
		    const struct net_device *out,
		    unsigned int hooknum, const void *targinfo,
		    void *userinfo)
{
    struct ipt_trigger *found;
    const struct iphdr *iph = ip_hdr(*pskb);
    struct tcphdr *tcph = (void *)iph + (iph->ihl << 2);	/* Might be TCP, UDP */	//Leo
	
    /* Check if the trigger-ed range has already existed in 'trigger_list'. */
    found = LIST_FIND(&trigger_list, trigger_in_matched, struct ipt_trigger *, iph->protocol, ntohs(tcph->dest));
	
    if (found) 
	{
		/* Yeah, it exists. We need to update(delay) the destroying timer. */
		trigger_refresh(found, TRIGGER_TIMEOUT * HZ);
		return NF_ACCEPT;	/* Accept it, or the imcoming packet could be dropped in the FORWARD chain */
    }
 
    return IPT_CONTINUE;	/* Our job is the interception. */
}

static unsigned int
trigger_dnat(struct sk_buff **pskb,
		    const struct net_device *in,
		    const struct net_device *out,
		    unsigned int hooknum, const void *targinfo,
		    void *userinfo)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct iphdr *iph = ip_hdr(*pskb);
	struct tcphdr *tcph = (void *)iph + (iph->ihl << 2);	//Leo
	struct nf_nat_range newrange;
	struct ipt_trigger *found;

    IP_NF_ASSERT(hooknum == NF_INET_PRE_ROUTING);
	
    /* Check if the trigger-ed range has already existed in 'trigger_list'. */
    found = LIST_FIND(&trigger_list, trigger_in_matched, struct ipt_trigger *, iph->protocol, ntohs(tcph->dest));

    if (!found || !found->srcip)
		return IPT_CONTINUE;	/* We don't block any packet. */

	//printk("Get PT to %u \n", ntohs(tcph->dest));
        
    found->reply = 1;	/* Confirm there has been a reply connection. */
    ct = nf_ct_get(*pskb, &ctinfo);
	
    IP_NF_ASSERT(ct && (ctinfo == IP_CT_NEW));
    
	newrange = ((struct nf_nat_range){
		    IP_NAT_RANGE_MAP_IPS, found->srcip, found->srcip,
		    found->range.min, found->range.max});

	return nf_nat_setup_info(ct, &newrange, IP_NAT_MANIP_DST);
}

static unsigned int
trigger_target(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ipt_trigger_info *info = par->targinfo;
	const struct iphdr *iph = ip_hdr(skb);
    
    if ((iph->protocol != IPPROTO_TCP) && (iph->protocol != IPPROTO_UDP))
		return IPT_CONTINUE;

    if (info->type == IPT_TRIGGER_OUT)
		return trigger_out(&skb, par->in, par->out, par->hooknum, par->targinfo, NULL);
    else if (info->type == IPT_TRIGGER_IN)
		return trigger_in(&skb, par->in, par->out, par->hooknum, par->targinfo, NULL);
    else if (info->type == IPT_TRIGGER_DNAT)
    	return trigger_dnat(&skb, par->in, par->out, par->hooknum, par->targinfo, NULL);

    return IPT_CONTINUE;
}

static int trigger_check(const struct xt_tgchk_param *par)
{
	const struct ipt_trigger_info *info = par->targinfo;
	struct list_head *cur_item, *tmp_item;

	if ((strcmp(par->table, "mangle") == 0)) {
		printk("trigger_check: bad table `%s'.\n", par->table);
		return -EINVAL;
	}
 	
	if (par->hook_mask & ~((1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_FORWARD) | (1 << NF_INET_POST_ROUTING))) {
		printk("trigger_check: bad hooks %x.\n", par->hook_mask);
		return -EINVAL;
	}
	
	if (info->trigger) {
	    if (info->trigger != IPPROTO_TCP && info->trigger != IPPROTO_UDP && info->trigger != 0) {
			printk("trigger_check: bad proto %d.\n", info->trigger);
			return -EINVAL;
	    }
	}

	if (info->related) {
	    if (info->related != IPPROTO_TCP && info->related != IPPROTO_UDP && info->related != 0) {
			printk("trigger_check: bad proto %d.\n", info->related);
			return -EINVAL;
	    }
	}	

	if (info->type == IPT_TRIGGER_OUT) {
	    if (!info->ports.mport[0] || !info->ports.rport[0]) {
			printk("trigger_check: Try 'iptbles -j TRIGGER -h' for help, your type is %d .\n", info->type);
			return -EINVAL;
	    }
	}
	
	/* Empty the 'trigger_list' */
	list_for_each_safe(cur_item, tmp_item, &trigger_list) 
	{
	    struct ipt_trigger *trig = (void *)cur_item;
	    
	    del_timer(&trig->timeout);
	    __del_trigger(trig);
	}

	return 0;
}

static struct xt_target porttrigger = { 				
	.name 		= "TRIGGER",
	.family 	= NFPROTO_IPV4,
	.target 	= trigger_target, 
	.targetsize	= sizeof(struct ipt_trigger_info),
	.hooks		= (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_FORWARD) | (1 << NF_INET_POST_ROUTING),				
	.checkentry = trigger_check,
	.me 		= THIS_MODULE,
};

static int __init init(void)
{
	return xt_register_target(&porttrigger);
}

static void __exit fini(void)
{
	xt_unregister_target(&porttrigger);
}

module_init(init);
module_exit(fini);

