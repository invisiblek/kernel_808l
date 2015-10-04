/* Masquerade.  Simple mapping which alters range to a local IP address
   (depending on route). */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/types.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/route.h>
#include <net/netfilter/nf_nat_rule.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("Xtables: automatic-address SNAT");

#define CONFIG_IP_NF_TARGET_UDP_CONE_NAT

#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT
#include <linux/list.h>
#include <linux/netdevice.h>

#define DEBUGON			0

static DEFINE_RWLOCK(masqType_lock);

#define MAX_HASH_HEAD	8
static struct list_head root[MAX_HASH_HEAD];
static int nodeCnt[MAX_HASH_HEAD];
static int nodeCntAll;

#define CONE_NAT_TIMEOUT 300

typedef enum
{
	np_src,
	np_nat,
	np_dst,

	np_max
}natPoint;

typedef struct
{
	struct list_head list;
	struct timer_list timeout;
	
	__be32	ip[np_max];
	__be16  port[np_max];
	__be16  protocol;

	__be16	ifidx;
	__be16	natType;	//0:CONE 1:ADDRESS RESTRICT CONE
}natTypeNode;

static void addNATNode(natTypeNode *node)		//New Rule
{
	__be32 ip = node->ip[np_nat];
	__be16 port = node->port[np_nat];
	__be16 protocol = node->protocol;
	int index = ((ip ^ ((port << 16) | protocol)) % MAX_HASH_HEAD);

	write_lock_bh(&masqType_lock);
	if (nodeCntAll > 1024 && nodeCnt[index] > 0)
	{
		natTypeNode *nodeDel = list_entry(root[index].prev, natTypeNode, list);
		
		if (del_timer(&nodeDel->timeout))
		{
			list_del(&nodeDel->list);
			kfree(nodeDel);
		}
	}
	else
	{
		nodeCnt[index]++;
		nodeCntAll++;
	}
	
	list_add(&node->list, &root[index]);
	add_timer(&node->timeout);	
	write_unlock_bh(&masqType_lock);
}

static void updateNATNode(natTypeNode *node)	//Hit Rule
{
	mod_timer(&node->timeout, jiffies + CONE_NAT_TIMEOUT * HZ);
}

static void timerTimeOut(unsigned long nodeptr)
{
	natTypeNode *node;
	int index;
	
	write_lock_bh(&masqType_lock);	
	node = (natTypeNode *) nodeptr;
	index = ((node->ip[np_nat] ^ (node->port[np_nat]<<16 | node->protocol)) % MAX_HASH_HEAD);
	list_del(&node->list);	
	nodeCnt[index]--;
	nodeCntAll--;
	write_unlock_bh(&masqType_lock);
	kfree(node);

}

static inline natTypeNode *getNode(__be32 ip, __be16 port, __be16 protocol, int ifidx)
{
	int index = ((ip ^ (port<<16 | protocol)) % MAX_HASH_HEAD);
	
	struct list_head *next;

	if (unlikely(list_empty(&root[index])))
		return NULL;

	list_for_each(next, &root[index])
	{
		natTypeNode *node = list_entry(next,natTypeNode,list);

		if ((ip == node->ip[np_nat]) && 
			(port == node->port[np_nat]) && 
			(protocol == node->protocol) && 
			(ifidx == node->ifidx))
		{
			return node;
		}
	}
	
	return NULL;
}
#endif


/* FIXME: Multiple targets. --RR */
static int masquerade_tg_check(const struct xt_tgchk_param *par)
{
	const struct nf_nat_multi_range_compat *mr = par->targinfo;

	if (mr->range[0].flags & IP_NAT_RANGE_MAP_IPS) {
		pr_debug("bad MAP_IPS.\n");
		return -EINVAL;
	}
	if (mr->rangesize != 1) {
		pr_debug("bad rangesize %u\n", mr->rangesize);
		return -EINVAL;
	}
	return 0;
}

static unsigned int
masquerade_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct nf_conn *ct;
	struct nf_conn_nat *nat;
	enum ip_conntrack_info ctinfo;
	struct nf_nat_range newrange;
	const struct nf_nat_multi_range_compat *mr;
	const struct rtable *rt;
	__be32 newsrc;

	NF_CT_ASSERT(par->hooknum == NF_INET_POST_ROUTING);


#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT
	if (par->hooknum == NF_INET_PRE_ROUTING)
	{
		natTypeNode *node;
		unsigned int ret;
		
		mr = par->targinfo;
		ret = IPT_CONTINUE;
		ct = nf_ct_get(skb, &ctinfo);

		if ((ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum)!=IPPROTO_UDP)
		{
			return ret;
		}
		
#if DEBUGON		
		printk(	"\tINPUT CT, "
				"%pI4:%d, %pI4:%d, protocol=%d, iif=%d\n",
				&(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip), ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all,
				&(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip), ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum, skb->dev->ifindex);
#endif		
		//lock it 
		read_lock_bh(&masqType_lock);

		node = getNode( ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, 
						ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all,
						ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum,
						skb->dev->ifindex);
		

		if (!node)
		{
#if DEBUGON		
			printk("\tnode not found\n");
#endif
			read_unlock_bh(&masqType_lock);
			return ret;
		}
		
		if (node->natType)
		{
			if (node->ip[np_dst]!= ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)
			{
#if DEBUGON		
				printk("\tAddress not match\n");
#endif
				read_unlock_bh(&masqType_lock);
				return ret;
			}
		}

		updateNATNode(node);

		//unlock it
		read_unlock_bh(&masqType_lock);

		//dnat
		newrange = ((struct nf_nat_range) {
				mr->range[0].flags | IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED,
				node->ip[np_src], node->ip[np_src],
				{node->port[np_src]}, {node->port[np_src]}});

		ret = nf_nat_setup_info(ct, &newrange, IP_NAT_MANIP_DST);	/*DNAT?*/

		#ifdef CONFIG_NETFILTER_XT_MATCH_CAMEOMARK
		if (mr->range[0].flags & IP_NAT_RANGE_CAMEOMARK)
			skb->aclmatchtag |= (1 << ((mr->range[0].flags >> 16) & 0x1F));
		#endif
		
#if DEBUGON		
		printk("\tret=%d\n",ret);

		printk( "\tGet Node, "
				"%pI4:%d, "
				"%pI4:%d, "
				"%pI4:%d, "
				"protocol=%d "
				"ifidx=%d, "
				"expires=%u \n",
				&(node->ip[np_src]), node->port[np_src],
				&(node->ip[np_nat]), node->port[np_nat],
				&(node->ip[np_dst]), node->port[np_dst],
				node->protocol,
				skb->dev->ifindex,
				(node->timeout.expires-jiffies) / HZ);

		printk(	"\tNew CT, "
				"%pI4:%d, %pI4:%d, %pI4:%d, %pI4:%d, protocol=%d, iif=%d\n",
				&(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip), ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all,
				&(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip), ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all,
				&(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip), ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all,
				&(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip), ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum, skb->dev->ifindex);
#endif


#if 0
#ifdef CONFIG_NETFILTER_XT_MATCH_CAMEOMARK
		skb->aclmatchtag |= (1 << IP_NAT_RANGE_GET_OFFSET(mr->range[0].flags));
#if DEBUGON		
		printk("\tset offset bit ==> %d\n", IP_NAT_RANGE_GET_OFFSET(mr->range[0].flags));
#endif
#endif
#else
		ct->status |= IPS_ASSURED;	//set assured
#endif		
		//always continue, even can't process
		return ret;
	}	
#endif

	ct = nf_ct_get(skb, &ctinfo);
	nat = nfct_nat(ct);

	NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED
			    || ctinfo == IP_CT_RELATED + IP_CT_IS_REPLY));

	/* Source address is 0.0.0.0 - locally generated packet that is
	 * probably not supposed to be masqueraded.
	 */
	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == 0)
		return NF_ACCEPT;

	mr = par->targinfo;
	rt = skb_rtable(skb);
	newsrc = inet_select_addr(par->out, rt->rt_gateway, RT_SCOPE_UNIVERSE);
	if (!newsrc) {
		pr_info("%s ate my IP address\n", par->out->name);
		return NF_DROP;
	}

	nat->masq_index = par->out->ifindex;

	/* Transfer from original range. */
	newrange = ((struct nf_nat_range)
		{ mr->range[0].flags | IP_NAT_RANGE_MAP_IPS,
		  newsrc, newsrc,
		  mr->range[0].min, mr->range[0].max });

#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT
	{
		unsigned int ret;

		ret = nf_nat_setup_info(ct, &newrange, IP_NAT_MANIP_SRC);

		//record if it is udp
		if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP)
		{
			natTypeNode *newNode = getNode(	ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, 
											ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all,
											IPPROTO_UDP,
											par->out->ifindex);

			if (unlikely(newNode))
			{
#if DEBUGON
				printk( "Before Replace Node, "
						"%pI4:%d, "
						"%pI4:%d, "
						"%pI4:%d, "
						"protocol=%d "
						"ifidx=%d \n",
						&(newNode->ip[np_src]), newNode->port[np_src],
						&(newNode->ip[np_nat]), newNode->port[np_nat],
						&(newNode->ip[np_dst]), newNode->port[np_dst],
						IPPROTO_UDP,
						par->out->ifindex);

#endif							
				//replace value
				newNode->ip[np_src] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
				newNode->ip[np_nat] = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
				newNode->ip[np_dst] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				
				newNode->port[np_src] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
				newNode->port[np_nat] = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
				newNode->port[np_dst] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				
				newNode->protocol = IPPROTO_UDP;
				
				newNode->ifidx = par->out->ifindex;
				
				newNode->natType = 1;
			
				updateNATNode(newNode);
#if DEBUGON
				printk( "After Replace Node, "
						"%pI4:%d, "
						"%pI4:%d, "
						"%pI4:%d, "
						"protocol=%d "
						"ifidx=%d \n",
						&(newNode->ip[np_src]), newNode->port[np_src],
						&(newNode->ip[np_nat]), newNode->port[np_nat],
						&(newNode->ip[np_dst]), newNode->port[np_dst],
						IPPROTO_UDP,
						par->out->ifindex);

#endif				
				goto exit;
			}

			newNode = (natTypeNode *) kmalloc(sizeof(natTypeNode), GFP_ATOMIC);
			
			if (unlikely(!newNode))
			{
#if DEBUGON
				printk("No More Memory\n");
#endif					
				goto exit;
			}

			//put value
			newNode->ip[np_src] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
			newNode->ip[np_nat] = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
			newNode->ip[np_dst] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;

			newNode->port[np_src] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
			newNode->port[np_nat] = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
			newNode->port[np_dst] = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;

			newNode->protocol = IPPROTO_UDP;

			newNode->ifidx = par->out->ifindex;

			newNode->natType = 1;
			
			//add timer				
			init_timer(&newNode->timeout);
			newNode->timeout.data = (unsigned long) newNode;
			newNode->timeout.function = timerTimeOut;
			newNode->timeout.expires = jiffies + (CONE_NAT_TIMEOUT * HZ);

			//add list
			INIT_LIST_HEAD(&newNode->list);
			addNATNode(newNode);

			#ifdef CONFIG_NETFILTER_XT_MATCH_CAMEOMARK
			if (mr->range[0].flags & IP_NAT_RANGE_CAMEOMARK)
				skb->aclmatchtag |= (1 << ((mr->range[0].flags >> 16) & 0x1F));
			#endif
#if DEBUGON
			printk(	"Save Node, "
					"%pI4:%d, "
					"%pI4:%d, "
					"%pI4:%d, "
					"protocol=%d "
					"ifidx=%d \n",
					&(newNode->ip[np_src]), newNode->port[np_src],
					&(newNode->ip[np_nat]), newNode->port[np_nat],
					&(newNode->ip[np_dst]), newNode->port[np_dst],
					IPPROTO_UDP,
					par->out->ifindex);
#endif
		}
		
		exit:	
			return ret;		
	}
#else
	/* Hand modified range to generic setup. */
	return nf_nat_setup_info(ct, &newrange, IP_NAT_MANIP_SRC);
#endif
}

static int
device_cmp(struct nf_conn *i, void *ifindex)
{
	const struct nf_conn_nat *nat = nfct_nat(i);

	if (!nat)
		return 0;

	return nat->masq_index == (int)(long)ifindex;
}

static int masq_device_event(struct notifier_block *this,
			     unsigned long event,
			     void *ptr)
{
	const struct net_device *dev = ptr;
	struct net *net = dev_net(dev);

	if (event == NETDEV_DOWN) {
		/* Device was downed.  Search entire table for
		   conntracks which were associated with that device,
		   and forget them. */
		NF_CT_ASSERT(dev->ifindex != 0);

		nf_ct_iterate_cleanup(net, device_cmp,
				      (void *)(long)dev->ifindex);
	}

	return NOTIFY_DONE;
}

static int masq_inet_event(struct notifier_block *this,
			   unsigned long event,
			   void *ptr)
{
	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
	return masq_device_event(this, event, dev);
}

static struct notifier_block masq_dev_notifier = {
	.notifier_call	= masq_device_event,
};

static struct notifier_block masq_inet_notifier = {
	.notifier_call	= masq_inet_event,
};

static struct xt_target masquerade_tg_reg __read_mostly = {
	.name		= "MASQUERADE",
	.family		= NFPROTO_IPV4,
	.target		= masquerade_tg,
	.targetsize	= sizeof(struct nf_nat_multi_range_compat),
	.table		= "nat",
#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT	
	.hooks 		= 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_POST_ROUTING,
#else
	.hooks		= 1 << NF_INET_POST_ROUTING,
#endif
	.checkentry	= masquerade_tg_check,
	.me		= THIS_MODULE,
};

static int __init masquerade_tg_init(void)
{
	int ret;
#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT		
	int i;
#endif

	ret = xt_register_target(&masquerade_tg_reg);

#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT	
	//reset node 
	for (i=0; i<MAX_HASH_HEAD; i++)
	{		
		nodeCnt[i]=0;
		nodeCntAll=0;
		INIT_LIST_HEAD(&root[i]);
	}

	printk("LEO_CONE_NAT extend enable, each node (%d) byte\n", sizeof(natTypeNode));
#endif	

	if (ret == 0) {
		/* Register for device down reports */
		register_netdevice_notifier(&masq_dev_notifier);
		/* Register IP address change reports */
		register_inetaddr_notifier(&masq_inet_notifier);
	}

	return ret;
}

#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT	
void remove_Cone_Nat(void)
{
	int i;
	write_lock_bh(&masqType_lock);	
	for (i=0; i<MAX_HASH_HEAD; i++)
	{
		struct list_head *next;

		nodeCnt[i]=0;
		nodeCntAll=0;

redo:
		if (list_empty(&root[i]))
			continue;
		
		list_for_each(next,&root[i])
		{
			natTypeNode *node = list_entry(next,natTypeNode,list);
			
			if (del_timer(&node->timeout))
			{
				list_del(&node->list);
				kfree(node);
			}
			goto redo;
		}
	}
	write_unlock_bh(&masqType_lock);
}
#endif

static void __exit masquerade_tg_exit(void)
{
#ifdef CONFIG_IP_NF_TARGET_UDP_CONE_NAT	
		remove_Cone_Nat();
#endif	

	xt_unregister_target(&masquerade_tg_reg);
	unregister_netdevice_notifier(&masq_dev_notifier);
	unregister_inetaddr_notifier(&masq_inet_notifier);
}

module_init(masquerade_tg_init);
module_exit(masquerade_tg_exit);
