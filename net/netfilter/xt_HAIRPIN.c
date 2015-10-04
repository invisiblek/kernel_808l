 /* xt_HAIRPIN.c */
 /* (C) 2013 Xavier Hsu
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation.
  */

#include <linux/config.h>
#include <linux/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/xt_HAIRPIN.h>
#include <net/netfilter/nf_nat.h>
#ifdef CONFIG_CAMEO_TP_NEW
#include <linux/list.h>
#include <net/cameo/cameo_tp_types.h>
#include <net/cameo/cameo_tp.h>
#endif

MODULE_DESCRIPTION("Xtables: packet \"HAIRPIN\" target for IPv4");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xavier <xavier_hsu@cameo.com.tw>");

#if 0
	#define DEBUGP(format, args...) printk("%s_%d: "format"\n",__FUNCTION__,__LINE__, ##args)
#else
	#define DEBUGP(format, args...) 
#endif

static unsigned int
HAIRPIN_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	unsigned int ret = XT_CONTINUE;
#ifdef CONFIG_CAMEO_TP_NEW
	const struct xt_hairpin_info *info = par->targinfo;
	enum ip_conntrack_info ct_info;
	struct nf_conntrack_tuple tuple, invert;
	struct nf_conn *ict, *ct, *ict2;
	struct nf_conntrack_tuple *ituple, *ituple2;
	struct hlist_head *head, *head2;
	struct hlist_node *node, *node2;
	struct nf_nat_range range;

	if(!nf_ct_get_tuplepr(skb, skb_network_offset(skb), NFPROTO_IPV4, &tuple))
	{
		DEBUGP("get tulpler failed, return XT_CONTINUE");
		return ret;
	}

	ct = nf_ct_get(skb, &ct_info);
	if ((ct && ct_info!=IP_CT_NEW && ct_info!=IP_CT_RELATED) ||
		(tuple.dst.protonum!=info->proto_type && tuple.dst.protonum!=IPPROTO_FRAGMENT))
	{
		DEBUGP("state(%p, %d) or protocol(%d, request:%d, %s) not supported, return XT_CONTINUE\n",
			 nf_ct_get(skb, &ct_info), ct_info, tuple.dst.protonum, info->proto_type, info->proto_type==IPPROTO_TCP ? "tcp" : "udp");
		return ret;
	}

	rcu_read_lock();

	DEBUGP("original tunple src=%pI4:%u dst=%pI4:%u", &tuple.src.u3.ip, ntohs(tuple.src.u.all), &tuple.dst.u3.ip, ntohs(tuple.dst.u.all));

	head = cameo_FindTpHead(&tuple, IP_CT_DIR_REPLY);
	if(hlist_empty(head))
	{
		DEBUGP("list empty\n");
		goto out;
	}

	hlist_for_each_entry(ict, node, head, cameo_node[IP_CT_DIR_REPLY])
	{
		ituple = &ict->tuplehash[IP_CT_DIR_REPLY].tuple;

		if(ituple->src.l3num != AF_INET || tuple.dst.protonum != ituple->dst.protonum
			|| (ituple->dst.protonum!=info->proto_type && ituple->dst.protonum!=IPPROTO_FRAGMENT)
			|| (memcmp(&(ituple->dst.u3.ip), &(tuple.dst.u3.ip), sizeof(ituple->dst.u3.ip))!=0 || ituple->dst.u.all!=tuple.dst.u.all)
			)
			continue;


		nf_ct_invert_tuplepr(&invert, ituple);
		DEBUGP(" ituple	     src=%pI4:%u dst=%pI4:%u", &ituple->src.u3.ip, ntohs(ituple->src.u.all), &ituple->dst.u3.ip, ntohs(ituple->dst.u.all));
		DEBUGP(" invert	     src=%pI4:%u dst=%pI4:%u", &invert.src.u3.ip, ntohs(invert.src.u.all), &invert.dst.u3.ip, ntohs(invert.dst.u.all));
		head2 = cameo_FindTpHead(&invert, IP_CT_DIR_ORIGINAL);
		if(hlist_empty(head2)) 
		{
			DEBUGP("list2 empty\n");
			goto out;
		}

		hlist_for_each_entry(ict2, node2, head2, cameo_node[IP_CT_DIR_ORIGINAL])
		{
			ituple2 = &ict->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
			if(ituple2->src.l3num != AF_INET || invert.dst.protonum != ituple2->dst.protonum
				|| (ituple2->dst.protonum!=info->proto_type && ituple2->dst.protonum!=IPPROTO_FRAGMENT)
				|| (memcmp(&(ituple2->dst.u3.ip), &(invert.dst.u3.ip), sizeof(ituple2->dst.u3.ip))!=0 || ituple2->dst.u.all!=invert.dst.u.all)
				|| ituple2->src.u.all!=tuple.dst.u.all
				)
				continue;

			DEBUGP(" ituple2     src=%pI4:%u dst=%pI4:%u", &ituple2->src.u3.ip, ntohs(ituple2->src.u.all), &ituple2->dst.u3.ip, ntohs(ituple2->dst.u.all));
			DEBUGP(" HAIRPIN to  %pI4:%u\n", &ituple2->src.u3.ip, ntohs(ituple2->src.u.all));

			#ifdef CONFIG_NETFILTER_XT_MATCH_CAMEOMARK
			if(info->cameo_mark)
				skb->aclmatchtag |= (info->cameo_mark);
			#endif

			range.flags = IP_NAT_RANGE_MAP_IPS;
			range.min_ip = ituple2->src.u3.ip;
			range.max_ip = ituple2->src.u3.ip;
			ret = nf_nat_setup_info(ct, &range, IP_NAT_MANIP_DST);
			goto out;
		}
	}
out:
	rcu_read_unlock();
#endif /* CONFIG_CAMEO_TP_NEW */
	DEBUGP(" return %d(drop:%d accept:%d continue:%d)\n", ret, NF_DROP, NF_ACCEPT, XT_CONTINUE);
	return ret;
}

static int HAIRPIN_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target hairpin_tg_reg __read_mostly = {
	.name		= "HAIRPIN",
	.family		= NFPROTO_IPV4,
	.target		= HAIRPIN_tg,
	.targetsize	= sizeof(struct xt_hairpin_info),
	.checkentry	= HAIRPIN_tg_check,
	.me			= THIS_MODULE,
	.hooks      = (1 << NF_INET_PRE_ROUTING),
	.table		= "nat",
};

static int __init HAIRPIN_tg_init(void)
{
	return xt_register_target(&hairpin_tg_reg);
}

static void __exit HAIRPIN_tg_exit(void)
{
	xt_unregister_target(&hairpin_tg_reg);
}

module_init(HAIRPIN_tg_init);
module_exit(HAIRPIN_tg_exit);
