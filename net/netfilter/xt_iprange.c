/*
 *	xt_iprange - Netfilter module to match IP address ranges
 *
 *	(C) 2003 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *	(C) CC Computer Consultants GmbH, 2008
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_iprange.h>

static bool
iprange_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_iprange_mtinfo *info = par->matchinfo;
	const struct iphdr *iph = ip_hdr(skb);
	bool m;

	if (info->flags & IPRANGE_SRC) {
		m  = ntohl(iph->saddr) < ntohl(info->src_min.ip);
		m |= ntohl(iph->saddr) > ntohl(info->src_max.ip);
		m ^= !!(info->flags & IPRANGE_SRC_INV);
		if (m) {
			pr_debug("src IP %pI4 NOT in range %s%pI4-%pI4\n",
			         &iph->saddr,
			         (info->flags & IPRANGE_SRC_INV) ? "(INV) " : "",
			         &info->src_max.ip,
			         &info->src_max.ip);
			return false;
		}
	}
	if (info->flags & IPRANGE_DST) {
		m  = ntohl(iph->daddr) < ntohl(info->dst_min.ip);
		m |= ntohl(iph->daddr) > ntohl(info->dst_max.ip);
		m ^= !!(info->flags & IPRANGE_DST_INV);
		if (m) {
			pr_debug("dst IP %pI4 NOT in range %s%pI4-%pI4\n",
			         &iph->daddr,
			         (info->flags & IPRANGE_DST_INV) ? "(INV) " : "",
			         &info->dst_min.ip,
			         &info->dst_max.ip);
			return false;
		}
	}
	return true;
}

/********************************************************************************************/
/* Xavier@20130708 for original-design might caused signed-int overflow						*/
/* Example:																					*/
/*	setup ipv6 range as 3000:aaaa:bbbb:cccc::1 -> 3000:aaaa:bbbb:cccc:ffff:ffff:ffff:ffff	*/
/*	Then ipv6 address with 2001:aaaa:bbbb:cccc:1111:2222:3333:1								*/
/********************************************************************************************/
#if 0
static inline int
iprange_ipv6_sub(const struct in6_addr *a, const struct in6_addr *b)
{
	unsigned int i;
	int r;

	for (i = 0; i < 4; ++i) {
		r = ntohl(a->s6_addr32[i]) - ntohl(b->s6_addr32[i]);
		if (r != 0)
			return r;
	}

	return 0;
}
#else
static inline bool
iprange_ipv6_out_of_range(const struct in6_addr *a, const struct in6_addr *min, const struct in6_addr *max)
{
	unsigned int i;

	for (i = 0; i < 4; ++i) {
		if(ntohl(a->s6_addr32[i]) >= ntohl(min->s6_addr32[i]) && 
			ntohl(a->s6_addr32[i]) <= ntohl(max->s6_addr32[i]))
			continue;
		else
			return true;
	}

	return false;
}
#endif

static bool
iprange_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_iprange_mtinfo *info = par->matchinfo;
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	bool m;

	if (info->flags & IPRANGE_SRC) {
		//Xaveir@20130708
		#if 0
		m  = iprange_ipv6_sub(&iph->saddr, &info->src_min.in6) < 0;
		m |= iprange_ipv6_sub(&iph->saddr, &info->src_max.in6) > 0;
		#else
		m  = iprange_ipv6_out_of_range(&iph->saddr, &info->src_min.in6, &info->src_max.in6);
		#endif
		m ^= !!(info->flags & IPRANGE_SRC_INV);
		if (m)
			return false;
	}
	if (info->flags & IPRANGE_DST) {
		//Xaveir@20130708
		#if 0
		m  = iprange_ipv6_sub(&iph->daddr, &info->dst_min.in6) < 0;
		m |= iprange_ipv6_sub(&iph->daddr, &info->dst_max.in6) > 0;
		#else
		m  = iprange_ipv6_out_of_range(&iph->daddr, &info->dst_min.in6, &info->dst_max.in6);
		#endif
		m ^= !!(info->flags & IPRANGE_DST_INV);
		if (m)
			return false;
	}
	return true;
}

static struct xt_match iprange_mt_reg[] __read_mostly = {
	{
		.name      = "iprange",
		.revision  = 1,
		.family    = NFPROTO_IPV4,
		.match     = iprange_mt4,
		.matchsize = sizeof(struct xt_iprange_mtinfo),
		.me        = THIS_MODULE,
	},
	{
		.name      = "iprange",
		.revision  = 1,
		.family    = NFPROTO_IPV6,
		.match     = iprange_mt6,
		.matchsize = sizeof(struct xt_iprange_mtinfo),
		.me        = THIS_MODULE,
	},
};

static int __init iprange_mt_init(void)
{
	return xt_register_matches(iprange_mt_reg, ARRAY_SIZE(iprange_mt_reg));
}

static void __exit iprange_mt_exit(void)
{
	xt_unregister_matches(iprange_mt_reg, ARRAY_SIZE(iprange_mt_reg));
}

module_init(iprange_mt_init);
module_exit(iprange_mt_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: arbitrary IPv4 range matching");
MODULE_ALIAS("ipt_iprange");
MODULE_ALIAS("ip6t_iprange");
