#include <linux/config.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_ipv6/ip6t_CTFILTER.h>
/* Cameo add */
/* CONFIG_CAMEO_TP_NEW */
#if CONFIG_CAMEO_TP_NEW
#include <linux/list.h>
#include <net/cameo/cameo_tp_types.h>
#include <net/cameo/cameo_tp.h>
#endif
/* Cameo add end */

MODULE_DESCRIPTION("Xtables: packet \"ctfilter\" target for IPv6");
MODULE_LICENSE("GPL");

#define icmpv6_id(icmph)        (icmph->icmp6_dataun.u_echo.identifier)

#if 0
	#define DEBUGP(format, args...) printk("%s_%d: "format"\n",__FUNCTION__,__LINE__, ##args)
#else
	#define DEBUGP(format, args...) 
#endif

static unsigned int
ctfilter_tg6(struct sk_buff *skb, const struct xt_target_param *par)  //Modify xt_target_param to xt_action_param 20120117 Beautidays
{
	const struct ip6t_ctfilter_info *ctfilter_info = par->targinfo;
	int found=0;
	enum ip_conntrack_info ct_info;
	struct nf_conntrack_tuple *tuple=NULL;
	struct ipv6hdr  *iph;

	// for each all conntrack
	struct nf_conn *ict;
	struct nf_conntrack_tuple *ituple;
	struct nf_conntrack_tuple tuple_tmp;

/* Cameo add */
/* CONFIG_CAMEO_TP_NEW */
#if CONFIG_CAMEO_TP_NEW
	struct hlist_head *head;
	struct hlist_node *node;
#else
	unsigned int i;
	struct nf_conntrack_tuple_hash *ih;
	struct hlist_nulls_node *in;
#endif

	iph = ipv6_hdr(skb);
	if(!nf_ct_get_tuplepr(skb, skb_network_offset(skb), NFPROTO_IPV6, &tuple_tmp) || !iph)
	{
		DEBUGP("ctfilter_tg6: get tulpler failed or get ip header failed(%p) return IP6T_CONTINUE", iph);
		return IP6T_CONTINUE;
	}
	tuple = &tuple_tmp;
	DEBUGP("%p skb->len=%d",tuple,skb->len);

	/*************************************************************************************/
	/* By now,                                                                           */
	/* CTFILTER work for state:NEW and RELEATED if contrack is effectived(means not NULL)*/
	/* protocol support: TCP UDP ICMP                                                    */
	/*                                                                   Xavier@20130306 */
	/*************************************************************************************/
	if ((nf_ct_get(skb, &ct_info) && ct_info!=IP_CT_NEW && ct_info!=IP_CT_RELATED) ||
		(tuple->dst.protonum!=IPPROTO_TCP && tuple->dst.protonum!=IPPROTO_UDP && tuple->dst.protonum!=IPPROTO_ICMPV6))
	{
		DEBUGP("ctfilter_tg6: state(%p, %d) or protocol(%d) not supported, return IP6T_CONTINUE\n",
			 nf_ct_get(skb, &ct_info), ct_info, tuple->dst.protonum);
		return IP6T_CONTINUE;
	}

	rcu_read_lock();

/* Cameo add */
/* CONFIG_CAMEO_TP_NEW */
#if CONFIG_CAMEO_TP_NEW
	DEBUGP("ctfilter_tg6: tunple all=%pI6", tuple->dst.u3.all);
	head = cameo_FindTpHead(tuple, IP_CT_DIR_REPLY);

	if(!hlist_empty(head)) {

		struct icmp6hdr _icmph;
		struct icmp6hdr *icmph = skb_header_pointer(skb, sizeof(struct ipv6hdr), sizeof(struct icmp6hdr), &_icmph);    
		hlist_for_each_entry(ict, node, head, cameo_node[IP_CT_DIR_REPLY])
		{
			ituple = &ict->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
#else
	struct nf_conn *ct;
	struct net *net;
	ct = nf_ct_get(skb, &ct_info);
	net = nf_ct_net(ct);
	DEBUGP("ct=%p",ct);
	for (i = 0; i < nf_conntrack_htable_size; i++) {
		hlist_nulls_for_each_entry(ih, in, &net->ct.hash[i], hnnode)
		{
			DEBUGP("ctfilter_tg6: net=%p\n",net);
			/* we only want IP_CT_DIR_ORIGINAL */
			if (NF_CT_DIRECTION(ih))
				continue;

			ict = nf_ct_tuplehash_to_ctrack(ih);
			ituple = &ih->tuple;
#endif
			if(ituple->src.l3num != AF_INET6)//only need to check itouple with l3proto is IPv6,the other is ipv4
				continue;
			/*
				be check with icmp package for detail reply ip header. 
				Layer 2 -> Layer 3-> Layer 4->(Layer 3->Layer 4)
				MAC          IPv6         ICMPv6     Original package
			*/
			if( iph->nexthdr == IPPROTO_ICMPV6 )
			{
				DEBUGP("checkICMP: type:%d", icmph->icmp6_type);
				DEBUGP("checkICMP:tuple sip=%pI6, DstIP=%pI6", tuple->src.u3.ip6 ,tuple->dst.u3.ip6 );
				DEBUGP("checkICMP:tuple.src.u.all=%d ,tuple.src.l3num=%d",tuple->src.u.all,tuple->src.l3num);
				DEBUGP("checkICMP:tuple.dst.u.all=%d, tuple.dst.protonum=%d\n",tuple->dst.u.all,tuple->dst.protonum);
				DEBUGP("checkICMP:ituple sip=%pI6, DstIP=%pI6", ituple->src.u3.ip6 ,ituple->dst.u3.ip6 );
				DEBUGP("checkICMP:ituple.src.u.all=%d ,ituple.src.l3num=%d",ituple->src.u.all,ituple->src.l3num);
				DEBUGP("checkICMP:ituple.dst.u.all=%d, ituple.dst.protonum=%d\n",ituple->dst.u.all,ituple->dst.protonum);			

				if(icmph->icmp6_type!=ICMPV6_DEST_UNREACH && icmph->icmp6_type!=ICMPV6_PKT_TOOBIG ){
					DEBUGP("checkICMPv6: not my type(%d), continue to next loop\n", icmph->icmp6_type);
					continue;
				}

				if((memcmp(tuple->dst.u3.ip6, ituple->src.u3.ip6, sizeof(struct in6_addr)) == 0)
					&&(memcmp(tuple->src.u3.ip6, ituple->dst.u3.ip6, sizeof(struct in6_addr)) == 0))
				{
					DEBUGP("ctfilter_tg6: %d found, return NF_ACCEPT\n",__LINE__);
					rcu_read_unlock();
					return NF_ACCEPT;
				}
			}
			/*
				CHECK TCP UDP
			*/
			// check ict is AF_INET6, TCP status is IPS_SEEN_REPLY_BIT (IP_CT_ESTABLISHED), or UDP
			//by pass tuple is tcp and ituple is IPv6 FRAGMENT  + Ext UDP/TCP header
			if ((ituple->src.l3num == AF_INET6 && 
			    tuple->dst.protonum == ituple->dst.protonum) ||
				(ituple->dst.protonum==IPPROTO_FRAGMENT &&
				((tuple->dst.protonum==IPPROTO_TCP&&test_bit(IPS_SEEN_REPLY_BIT, &ict->status)) || tuple->dst.protonum==IPPROTO_UDP)))
			{
				DEBUGP("ctfilter_tg6: ctfilter_info->type:%d", ctfilter_info->type);
				DEBUGP("ctfilter_tg6: itunple sip=%pI6, sport=%d", ituple->src.u3.ip6, ntohs(ituple->src.u.tcp.port));
				DEBUGP("ctfilter_tg6:  tunple dip=%pI6, dport=%d\n", tuple->dst.u3.ip6, ntohs(tuple->dst.u.tcp.port));
				
				if (memcmp(tuple->dst.u3.ip6, ituple->src.u3.ip6, sizeof(struct in6_addr)) == 0 &&
				    tuple->dst.u.tcp.port == ituple->src.u.tcp.port)
				{
					if (ctfilter_info->type == IP6T_ADDRESS_DEPENDENT) {
						if (memcmp(tuple->src.u3.ip6, ituple->dst.u3.ip6, sizeof(struct in6_addr)) == 0)
							found = 1;
					} else
						found = 1;
					
					if (found) {
						DEBUGP("ctfilter_tg6: found conntrack\n");
						goto exit_loop;
					}
				}
			}
		}
	}
	else
	{
		DEBUGP("ctfilter_tg6: list empty\n");
	}

exit_loop:

	rcu_read_unlock();
	if (found) {
		DEBUGP("ctfilter_tg6: return IP6T_CONTINUE\n");
		return IP6T_CONTINUE;
	} else {
		DEBUGP("ctfilter_tg6: return NF_DROP\n");
		return NF_DROP;
	}
}

static int ctfilter_tg6_check(const struct xt_tgchk_param *par)
{
	unsigned int hook_mask = par->hook_mask;
	const struct ip6t_ctfilter_info *ctfilter_info = par->targinfo;

	if( ctfilter_info->type == IP6T_ADDRESS_PORT_DEPENDENT) {
		DEBUGP("ip6t_CTFILTER: For Port and Address Restricted. this rule is needless\n");
		return -EINVAL;
	}
	else if( ctfilter_info->type == IP6T_ADDRESS_DEPENDENT) {
		DEBUGP("ip6t_CTFILTER: IP6T_ADDRESS_DEPENDENT.\n");
	}
	else if( ctfilter_info->type == IP6T_ENDPOINT_INDEPENDENT) {
		DEBUGP("ip6t_CTFILTER: Type = IP6T_ENDPOINT_INDEPENDENT.\n");
	}

	if (hook_mask & ~(1 << NF_INET_FORWARD)) {
		DEBUGP("ip6t_CTFILTER: bad hooks %x.\n", hook_mask);
		return -EINVAL;
	}

	return 0;
}

static struct xt_target ctfilter_tg6_reg __read_mostly = {
	.name		= "CTFILTER",
	.family		= NFPROTO_IPV6,
	.target		= ctfilter_tg6,
	.targetsize	= sizeof(struct ip6t_ctfilter_info),
	.checkentry	= ctfilter_tg6_check,
	.me		= THIS_MODULE
};

static int __init ctfilter_tg6_init(void)
{
	return xt_register_target(&ctfilter_tg6_reg);
}

static void __exit ctfilter_tg6_exit(void)
{
	xt_unregister_target(&ctfilter_tg6_reg);
}

module_init(ctfilter_tg6_init);
module_exit(ctfilter_tg6_exit);
