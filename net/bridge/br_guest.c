#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "br_private.h"
#include <linux/inetdevice.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/if_inet6.h>
#include <linux/in6.h>
#include <net/addrconf.h>
#endif

static int cameo_br_list_check(struct net_bridge *br, u16 port, int proto)
{
	struct cameo_port_list *p, *n;

	pr_debug("[%s %d]port:%d, proto:%d\n", __FUNCTION__, __LINE__, port, proto);

	if(proto == 6)
	{
		if((port == 80) ||
		   (port == 443))
		{
			pr_debug("[%s %d]port %d exist\n", __FUNCTION__, __LINE__, port);
			return 1;
		}

		if(!list_empty(&br->tcp_list))
		{
			list_for_each_entry_safe(p, n, &br->tcp_list, node)
			{
				if(p->port == port)
				{
					pr_debug("[%s %d]port %d exist\n", __FUNCTION__, __LINE__, p->port);
					return 1;
				}
			}
		}
	}
	else if(proto == 17)
	{
		if(!list_empty(&br->udp_list))
		{
			list_for_each_entry_safe(p, n, &br->udp_list, node)
			{
				if(p->port == port)
				{
					pr_debug("[%s %d]port %d exist\n", __FUNCTION__, __LINE__, p->port);
					return 1;
				}
			}
		}
	}

	return 0;
}

void cameo_br_list_init(struct net_bridge *br)
{
	INIT_LIST_HEAD(&br->tcp_list);
	INIT_LIST_HEAD(&br->udp_list);
}

int cameo_br_list_add(struct net_bridge *br, u16 port, int proto)
{
	struct cameo_port_list *p, *p1, *n;

	pr_debug("[%s %d]port:%d, proto:%d\n", __FUNCTION__, __LINE__, port, proto);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if(p == NULL)
		return -1;

	p->port = port;

	if(proto == 6)
	{
		if(!list_empty(&br->tcp_list))
		{
			list_for_each_entry_safe(p1, n, &br->tcp_list, node)
			{
				if(p1->port == port)
				{
					if(p)
						kfree(p);

					pr_debug("[%s %d]port %d exist\n", __FUNCTION__, __LINE__, port);
					return -1;
				}
			}
		}
		list_add_rcu(&p->node, &br->tcp_list);
	}
	else if(proto == 17)
	{
		if(!list_empty(&br->udp_list))
		{
			list_for_each_entry_safe(p1, n, &br->udp_list, node)
			{
				if(p1->port == port)
				{
					if(p)
						kfree(p);

					pr_debug("[%s %d]port %d exist\n", __FUNCTION__, __LINE__, port);
					return -1;
				}
			}
		}
		list_add_rcu(&p->node, &br->udp_list);
	}

	return 0;
}

void cameo_br_list_del_one(struct net_bridge *br, u16 port, int proto)
{
	struct cameo_port_list *p, *n;

	if(proto == 6)
	{
		if(!list_empty(&br->tcp_list))
		{
			list_for_each_entry_safe(p, n, &br->tcp_list, node)
			{
				pr_debug("[%s %d]port:%d\n", __FUNCTION__, __LINE__, p->port);
				if(p->port == port)
				{
					pr_debug("[%s %d]delete port %d\n", __FUNCTION__, __LINE__, port);
					list_del_rcu(&p->node);
					return;
				}
			}
		}
	}
	else if(proto == 17)
	{
		if(!list_empty(&br->udp_list))
		{
			list_for_each_entry_safe(p, n, &br->udp_list, node)
			{
				pr_debug("[%s %d]port:%d\n", __FUNCTION__, __LINE__, p->port);
				if(p->port == port)
				{
					pr_debug("[%s %d]delete port %d\n", __FUNCTION__, __LINE__, port);
					list_del_rcu(&p->node);
					return;
				}
			}
		}
	}
}

void cameo_br_list_del_all(struct net_bridge *br, int proto)
{
	struct cameo_port_list *p, *n;

	if(proto == 6)
	{
		if(!list_empty(&br->tcp_list))
		{
			list_for_each_entry_safe(p, n, &br->tcp_list, node)
			{
				pr_debug("[%s %d]delete port %d\n", __FUNCTION__, __LINE__, p->port);
				list_del_rcu(&p->node);
			}
		}
	}
	else if(proto == 17)
	{
		if(!list_empty(&br->udp_list))
		{
			list_for_each_entry_safe(p, n, &br->udp_list, node)
			{
				pr_debug("[%s %d]delete port %d\n", __FUNCTION__, __LINE__, p->port);
				list_del_rcu(&p->node);
			}
		}
	}
}

int cameo_check_guest_forward(struct sk_buff *skb, struct net_bridge_port *p, const struct net_bridge_port *dst)
{

	if(unlikely((p->support_guest_zone ^ dst->support_guest_zone) &&
		    (p->support_route ^ dst->support_route)))
	{
		pr_debug("[%s %d]src port no:%d, name:%s, dst port no:%d, name:%s\n", __FUNCTION__, __LINE__, p->port_no, p->dev->name, dst->port_no, dst->dev->name);
		return 0;
	}
 
	return 1;
}

int cameo_check_guest_local(struct sk_buff *skb, struct net_bridge_port *p)
{
	//struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	struct net_bridge *br = p->br;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int is_local = 0;
	u16 port = 0;

	if(unlikely(p->support_guest_zone))
	{
		if(ntohs(skb->protocol) == ETH_P_IP)
		{
			const unsigned char *dest = eth_hdr(skb)->h_dest;

			if(is_broadcast_ether_addr(dest))
			{
				udph = (struct udphdr *)(skb->data + sizeof(struct iphdr));
				if((ntohs(udph->dest) != 67) && // DHCP
				   (ntohs(udph->dest) != 68))   // DHCP
				{
					pr_debug("[%s %d]Guest Zone: %s doesn't allow broadcast packet\n", __FUNCTION__, __LINE__, p->dev->name);
					return 0;
				}
			}
			else if(is_multicast_ether_addr(dest))
			{
				pr_debug("[%s %d]Guest Zone: %s doesn't allow multicast packet\n", __FUNCTION__, __LINE__, p->dev->name);
				return 0;
			} else {
				struct in_device *in_dev = __in_dev_get_rtnl(br->dev);
				struct iphdr *iph = ip_hdr(skb);

				is_local = (in_dev->ifa_list->ifa_local == iph->daddr) ? 1: 0;

				if(likely(is_local))
				{
					if(iph->protocol == IPPROTO_TCP)
					{
						if(unlikely(p->support_route))
						{
							tcph = (void *)iph + iph->ihl * 4;
							port = ntohs(tcph->dest);
#if 0
							if((port != 80) &&
							   (port != 443))
#else
							if(!cameo_br_list_check(br, port, 6))
#endif
							{
								pr_debug("[%s %d]Guest Zone: %s doesn't allow to access tcp port %d of device\n", __FUNCTION__, __LINE__, p->dev->name, port);
								return 0;
							}
						}
						else
						{
							pr_debug("[%s %d]Guest Zone: %s doesn't allow to access tcp port of device\n", __FUNCTION__, __LINE__, p->dev->name);
							return 0;
						}
					}
					else if(iph->protocol == IPPROTO_UDP)
					{
						udph = (void *)iph + iph->ihl * 4;
						port = ntohs(udph->dest);
#if 0
						if((port != 53))
#else
						if((port != 53) &&
						   !cameo_br_list_check(br, port, 17))
#endif
						{
							pr_debug("[%s %d]Guest Zone: %s doesn't allow to access udp port %d of device\n", __FUNCTION__, __LINE__, p->dev->name, port);
							return 0;
						}
					}
					else if(iph->protocol != IPPROTO_ICMP)
					{
						pr_debug("[%s %d]Guest Zone: %s doesn't allow to access device with protocol %d\n", __FUNCTION__, __LINE__, p->dev->name, iph->protocol);
						return 0;
					}
				}
			}
		}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if(ntohs(skb->protocol) == ETH_P_IPV6)
		{
			struct inet6_dev *in_dev = __in6_dev_get(br->dev);
			struct ipv6hdr *ip6h = ipv6_hdr(skb);
			struct inet6_ifaddr *ifa;

			list_for_each_entry(ifa, &in_dev->addr_list, if_list) {
				is_local = ipv6_addr_equal(&ifa->addr, &ip6h->daddr);

				if(likely(is_local))
				{
					if(ip6h->nexthdr == IPPROTO_TCP)
					{
						if(unlikely(p->support_route))
						{
							tcph = (struct tcphdr *)(skb->data + sizeof(struct ipv6hdr));
							port = ntohs(tcph->dest);
#if 0
							if((port != 80) &&
							   (port != 443))
#else
							if(!cameo_br_list_check(br, port, 6))
#endif
							{
								pr_debug("[%s %d]Guest Zone: %s doesn't allow to access tcp port %d of device\n", __FUNCTION__, __LINE__, p->dev->name, port);
								return 0;
							}
						}
						else
						{
							pr_debug("[%s %d]Guest Zone: %s doesn't allow to access tcp port of device\n", __FUNCTION__, __LINE__, p->dev->name);
							return 0;
						}
					}
					else if(ip6h->nexthdr == IPPROTO_UDP)
					{
						udph = (struct udphdr *)(skb->data + sizeof(struct ipv6hdr));
						port = ntohs(udph->dest);

						if((port != 546) &&
						   (port != 547) &&
						   (port != 53) &&
						   !cameo_br_list_check(br, port, 17))
						{
							pr_debug("[%s %d]Guest Zone: %s doesn't allow to access udp port %d of device\n", __FUNCTION__, __LINE__, p->dev->name, port);
							return 0;
						}
					}
					else if(ip6h->nexthdr == 0x3A) // ICMPv6
					{
						struct icmp6hdr *icmp6h = (struct icmp6hdr *)(skb->data + sizeof(struct ipv6hdr));
						if((icmp6h->icmp6_type != 128) && // echo request
						   (icmp6h->icmp6_type != 129) && // echo reply
						   (icmp6h->icmp6_type != 133) && // router solicitation
						   (icmp6h->icmp6_type != 134) && // router advertisement
						   (icmp6h->icmp6_type != 135) && // neighbor solicitation
						   (icmp6h->icmp6_type != 136))   // neighbor advertisement
						{
							pr_debug("[%s %d]Guest Zone: %s doesn't allow to access icmpv6 type %d of device\n", __FUNCTION__, __LINE__, p->dev->name, icmp6h->icmp6_type);
							return 0;
						}
					}
					else
					{
						pr_debug("[%s %d]Guest Zone: %s doesn't allow to access device with protocol %d\n", __FUNCTION__, __LINE__, p->dev->name, ip6h->nexthdr);
						return 0;
					}
				}
			}
		}
#endif

	}

	return 1;
}

