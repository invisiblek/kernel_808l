 /* xt_wol. */
 /* (C) 2012 Xavier Hsu
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation.
  */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/udp.h>

#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xavier Hsu <xavier_hsu@cameo.com.tw>");
MODULE_DESCRIPTION("Xtables: Wake On Lan");
MODULE_ALIAS("ipt_wol");

#if (LINUX_VERSION_CODE>=KERNEL_VERSION(2,6,35))
static inline bool wol_mt(const struct sk_buff *skb, struct xt_match_param *par)
#else
static inline bool wol_mt(const struct sk_buff *skb, const struct xt_match_param *par)
#endif
{
	struct udphdr _uhdr, *uhdr;
	int i;
	u8 *payload;

	if(skb==NULL)
		return false;

	uhdr = (struct udphdr *)skb_header_pointer(skb, par->thoff, sizeof(_uhdr), &_uhdr);
	if(ntohs(uhdr->len)!=110)
		return false;

	payload = (unsigned char *)uhdr;
	payload += sizeof(struct udphdr);

	if(!(payload[0]==0xff && payload[1]==0xff && payload[2]==0xff
		 && payload[3]==0xff && payload[4]==0xff && payload[5]==0xff))
		return false;

	payload += 6;
	for(i=1; i<=15; i++)
	{
		if(!(payload[0]==payload[6*i] && payload[1]==payload[6*i+1] && payload[2]==payload[6*i+2]
			 && payload[3]==payload[6*i+3] && payload[4]==payload[6*i+4] && payload[5]==payload[6*i+5]))
				return false;
	}

	return true;
}

static struct xt_match wol_mt_reg[] __read_mostly = {
	{
		.name		= "wol",
		.family		= NFPROTO_IPV4,
		.match		= wol_mt,
		.me			= THIS_MODULE,
	}
};

static int __init wol_mt_init(void)
{
	return xt_register_matches(wol_mt_reg, ARRAY_SIZE(wol_mt_reg));
}

static void __exit wol_mt_exit(void)
{
	xt_unregister_matches(wol_mt_reg, ARRAY_SIZE(wol_mt_reg));
}

module_init(wol_mt_init);
module_exit(wol_mt_exit);
