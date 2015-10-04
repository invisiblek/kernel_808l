 /* xt_cameomark. */
 /* (C) 2010 Leo Lin
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation.
  */

#include <linux/module.h>
#include <linux/skbuff.h>

#include <linux/netfilter/xt_cmomark.h>
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leo Lin <leo_lin@cameo.com.tw>");
MODULE_DESCRIPTION("Xtables: packet cameomark match");
MODULE_ALIAS("ipt_cameomark");
MODULE_ALIAS("ip6t_cameomark");

static bool
cameomark_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_cameomark_info *info = par->matchinfo;

	bool ret = false;

	switch (info->type)
	{
		case type_time:
			ret = (skb->timematchtag & (1 << info->offset));
			break;
		case type_acl:
			ret = (skb->aclmatchtag & (1 << info->offset));
			break;
		case type_acl_val:
			ret = ((skb->aclmatchtag & info->offset) == info->offset ? true : false);
			//printk("%u,%u,%u\n", skb->aclmatchtag, info->offset, (skb->aclmatchtag & info->offset));
			break;
		case type_acl_or:
			ret = (skb->aclmatchtag & info->offset);
			//printk("aclmatch:%x, offset:%x, ret:%x\n", skb->aclmatchtag, info->offset, ret);
			break;
	}

	return ret;
}

static int cameomark_mt_check(struct xt_mtchk_param *par)
{
	const struct xt_cameomark_info *minfo = par->matchinfo;

	if (minfo->type != type_acl_val)
	{
		if (minfo->offset > 31) {
			printk(KERN_WARNING "cameomark: only supports 32bit(0~31) cameomark\n");
			return false;
		}
	}
	return true;
}

static struct xt_match cameomark_mt_reg[] __read_mostly = {
	{
		.name		= "cameomark",
		.family		= NFPROTO_UNSPEC,
		//.checkentry	= cameomark_mt_check,
		.match		= cameomark_mt,
		.matchsize	= sizeof(struct xt_cameomark_info),
		.me			= THIS_MODULE,
	}
};

static int __init cameomark_mt_init(void)
{
	return xt_register_matches(cameomark_mt_reg, ARRAY_SIZE(cameomark_mt_reg));
}

static void __exit cameomark_mt_exit(void)
{
	xt_unregister_matches(cameomark_mt_reg, ARRAY_SIZE(cameomark_mt_reg));
}

module_init(cameomark_mt_init);
module_exit(cameomark_mt_exit);
