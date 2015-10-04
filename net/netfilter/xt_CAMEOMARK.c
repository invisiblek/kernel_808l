 /* xt_CAMEOMARK. */
 /* (C) 2010 Leo Lin
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation.
  */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_CAMEOMARK.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leo Lin <leo_lin@cameo.com.tw>");
MODULE_DESCRIPTION("Xtables: packet match mark");
MODULE_ALIAS("ipt_CAMEOMARK");
MODULE_ALIAS("ip6t_CAMEOMARK");

static unsigned int
cameomark_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_cameomark_target_info *markinfo = par->targinfo;

	switch (markinfo->type)
	{
		case type_time:
			skb->timematchtag |= (1 << markinfo->offset);
			break;
			
		case type_acl:
			skb->aclmatchtag |= (1 << markinfo->offset);
			break;

		case type_acl_other_machines:
			if((skb->aclmatchtag&markinfo->offset)==markinfo->offset)
				skb->aclmatchtag &= (~(markinfo->offset));
			else if((skb->aclmatchtag&CMARK(ACLMARK_OTHER))==CMARK(ACLMARK_OTHER))
				skb->aclmatchtag |= (markinfo->offset);
			break;
	}

	return XT_CONTINUE;
}

static int cameomark_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_cameomark_target_info *markinfo = par->targinfo;

	if (markinfo->type!=type_acl_other_machines && markinfo->offset > 31) 
	{
		printk(KERN_WARNING "CAMEOMARK: Only supports 32bit(0~31) wide mark\n");
		return -EINVAL;
	}
	return 0;
}

static struct xt_target cameomark_tg_reg[] __read_mostly = {
	{
		.name		= "CAMEOMARK",
		.family		= NFPROTO_UNSPEC,
		.checkentry	= cameomark_tg_check,
		.target		= cameomark_tg,
		.targetsize	= sizeof(struct xt_cameomark_target_info),
		.table		= "mangle",
		.me			= THIS_MODULE,
	}
};

static int __init cameomark_tg_init(void)
{
	return xt_register_targets(cameomark_tg_reg, ARRAY_SIZE(cameomark_tg_reg));
}

static void __exit cameomark_tg_exit(void)
{
	xt_unregister_targets(cameomark_tg_reg, ARRAY_SIZE(cameomark_tg_reg));
}

module_init(cameomark_tg_init);
module_exit(cameomark_tg_exit);

