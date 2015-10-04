#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include <net/cameo/cameo_ct_types.h>

#if defined(CONFIG_CAMEO_CT_NEW)

static LIST_HEAD(ss_list);
static LIST_HEAD(sr_list);
static LIST_HEAD(es_list);
static LIST_HEAD(fw_list);
static LIST_HEAD(cw_list);
static LIST_HEAD(la_list);
static LIST_HEAD(tw_list);
static LIST_HEAD(cl_list);
static LIST_HEAD(li_list);
static LIST_HEAD(ur_list);
static LIST_HEAD(as_list);

struct cameo_state_list Cameo_State_List[] = {
	{enNO, NULL},
	{enSS, &ss_list},
	{enSR, &sr_list},
	{enES, &es_list},
	{enFW, &fw_list},
	{enCW, &cw_list},
	{enLA, &la_list},
	{enTW, &tw_list},
	{enCL, &cl_list},
	{enLI, &li_list},
	{enUR, &ur_list},
	{enAS, &as_list}
};

static void init_cameo_state_list(void)
{
	int cnt;

	for(cnt = 0; cnt < sizeof(Cameo_State_List) / sizeof(struct cameo_state_list); cnt++)
	{
		struct cameo_state_list *ptr = &Cameo_State_List[cnt];

		if(ptr->state_list)
			INIT_LIST_HEAD(ptr->state_list);
	}

	return;
}

int32_t cameo_nf_conn_init(void)
{
	init_cameo_state_list();

	return SUCCESS;
}

int32_t cameo_AddCtToList(struct sk_buff *skb, struct nf_conn *ct)
{
	if(NULL == ip_hdr(skb))
		return SUCCESS;

	switch(ip_hdr(skb)->protocol)
	{
		case IPPROTO_TCP:
			if(Cameo_State_List[ct->proto.tcp.state].state_list != NULL)
				list_add_tail(&ct->state_list, Cameo_State_List[ct->proto.tcp.state].state_list);
			break;
		case IPPROTO_UDP:
			if(ct->status & IPS_SEEN_REPLY)
				list_add_tail(&ct->state_list, Cameo_State_List[enAS].state_list);
			else
				list_add_tail(&ct->state_list, Cameo_State_List[enUR].state_list);
			break;
	}

	return SUCCESS;
}

void __cameo_nf_ct_refresh_acct(struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  const struct sk_buff *skb,
			  unsigned long extra_jiffies,
			  int do_acct,
			  unsigned char protocol,
			  void * param1,
			  void * param2)
{
	//NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);
	//NF_CT_ASSERT(skb);

	/* Only update if this is not a fixed timeout */
	if (test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status))
		goto acct;

	/* If not in hash table, timer will not be active yet */
	if (!nf_ct_is_confirmed(ct)) {
		ct->timeout.expires = extra_jiffies;
	} else {
		/* Only update the timeout if the new timeout is at least
		   HZ jiffies from the old timeout. Need del_timer for race
		   avoidance (may already be dying). */
		mod_timer_pending(&ct->timeout, jiffies + extra_jiffies);

		spin_lock_bh(&ct->lock);
		switch(protocol)
		{
			case 6:
				list_move_tail(&ct->state_list, Cameo_State_List[(enum cameo_state_enum)param2].state_list);
				break;
			case 17:
				if (ct->status & IPS_SEEN_REPLY)
					list_move_tail(&ct->state_list, Cameo_State_List[enAS].state_list);
				else
					list_move_tail(&ct->state_list, Cameo_State_List[enUR].state_list);
				break;
		}
		spin_unlock_bh(&ct->lock);
	}

acct:
	if (do_acct) {
		struct nf_conn_counter *acct;

		acct = nf_conn_acct_find(ct);
		if (acct) {
			spin_lock_bh(&ct->lock);
			acct[CTINFO2DIR(ctinfo)].packets++;
			acct[CTINFO2DIR(ctinfo)].bytes += skb->len;
			spin_unlock_bh(&ct->lock);
		}
	}
}

static void cameo_death_act(unsigned long ul_conntrack)
{
	struct nf_conn *ct = (void *)ul_conntrack;

	if(!test_bit(IPS_DYING_BIT, &ct->status) &&
	    unlikely(nf_conntrack_event(IPCT_DESTROY, ct) < 0)) {
		/* destroy event was not delivered */
		nf_ct_delete_from_lists(ct);
		nf_ct_insert_dying_list(ct);
		return;
	}
	set_bit(IPS_DYING_BIT, &ct->status);
	nf_ct_delete_from_lists(ct);
	nf_ct_put(ct);
}

static inline int32_t __cameo_drop_one_ct_proc(struct list_head *head)
{
	struct list_head *ptr;
	struct nf_conn *ct;

	if(!list_empty(head))
	{
		list_for_each(ptr, head)
		{
			ct = list_entry(ptr, struct nf_conn, state_list);

			if(ct != NULL)
				if (likely(!nf_ct_is_dying(ct) &&
					   atomic_inc_not_zero(&ct->ct_general.use)))
				{
					read_unlock_bh(&nf_conntrack_lock);
					if (del_timer(&ct->timeout))
						cameo_death_act((unsigned long)ct);

					nf_ct_put(ct);
					return 1;
				}
		}
	}
	return 0;
}

static inline int32_t __cameo_drop_one_ct(uint8_t esFlags)
{
	int i;

	read_lock_bh(&nf_conntrack_lock);
	if(esFlags)
	{
		if(__cameo_drop_one_ct_proc(Cameo_State_List[enES].state_list))
			return 1;

		if(__cameo_drop_one_ct_proc(Cameo_State_List[enAS].state_list))
			return 1;
	}

	for(i = 0; i < sizeof(Cameo_State_List) / sizeof(struct cameo_state_list); i++)
		if(__cameo_drop_one_ct_proc(Cameo_State_List[i].state_list))
			return 1;

	read_unlock_bh(&nf_conntrack_lock);
	return 0;
}

int32_t cameo_drop_conntrack(const struct nf_conntrack_tuple *orig,const struct nf_conntrack_tuple *repl)
{
	if(__cameo_drop_one_ct(1) || __cameo_drop_one_ct(0))
		return 1;
	else
	{
		if (net_ratelimit())
		{
			printk(KERN_WARNING
				"enter urgent stage!!\n");
		}
	}
	return 0;
}
#endif /* #if defined(CONFIG_CAMEO_CT_NEW) */

