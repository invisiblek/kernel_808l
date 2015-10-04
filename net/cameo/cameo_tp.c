#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include <net/cameo/cameo_tp_types.h>

#if defined(CONFIG_CAMEO_TP_NEW)

#define cameo_container_of(ptr, type, member, type1, member1) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type1 *)( (char *)__mptr - offsetof(type,member) + offsetof(type, member1));})

struct cameo_htable {
	u_int32_t size;
	int vmalloc;
	struct hlist_head *hOR;
	struct hlist_head *hRE;
};

static struct cameo_htable hinfo;

static inline struct nf_conntrack_tuple_hash *cameo_cnode_to_tuplehash(const struct hlist_node *node, int dir)
{
	return cameo_container_of(node, struct nf_conn, cameo_node[dir], struct nf_conntrack_tuple_hash, tuplehash[dir]);
}

static u_int32_t
hash_dst_port(const struct cameo_htable *ht, const struct nf_conntrack_tuple *tuple)
{
	u_int32_t hash = jhash((void *)tuple->dst.u3.all, sizeof(tuple->dst.u3.all),
				tuple->dst.protonum);

	return ((u64)hash * ht->size) >> 32;
}

static u_int32_t
hash_dst(const struct cameo_htable *ht, const struct nf_conntrack_tuple *tuple)
{
	u_int32_t hash = jhash((void *)tuple->dst.u3.all, sizeof(tuple->dst.u3.all), 0);

	return ((u64)hash * ht->size) >> 32;
}

static void init_cameo_tp_hash(void)
{
	unsigned int size;
	int i;

	memset(&hinfo, 0, sizeof(struct cameo_htable));

	size = nf_conntrack_htable_size;

	hinfo.size = size;

	hinfo.hOR = nf_ct_alloc_hashtable(&hinfo.size, &hinfo.vmalloc, 0);
	hinfo.hRE = nf_ct_alloc_hashtable(&hinfo.size, &hinfo.vmalloc, 0);

	for(i = 0; i < size; i++)
	{
		INIT_HLIST_HEAD(&hinfo.hOR[i]);
		INIT_HLIST_HEAD(&hinfo.hRE[i]);
	}

	return;
}

int32_t cameo_tp_init(void)
{
	init_cameo_tp_hash();

	return SUCCESS;
}

int32_t cameo_AddTpToList(const struct nf_conntrack_tuple *tuple)
{
	struct nf_conn *ct = nf_ct_tuple_to_ctrack(tuple);
	u_int32_t hash = hash_dst(&hinfo, tuple);

	switch(tuple->dst.dir)
	{
		case enOR:
			hlist_add_head_rcu(&ct->cameo_node[tuple->dst.dir], &hinfo.hOR[hash]);
			break;
		case enRE:
			hlist_add_head_rcu(&ct->cameo_node[tuple->dst.dir], &hinfo.hRE[hash]);
			break;
	}

	return SUCCESS;
}

struct hlist_head *cameo_FindTpHead(const struct nf_conntrack_tuple *tuple, int dir)
{
	u_int32_t hash = hash_dst(&hinfo, tuple);

	switch(dir)
	{
		case enOR:
			return &hinfo.hOR[hash];
			break;
		case enRE:
			return &hinfo.hRE[hash];
			break;
	}

	return NULL;
}

//Xavier@20130822
#ifdef CONFIG_CAMEO_TCP_RELY
#undef DEBUGP
#define DEBUGP(format, args...) //printk("%s_%d: "format"\n",__FUNCTION__,__LINE__, ##args)
void cameo_tp_add_tcp_rely(struct nf_conn *ct,
				const __u8 dir,
				const __be32 *saddr,
				const __be32 *daddr,
				const __be16 *src, const __be16 *dst)
{
	ct->tcp_rely_tuple.enable	= 1;
	ct->tcp_rely_tuple.dir		= dir;
	ct->tcp_rely_tuple.saddr	= saddr==NULL ? 0 : *saddr;
	ct->tcp_rely_tuple.daddr	= daddr==NULL ? 0 : *daddr;
	ct->tcp_rely_tuple.src		= src==NULL ? 0 : *src;
	ct->tcp_rely_tuple.dst		= dst==NULL ? 0 : *dst;

	DEBUGP("original  : %pI4:%u->%pI4:%u",
		&ct->tuplehash[dir].tuple.src.u3.ip,
		ntohs(ct->tuplehash[dir].tuple.src.u.all),
		&ct->tuplehash[dir].tuple.dst.u3.ip,
		ntohs(ct->tuplehash[dir].tuple.dst.u.all));
	DEBUGP("reply     : %pI4:%u->%pI4:%u",
		&ct->tuplehash[!dir].tuple.src.u3.ip,
		ntohs(ct->tuplehash[!dir].tuple.src.u.all),
		&ct->tuplehash[!dir].tuple.dst.u3.ip,
		ntohs(ct->tuplehash[!dir].tuple.dst.u.all));
	DEBUGP("rely      : %pI4:%u->%pI4:%u\n",
		&ct->tcp_rely_tuple.saddr,
		htons(ct->tcp_rely_tuple.src),
		&ct->tcp_rely_tuple.daddr,
		htons(ct->tcp_rely_tuple.dst));
}

int cameo_ct_find_tcp_rely(const struct nf_conn *ct, struct nf_conn *rely_ct)
{
	struct nf_conntrack_tuple rely_tuple;
	struct nf_conn *ict;
	struct nf_conntrack_tuple *ituple;
	struct hlist_head *head;
	struct hlist_node *node;
	int dir;

	if(!ct->tcp_rely_tuple.enable || test_bit(IPS_DYING_BIT, &ct->status))
		return -1;

	memset(&rely_tuple, 0, sizeof(struct nf_conntrack_tuple));
	rely_tuple.src.u3.ip	= ct->tcp_rely_tuple.saddr;
	rely_tuple.dst.u3.ip	= ct->tcp_rely_tuple.daddr;
	rely_tuple.src.u.all	= ct->tcp_rely_tuple.src;
	rely_tuple.dst.u.all	= ct->tcp_rely_tuple.dst;
	rely_tuple.dst.protonum = IPPROTO_TCP;
	rely_tuple.src.l3num	= AF_INET;
	dir						= ct->tcp_rely_tuple.dir;

	DEBUGP("dying tuple %pI4:%u -> %pI4:%u",
		&ct->tuplehash[dir].tuple.src.u3.ip,
		ntohs(ct->tuplehash[dir].tuple.src.u.all),
		&ct->tuplehash[dir].tuple.dst.u3.ip,
		ntohs(ct->tuplehash[dir].tuple.dst.u.all));

	DEBUGP("rely  tuple %pI4:%u -> %pI4:%u",
		&rely_tuple.src.u3.ip,
		ntohs(rely_tuple.src.u.all),
		&rely_tuple.dst.u3.ip,
		ntohs(rely_tuple.dst.u.all));

	head = cameo_FindTpHead(&rely_tuple, dir);
	if(hlist_empty(head))
	{
		DEBUGP("list empty\n");
		return -1;
	}

	hlist_for_each_entry(ict, node, head, cameo_node[dir])
	{
		ituple = &ict->tuplehash[dir].tuple;

		if(ituple->src.l3num!=AF_INET || ituple->dst.protonum!=IPPROTO_TCP)
		{
			DEBUGP("protocol not match, l3:%u, ituple:%u\n",  ituple->src.l3num, ituple->dst.protonum);
			continue;
		}

		DEBUGP("itunple %pI4:%u -> %pI4:%u", &ituple->src.u3.ip, ntohs(ituple->src.u.all), &ituple->dst.u3.ip, ntohs(ituple->dst.u.all));
		if( rely_tuple.dst.u3.ip==0 ? 1 : rely_tuple.dst.u3.ip==ituple->dst.u3.ip &&
			rely_tuple.src.u3.ip==0 ? 1 : rely_tuple.src.u3.ip==ituple->src.u3.ip &&
			rely_tuple.dst.u.all==0 ? 1 : rely_tuple.dst.u.all==ituple->dst.u.all &&
			rely_tuple.src.u.all==0 ? 1 : rely_tuple.src.u.all==ituple->src.u.all)
		{
			if (test_bit(IPS_DYING_BIT, &ict->status))
			{
				DEBUGP("rely tuple is dying...\n");
				return -1;
			}

			DEBUGP("matched, my expire:%lu expire up to: %lu\n", ct->timeout.expires, ict->timeout.expires);
			memcpy(rely_ct, ict, sizeof(struct nf_conn));
			return 0;
		}
	}
	return -1;
}
#endif /* CONFIG_CAMEO_TCP_RELY */
#endif /* #if defined(CONFIG_CAMEO_TP_NEW) */

