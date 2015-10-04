#ifndef CAMEO_TP_H
#define CAMEO_TP_H

int32_t cameo_tp_init(void);
int32_t cameo_AddTpToList(const struct nf_conntrack_tuple *tuple);
struct hlist_head *cameo_FindTpHead(const struct nf_conntrack_tuple *tuple, int dir);

//Xavier@20130822
#ifdef CONFIG_CAMEO_TCP_RELY
struct tcp_rely_tuple_t{
	__u8 enable;
	__u8 dir;
	__u16 reserved;
	__be32 saddr;
	__be32 daddr;
	__be16 src;
	__be16 dst;
};

void cameo_tp_add_tcp_rely(struct nf_conn *ct,
				const __u8 dir,
				const __be32 *saddr,
				const __be32 *daddr,
				const __be16 *src, const __be16 *dst);

int cameo_ct_find_tcp_rely(const struct nf_conn *ct, struct nf_conn *rely_ct);
#endif

#endif /* #ifndef CAMEO_TP_H */
