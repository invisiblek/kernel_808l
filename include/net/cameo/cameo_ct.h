#ifndef CAMEO_CT_H
#define CAMEO_CT_H

int32_t cameo_nf_conn_init(void);
int32_t cameo_AddCtToList(struct sk_buff *skb, struct nf_conn *ct);
int32_t cameo_drop_conntrack(const struct nf_conntrack_tuple *orig,const struct nf_conntrack_tuple *repl);

#endif /* #ifndef CAMEO_CT_H */
