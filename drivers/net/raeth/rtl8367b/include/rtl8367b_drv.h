
#ifndef __8367_DRV_H__
#define __8367_DRV_H__

int rtl8367rb_init(void);
int get_port_stat(swInfo *pInfo);
int set_port_speed(swInfo *pInfo);
int set_acl_rule(aclRule *pRule);
int mldSnoopRuleJoin(struct in6_addr *ma, int prefixLen, int port);
int mldSnoopRuleLeave(struct in6_addr *ma, int prefixLen, int port);

typedef struct _DEFAULT_RULE
{
	unsigned short groupIP[8];
	unsigned short prefixLen;
}DEFAULT_RULE;

#endif


