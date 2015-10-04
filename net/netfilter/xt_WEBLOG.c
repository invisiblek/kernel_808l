
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/sock.h>

#ifdef CONFIG_CAMEO_KLOG_ENTRY
#include <net/cameo/cameo_klog_entry.h>
#else
#define KLOG_BUF_SIZ 256
#endif

#define WEBLOG_DBG 0
typedef enum
{
	info_url = 0,
	info_host,
	info_referer,
	info_url_port,

	i_max
}info_name;

struct req_info_t
{
	char *info[i_max];
};

static inline char* index(const char *s, int c)
{
	int cnt;
	if(unlikely(s==NULL))
		return NULL;

	for(cnt=0; (s+cnt)!='\0' && *(s+cnt)!=c; cnt++)
		;

	return (*(s+cnt)==c) ? (char *)(s+cnt) : NULL;
}

static inline bool get_req_info(const char *buffer, struct req_info_t *info)
{
	//find url
	info->info[info_url] = index(buffer, ' ');
	if (info->info[info_url])
		info->info[info_url] += 1;
	else
		return false;

	//find host
	info->info[info_host] = strstr(buffer,"Host: ");
	if (info->info[info_host])
		info->info[info_host]+=6;
	else
		return false;

	//find referer
	info->info[info_referer] = strstr(buffer,"Referer: ");
	if (info->info[info_referer])
		info->info[info_referer]+=9;

	return true;
}

static inline char *get_end(const char *src)
{
	char *data = NULL;

	data = strstr( src, "\015\012" );
	if (data == (char*) 0)
	{
		data = strstr( src, "\012" );
	}

	return data;
}

static inline void do_log(const struct sk_buff *skb, struct req_info_t req, unsigned int len)
{
	struct iphdr *iph = ip_hdr(skb);
	struct ethhdr *ethh = eth_hdr(skb);
	char buf[KLOG_BUF_SIZ];
	char *end_ptr = NULL;
	int action_len = 0, log_len = 0;

	memset(buf, 0, KLOG_BUF_SIZ);
	#undef MAC_ARG
	#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]
	sprintf(buf, "[PROXYLOG]Log: from ip = %pI4 , mac = "MAC_FMT", to ", &iph->saddr, MAC_ARG(ethh->h_source));

	log_len = strlen(buf);
	end_ptr = get_end(req.info[info_host]);
	if(end_ptr)
	{
		action_len = end_ptr-req.info[info_host];
		action_len = (KLOG_BUF_SIZ-1-log_len)>action_len ? action_len : (KLOG_BUF_SIZ-1-log_len);
		if(action_len>0)
			strncpy(buf+log_len, req.info[info_host], action_len);
	}
	else
		return;

	log_len = strlen(buf);
	end_ptr = strchr(req.info[info_url], ' ');
	if(end_ptr)
	{
		action_len = end_ptr-req.info[info_url];
		action_len = (KLOG_BUF_SIZ-1-log_len)>action_len ? action_len : (KLOG_BUF_SIZ-1-log_len);
		if(action_len>0)
			strncpy(buf+log_len, req.info[info_url], action_len);
	}
	else
		return;

	log_len = strlen(buf);
	#ifdef CONFIG_CAMEO_KLOG_ENTRY
	cameo_klog_entry_put(buf, log_len);
	#endif
	#if WEBLOG_DBG
	printk("%s\n", buf);
	#endif
}

static unsigned int
weblog_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	struct req_info_t req;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int dataoff;
	unsigned int data_len;
	char *data;
	char *first_line_end;
	
	iph = ip_hdr(skb);
	if(unlikely(iph==NULL || iph->protocol!=IPPROTO_TCP))
		goto pass;

	tcph = (struct tcphdr *)(skb->data + ((iph->ihl)<<2));;
	if(unlikely(tcph==NULL || tcph->dest!=htons(80)))
		goto pass;

	dataoff = ((iph->ihl)<<2)+((tcph->doff)<<2);
	#if WEBLOG_DBG
	printk("%pI4:%hu->%pI4:%hu, len:%u, dataoff%u\n", &iph->saddr, ntohs(tcph->source), &iph->daddr, ntohs(tcph->dest), skb->len, dataoff);
	#endif
	if(dataoff >= skb->len)
		goto pass;

 	data = (char *)(skb_network_header(skb) + dataoff);
	data_len = skb->len - dataoff;

	memset(&req, 0, sizeof(req));

	#if WEBLOG_DBG
	char *__ptr = data;
	int __i;
	for(__i=0; __i<data_len; __i++)
		printk("%02x ", (*(__ptr+__i)&0xff));
	printk("\n");
	#endif

	first_line_end = get_end(data);

	if (first_line_end == NULL)
		goto pass;
	else if (strncmp(first_line_end-8, "HTTP/1", 6) != 0)
		goto pass;

	get_req_info(data, &req);
	do_log(skb, req, data_len>KLOG_BUF_SIZ-1 ? KLOG_BUF_SIZ-1 : data_len);
pass:
	return XT_CONTINUE;
}

static struct xt_target xt_WEBLOG_target[] = {
	{
	.name		= "WEBLOG",
	.family		= AF_INET,
	.target		= weblog_tg,
	.me		= THIS_MODULE
	},
	#if 0
	{
	.name		= "WEBLOG",
	.family		= AF_INET6,
	.target		= weblog_tg,
	.me		= THIS_MODULE
	},
	#endif
};

static int __init init(void)
{
	return xt_register_targets(xt_WEBLOG_target, ARRAY_SIZE(xt_WEBLOG_target));
}

static void __exit fini(void)
{
	xt_unregister_targets(xt_WEBLOG_target, ARRAY_SIZE(xt_WEBLOG_target));
}

module_init(init);
module_exit(fini);
