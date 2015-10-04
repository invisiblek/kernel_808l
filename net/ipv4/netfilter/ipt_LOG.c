/*
 * This is a module which is used for logging packets.
 */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/route.h>

#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ipt_LOG.h>
#include <net/netfilter/nf_log.h>

#ifdef CONFIG_CAMEO_KLOG_ENTRY
#include <net/cameo/cameo_klog_entry.h>
#endif
#ifdef CONFIG_CAMEO_LOG_PKT
#include <net/cameo/cameo_log_pkt.h>
#endif

#include <linux/types.h>
#include <linux/net.h>

#define BUF_SIZE 1024

//Xavier@20130628 for DUT crashed during BT-test issue.
#if 0
#define _PATH_LOG "/var/syslogd"
asmlinkage int cameo_sendlog(const char *buf, int len)
{
	struct kvec iov;
	struct msghdr msg;
	int err = 0;
	struct socket *csock = NULL;
	struct sockaddr addr;
	int alen = 0;

	if(sock_create_kern(AF_UNIX, SOCK_DGRAM, 0, &csock) < 0)
	{
		printk("Unable to create socket.\n");
		return -EIO;
	}

	addr.sa_family = AF_UNIX;
	strncpy(addr.sa_data, _PATH_LOG, sizeof(addr.sa_data));

	alen = sizeof(addr) - sizeof(addr.sa_data) + strlen(addr.sa_data);

	if((err = kernel_connect(csock, &addr, alen, 0)) < 0)
	{
		printk( "Unable to connect to syslog server, error=%d\n", err);
		goto out;
	}

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	memset(&msg, 0x00, sizeof(msg));
	msg.msg_name = (void *)&addr;
	msg.msg_namelen = alen;
	msg.msg_flags = MSG_DONTWAIT;

	if((err = kernel_sendmsg(csock, &msg, &iov, 1, len)) < 0)
	{
		printk("send to syslog err:%d\n", err);
	}

out:
	if(csock)
	{
		sock_release(csock);
		csock = NULL;
	}

	return err;
}
#endif

asmlinkage int cameo_log(char *buf, int *len, const char *fmt, ...)
{
	va_list args;
	int r = 0;

	va_start(args, fmt);
	r = vscnprintf(buf + *len, BUF_SIZE - *len, fmt, args);
	*len += r;
	va_end(args);

	return r;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("Xtables: IPv4 packet logging to syslog");

/* Use lock to serialize, so printks don't overlap */
static DEFINE_SPINLOCK(log_lock);

/* One level of recursion won't kill us */
static void dump_packet(const struct nf_loginfo *info,
			const struct sk_buff *skb,
			unsigned int iphoff,
			char *buf,
			int *len)
{
	struct iphdr _iph;
	const struct iphdr *ih;
	unsigned int logflags;

	if (info->type == NF_LOG_TYPE_LOG)
		logflags = info->u.log.logflags;
	else
		logflags = NF_LOG_MASK;

	ih = skb_header_pointer(skb, iphoff, sizeof(_iph), &_iph);
	if (ih == NULL) {
		printk("TRUNCATED");
		return;
	}

	/* Important fields:
	 * TOS, len, DF/MF, fragment offset, TTL, src, dst, options. */
	/* Max length: 40 "SRC=255.255.255.255 DST=255.255.255.255 " */
	cameo_log(buf, len, "SRC=%pI4 DST=%pI4 ",
	       &ih->saddr, &ih->daddr);

	/* Max length: 46 "LEN=65535 TOS=0xFF PREC=0xFF TTL=255 ID=65535 " */
	cameo_log(buf, len, "LEN=%u TOS=0x%02X PREC=0x%02X TTL=%u ID=%u ",
	       ntohs(ih->tot_len), ih->tos & IPTOS_TOS_MASK,
	       ih->tos & IPTOS_PREC_MASK, ih->ttl, ntohs(ih->id));

	/* Max length: 6 "CE DF MF " */
	if (ntohs(ih->frag_off) & IP_CE)
		cameo_log(buf, len, "CE ");
	if (ntohs(ih->frag_off) & IP_DF)
		cameo_log(buf, len, "DF ");
	if (ntohs(ih->frag_off) & IP_MF)
		cameo_log(buf, len, "MF ");

	/* Max length: 11 "FRAG:65535 " */
	if (ntohs(ih->frag_off) & IP_OFFSET)
		cameo_log(buf, len, "FRAG:%u ", ntohs(ih->frag_off) & IP_OFFSET);

	if ((logflags & IPT_LOG_IPOPT) &&
	    ih->ihl * 4 > sizeof(struct iphdr)) {
		const unsigned char *op;
		unsigned char _opt[4 * 15 - sizeof(struct iphdr)];
		unsigned int i, optsize;

		optsize = ih->ihl * 4 - sizeof(struct iphdr);
		op = skb_header_pointer(skb, iphoff+sizeof(_iph),
					optsize, _opt);
		if (op == NULL) {
			printk("TRUNCATED");
			return;
		}

		/* Max length: 127 "OPT (" 15*4*2chars ") " */
		cameo_log(buf, len, "OPT (");
		for (i = 0; i < optsize; i++)
			cameo_log(buf, len, "%02X", op[i]);
		cameo_log(buf, len, ") ");
	}

	switch (ih->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph;
		const struct tcphdr *th;

		/* Max length: 10 "PROTO=TCP " */
		cameo_log(buf, len, "PROTO=TCP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		th = skb_header_pointer(skb, iphoff + ih->ihl * 4,
					sizeof(_tcph), &_tcph);
		if (th == NULL) {
			cameo_log(buf, len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		cameo_log(buf, len, "SPT=%u DPT=%u ",
		       ntohs(th->source), ntohs(th->dest));
		/* Max length: 30 "SEQ=4294967295 ACK=4294967295 " */
		if (logflags & IPT_LOG_TCPSEQ)
			cameo_log(buf, len, "SEQ=%u ACK=%u ",
			       ntohl(th->seq), ntohl(th->ack_seq));
		/* Max length: 13 "WINDOW=65535 " */
		cameo_log(buf, len, "WINDOW=%u ", ntohs(th->window));
		/* Max length: 9 "RES=0x3F " */
		cameo_log(buf, len, "RES=0x%02x ", (u8)(ntohl(tcp_flag_word(th) & TCP_RESERVED_BITS) >> 22));
		/* Max length: 32 "CWR ECE URG ACK PSH RST SYN FIN " */
		if (th->cwr)
			cameo_log(buf, len, "CWR ");
		if (th->ece)
			cameo_log(buf, len, "ECE ");
		if (th->urg)
			cameo_log(buf, len, "URG ");
		if (th->ack)
			cameo_log(buf, len, "ACK ");
		if (th->psh)
			cameo_log(buf, len, "PSH ");
		if (th->rst)
			cameo_log(buf, len, "RST ");
		if (th->syn)
			cameo_log(buf, len, "SYN ");
		if (th->fin)
			cameo_log(buf, len, "FIN ");
		/* Max length: 11 "URGP=65535 " */
		cameo_log(buf, len, "URGP=%u ", ntohs(th->urg_ptr));

		if ((logflags & IPT_LOG_TCPOPT) &&
		    th->doff * 4 > sizeof(struct tcphdr)) {
			unsigned char _opt[4 * 15 - sizeof(struct tcphdr)];
			const unsigned char *op;
			unsigned int i, optsize;

			optsize = th->doff * 4 - sizeof(struct tcphdr);
			op = skb_header_pointer(skb,
						iphoff+ih->ihl*4+sizeof(_tcph),
						optsize, _opt);
			if (op == NULL) {
				printk("TRUNCATED");
				return;
			}

			/* Max length: 127 "OPT (" 15*4*2chars ") " */
			cameo_log(buf, len, "OPT (");
			for (i = 0; i < optsize; i++)
				cameo_log(buf, len, "%02X", op[i]);
			cameo_log(buf, len, ") ");
		}
		break;
	}
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE: {
		struct udphdr _udph;
		const struct udphdr *uh;

		if (ih->protocol == IPPROTO_UDP)
			/* Max length: 10 "PROTO=UDP "     */
			cameo_log(buf, len, "PROTO=UDP " );
		else	/* Max length: 14 "PROTO=UDPLITE " */
			cameo_log(buf, len, "PROTO=UDPLITE ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		uh = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_udph), &_udph);
		if (uh == NULL) {
			cameo_log(buf, len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		cameo_log(buf, len, "SPT=%u DPT=%u LEN=%u ",
		       ntohs(uh->source), ntohs(uh->dest),
		       ntohs(uh->len));
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr _icmph;
		const struct icmphdr *ich;
		static const size_t required_len[NR_ICMP_TYPES+1]
			= { [ICMP_ECHOREPLY] = 4,
			    [ICMP_DEST_UNREACH]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_SOURCE_QUENCH]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_REDIRECT]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_ECHO] = 4,
			    [ICMP_TIME_EXCEEDED]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_PARAMETERPROB]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_TIMESTAMP] = 20,
			    [ICMP_TIMESTAMPREPLY] = 20,
			    [ICMP_ADDRESS] = 12,
			    [ICMP_ADDRESSREPLY] = 12 };

		/* Max length: 11 "PROTO=ICMP " */
		cameo_log(buf, len, "PROTO=ICMP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		ich = skb_header_pointer(skb, iphoff + ih->ihl * 4,
					 sizeof(_icmph), &_icmph);
		if (ich == NULL) {
			cameo_log(buf, len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 18 "TYPE=255 CODE=255 " */
		cameo_log(buf, len, "TYPE=%u CODE=%u ", ich->type, ich->code);

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (ich->type <= NR_ICMP_TYPES &&
		    required_len[ich->type] &&
		    skb->len-iphoff-ih->ihl*4 < required_len[ich->type]) {
			cameo_log(buf, len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		switch (ich->type) {
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			/* Max length: 19 "ID=65535 SEQ=65535 " */
			cameo_log(buf, len, "ID=%u SEQ=%u ",
			       ntohs(ich->un.echo.id),
			       ntohs(ich->un.echo.sequence));
			break;

		case ICMP_PARAMETERPROB:
			/* Max length: 14 "PARAMETER=255 " */
			cameo_log(buf, len, "PARAMETER=%u ",
			       ntohl(ich->un.gateway) >> 24);
			break;
		case ICMP_REDIRECT:
			/* Max length: 24 "GATEWAY=255.255.255.255 " */
			cameo_log(buf, len, "GATEWAY=%pI4 ", &ich->un.gateway);
			/* Fall through */
		case ICMP_DEST_UNREACH:
		case ICMP_SOURCE_QUENCH:
		case ICMP_TIME_EXCEEDED:
			/* Max length: 3+maxlen */
			if (!iphoff) { /* Only recurse once. */
				cameo_log(buf, len, "[");
				dump_packet(info, skb,
					    iphoff + ih->ihl*4+sizeof(_icmph), buf, len);
				cameo_log(buf, len, "] ");
			}

			/* Max length: 10 "MTU=65535 " */
			if (ich->type == ICMP_DEST_UNREACH &&
			    ich->code == ICMP_FRAG_NEEDED)
				cameo_log(buf, len, "MTU=%u ", ntohs(ich->un.frag.mtu));
		}
		break;
	}
	/* Max Length */
	case IPPROTO_AH: {
		struct ip_auth_hdr _ahdr;
		const struct ip_auth_hdr *ah;

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 9 "PROTO=AH " */
		cameo_log(buf, len, "PROTO=AH ");

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		ah = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_ahdr), &_ahdr);
		if (ah == NULL) {
			cameo_log(buf, len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Length: 15 "SPI=0xF1234567 " */
		cameo_log(buf, len, "SPI=0x%x ", ntohl(ah->spi));
		break;
	}
	case IPPROTO_ESP: {
		struct ip_esp_hdr _esph;
		const struct ip_esp_hdr *eh;

		/* Max length: 10 "PROTO=ESP " */
		cameo_log(buf, len, "PROTO=ESP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		eh = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_esph), &_esph);
		if (eh == NULL) {
			cameo_log(buf, len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Length: 15 "SPI=0xF1234567 " */
		cameo_log(buf, len, "SPI=0x%x ", ntohl(eh->spi));
		break;
	}
	/* Max length: 10 "PROTO 255 " */
	default:
		cameo_log(buf, len, "PROTO=%u ", ih->protocol);
	}

	/* Max length: 15 "UID=4294967295 " */
	if ((logflags & IPT_LOG_UID) && !iphoff && skb->sk) {
		read_lock_bh(&skb->sk->sk_callback_lock);
		if (skb->sk->sk_socket && skb->sk->sk_socket->file)
			cameo_log(buf, len, "UID=%u GID=%u ",
				skb->sk->sk_socket->file->f_cred->fsuid,
				skb->sk->sk_socket->file->f_cred->fsgid);
		read_unlock_bh(&skb->sk->sk_callback_lock);
	}

	/* Max length: 16 "MARK=0xFFFFFFFF " */
	if (!iphoff && skb->mark)
		cameo_log(buf, len, "MARK=0x%x ", skb->mark);

	/* Proto    Max log string length */
	/* IP:      40+46+6+11+127 = 230 */
	/* TCP:     10+max(25,20+30+13+9+32+11+127) = 252 */
	/* UDP:     10+max(25,20) = 35 */
	/* UDPLITE: 14+max(25,20) = 39 */
	/* ICMP:    11+max(25, 18+25+max(19,14,24+3+n+10,3+n+10)) = 91+n */
	/* ESP:     10+max(25)+15 = 50 */
	/* AH:      9+max(25)+15 = 49 */
	/* unknown: 10 */

	/* (ICMP allows recursion one level deep) */
	/* maxlen =  IP + ICMP +  IP + max(TCP,UDP,ICMP,unknown) */
	/* maxlen = 230+   91  + 230 + 252 = 803 */
}

static void dump_mac_header(const struct nf_loginfo *info,
			    const struct sk_buff *skb,
			    char *buf,
			    int *len)
{
	struct net_device *dev = skb->dev;
	unsigned int logflags = 0;

	if (info->type == NF_LOG_TYPE_LOG)
		logflags = info->u.log.logflags;

	if (!(logflags & IPT_LOG_MACDECODE))
		goto fallback;

	switch (dev->type) {
	case ARPHRD_ETHER:
		cameo_log(buf, len, "MACSRC=%pM MACDST=%pM MACPROTO=%04x ",
		       eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest,
		       ntohs(eth_hdr(skb)->h_proto));
		return;
	default:
		break;
	}

fallback:
	cameo_log(buf, len, "MAC=");
	if (dev->hard_header_len &&
	    skb->mac_header != skb->network_header) {
		const unsigned char *p = skb_mac_header(skb);
		unsigned int i;

		cameo_log(buf, len, "%02x", *p++);
		for (i = 1; i < dev->hard_header_len; i++, p++)
			cameo_log(buf, len, ":%02x", *p);
	}
	cameo_log(buf, len, " ");
}

static struct nf_loginfo default_loginfo = {
	.type	= NF_LOG_TYPE_LOG,
	.u = {
		.log = {
			.level    = 5,
			.logflags = NF_LOG_MASK,
		},
	},
};

static void
ipt_log_packet(u_int8_t pf,
	       unsigned int hooknum,
	       const struct sk_buff *skb,
	       const struct net_device *in,
	       const struct net_device *out,
	       const struct nf_loginfo *loginfo,
	       const char *prefix)
{
	char buf[BUF_SIZE];
	int len = 0;

	if (!loginfo)
		loginfo = &default_loginfo;

	spin_lock_bh(&log_lock);
	cameo_log(buf, &len, "<%d>kernel: %sIN=%s OUT=%s ", loginfo->u.log.level | (1 << 3),
	       prefix,
	       in ? in->name : "",
	       out ? out->name : "");
#ifdef CONFIG_BRIDGE_NETFILTER
	if (skb->nf_bridge) {
		const struct net_device *physindev;
		const struct net_device *physoutdev;

		physindev = skb->nf_bridge->physindev;
		if (physindev && in != physindev)
			cameo_log(buf, &len, "PHYSIN=%s ", physindev->name);
		physoutdev = skb->nf_bridge->physoutdev;
		if (physoutdev && out != physoutdev)
			cameo_log(buf, &len, "PHYSOUT=%s ", physoutdev->name);
	}
#endif

	/* MAC logging for input path only. */
	if (in && !out)
		dump_mac_header(loginfo, skb, buf, &len);

	dump_packet(loginfo, skb, 0, buf, &len);
	cameo_log(buf, &len, "\n");

	//Xavier@20130628 for DUT crashed during BT-test issue.
	//cameo_sendlog(buf, len);
	#ifdef CONFIG_CAMEO_KLOG_ENTRY
	cameo_klog_entry_put(buf, len);
	#endif
	spin_unlock_bh(&log_lock);
}

static unsigned int
log_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ipt_log_info *loginfo = par->targinfo;
	struct nf_loginfo li;

	li.type = NF_LOG_TYPE_LOG;
	li.u.log.level = loginfo->level;
	li.u.log.logflags = loginfo->logflags;

	ipt_log_packet(NFPROTO_IPV4, par->hooknum, skb, par->in, par->out, &li,
		       loginfo->prefix);

	#ifdef CONFIG_CAMEO_LOG_PKT
	skb->aclmatchtag |= (1 << CAMEOMARK_LOGGED);
	#endif
//Leo add for log and drop
	if (loginfo->logflags & IPT_LOG_DROP)
	{
		return NF_DROP;
	}
	else
	{
		return XT_CONTINUE;
	}
}

static int log_tg_check(const struct xt_tgchk_param *par)
{
	const struct ipt_log_info *loginfo = par->targinfo;

	if (loginfo->level >= 8) {
		pr_debug("level %u >= 8\n", loginfo->level);
		return -EINVAL;
	}
	if (loginfo->prefix[sizeof(loginfo->prefix)-1] != '\0') {
		pr_debug("prefix is not null-terminated\n");
		return -EINVAL;
	}
	return 0;
}

static struct xt_target log_tg_reg __read_mostly = {
	.name		= "LOG",
	.family		= NFPROTO_IPV4,
	.target		= log_tg,
	.targetsize	= sizeof(struct ipt_log_info),
	.checkentry	= log_tg_check,
	.me		= THIS_MODULE,
};

static struct nf_logger ipt_log_logger __read_mostly = {
	.name		= "ipt_LOG",
	.logfn		= &ipt_log_packet,
	.me		= THIS_MODULE,
};

static int __init log_tg_init(void)
{
	int ret;

	ret = xt_register_target(&log_tg_reg);
	if (ret < 0)
		return ret;
	nf_log_register(NFPROTO_IPV4, &ipt_log_logger);
	return 0;
}

static void __exit log_tg_exit(void)
{
	nf_log_unregister(&ipt_log_logger);
	xt_unregister_target(&log_tg_reg);
}

module_init(log_tg_init);
module_exit(log_tg_exit);
