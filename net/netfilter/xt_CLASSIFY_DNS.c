 /* xt_CLASSIFY_DNS. */
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
#include <linux/netfilter/xt_CLASSIFY_DNS.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leo Lin <leo_lin@cameo.com.tw>");
MODULE_DESCRIPTION("Xtables: DNS packet record");
MODULE_ALIAS("ipt_CLASSIFY_DNS");
MODULE_ALIAS("ip6t_CLASSIFY_DNS");

#define __PACK__			__attribute__ ((packed))

static int isInit = 0;
static int record_count = 0;

#define MAX_RECORD	20

LIST_HEAD(dns_list);
static DEFINE_RWLOCK(dns_list_lock);

struct xtm {
	unsigned int year;
	u_int8_t month;    /* (1-12) */
	u_int8_t monthday; /* (1-31) */
	u_int8_t weekday;  /* (1-7) */
	u_int8_t hour;     /* (0-23) */
	u_int8_t minute;   /* (0-59) */
	u_int8_t second;   /* (0-59) */
	unsigned int dse;
};
extern struct timezone sys_tz; /* ouch */

static const u_int16_t days_since_year[] = {
	0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334,
};

static const u_int16_t days_since_leapyear[] = {
	0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335,
};

/*
 * Since time progresses forward, it is best to organize this array in reverse,
 * to minimize lookup time.
 */
enum {
	DSE_FIRST = 2039,
};
static const u_int16_t days_since_epoch[] = {
	/* 2039 - 2030 */
	25202, 24837, 24472, 24106, 23741, 23376, 23011, 22645, 22280, 21915,
	/* 2029 - 2020 */
	21550, 21184, 20819, 20454, 20089, 19723, 19358, 18993, 18628, 18262,
	/* 2019 - 2010 */
	17897, 17532, 17167, 16801, 16436, 16071, 15706, 15340, 14975, 14610,
	/* 2009 - 2000 */
	14245, 13879, 13514, 13149, 12784, 12418, 12053, 11688, 11323, 10957,
	/* 1999 - 1990 */
	10592, 10227, 9862, 9496, 9131, 8766, 8401, 8035, 7670, 7305,
	/* 1989 - 1980 */
	6940, 6574, 6209, 5844, 5479, 5113, 4748, 4383, 4018, 3652,
	/* 1979 - 1970 */
	3287, 2922, 2557, 2191, 1826, 1461, 1096, 730, 365, 0,
};

static inline bool is_leap(unsigned int y)
{
	return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
}

struct DNS_HEADER
{
    unsigned short id; // identification number
    
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
    
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available


    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries

}__PACK__;


//Constant sized fields of query structure
struct DNS_QUERY_NAME
{
	//unsigned char test_byte;	
	u_int8_t test_byte;
};


#define MAX_DNS_STR_LEN	128
typedef struct dns_data
{
	struct list_head	list;
	unsigned char 		mac[6];
	char				str[MAX_DNS_STR_LEN];
	struct xtm 			qtime;
}DNS_DATA;

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

static inline unsigned int localtime_1(struct xtm *r, time_t time)
{
	unsigned int v, w;

	/* Each day has 86400s, so finding the hour/minute is actually easy. */
	v         = time % 86400;
	r->second = v % 60;
	w         = v / 60;
	r->minute = w % 60;
	r->hour   = w / 60;
	return v;
}

static inline void localtime_2(struct xtm *r, time_t time)
{
	/*
	 * Here comes the rest (weekday, monthday). First, divide the SSTE
	 * by seconds-per-day to get the number of _days_ since the epoch.
	 */
	r->dse = time / 86400;

	/*
	 * 1970-01-01 (w=0) was a Thursday (4).
	 * -1 and +1 map Sunday properly onto 7.
	 */
	r->weekday = (4 + r->dse - 1) % 7 + 1;
}

static void localtime_3(struct xtm *r, time_t time)
{
	unsigned int year, i, w = r->dse;

	/*
	 * In each year, a certain number of days-since-the-epoch have passed.
	 * Find the year that is closest to said days.
	 *
	 * Consider, for example, w=21612 (2029-03-04). Loop will abort on
	 * dse[i] <= w, which happens when dse[i] == 21550. This implies
	 * year == 2009. w will then be 62.
	 */
	for (i = 0, year = DSE_FIRST; days_since_epoch[i] > w;
	    ++i, --year)
		/* just loop */;

	r->year = year;

	w -= days_since_epoch[i];

	/*
	 * By now we have the current year, and the day of the year.
	 * r->yearday = w;
	 *
	 * On to finding the month (like above). In each month, a certain
	 * number of days-since-New Year have passed, and find the closest
	 * one.
	 *
	 * Consider w=62 (in a non-leap year). Loop will abort on
	 * dsy[i] < w, which happens when dsy[i] == 31+28 (i == 2).
	 * Concludes i == 2, i.e. 3rd month => March.
	 *
	 * (A different approach to use would be to subtract a monthlength
	 * from w repeatedly while counting.)
	 */
	if (is_leap(year)) {
		/* use days_since_leapyear[] in a leap year */
		for (i = ARRAY_SIZE(days_since_leapyear) - 1;
		    i > 0 && days_since_leapyear[i] > w; --i)
			/* just loop */;
		r->monthday = w - days_since_leapyear[i] + 1;
	} else {
		for (i = ARRAY_SIZE(days_since_year) - 1;
		    i > 0 && days_since_year[i] > w; --i)
			/* just loop */;
		r->monthday = w - days_since_year[i] + 1;
	}

	r->month    = i + 1;
}

static void dns_data2str(unsigned char *data, unsigned char *str, int strlen)
{
	unsigned char count = 0;
	int len = 0;

	memset(str, 0, strlen);
	
start:
	count = *data;
	//printk("count=%d\n",count);

	len+=count;

	if (count == 0)
		goto end;

	if (len >= strlen)
		goto end;

	memcpy(str,data+1,count);
	str+=count;
	*str = '.'; str+=1;
	data+=count+1;

	goto start;

end:
	str-=1; *str = '\0';

}

static unsigned int
classify_dns_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	s64 stamp;
	struct DNS_HEADER *dns_header = (struct DNS_HEADER *)(skb_transport_header(skb) +sizeof(struct iphdr) +sizeof(struct udphdr));
	unsigned char *dns_name_start= skb_transport_header(skb) +sizeof(struct iphdr) +sizeof(struct udphdr)+sizeof(struct DNS_HEADER);
	struct ethhdr *mac_header = (struct ethhdr *)skb_mac_header(skb);	
	DNS_DATA	*data = NULL;
	int i; unsigned char *c = dns_name_start;
	int isFull = 0;

	if (dns_header->qr != 0)
		goto bypass;

	
	read_lock_bh(&dns_list_lock);
	if (record_count >= MAX_RECORD)
	{
		isFull = 1;
	}
	read_unlock_bh(&dns_list_lock);

	if (isFull)
	{	
		//printk("isFull");
	
		struct list_head *next;
		
		write_lock_bh(&dns_list_lock);

		list_for_each_prev(next, &dns_list)
		{
			data = list_entry(next, DNS_DATA, list);
			break;
		}
		
		list_del(&data->list);
		record_count -=1;
		write_unlock_bh(&dns_list_lock);
	}
	else
	{
		data = kmalloc(sizeof(DNS_DATA),GFP_ATOMIC);
		if (!data)		
			goto bypass;
	}
	

	memset(data, 0, sizeof(DNS_DATA));

	if (skb->tstamp.tv64 == 0)
				__net_timestamp((struct sk_buff *)skb);
			
	stamp = ktime_to_ns(skb->tstamp);
	stamp = div_s64(stamp, NSEC_PER_SEC);
	stamp -= 60 * sys_tz.tz_minuteswest;
	
	localtime_1(&data->qtime, stamp);
	localtime_2(&data->qtime, stamp);
	localtime_3(&data->qtime, stamp);
	memcpy(data->mac, mac_header->h_source, 6);

	#if 0
	for(i=0; i<16; i++)
		printk("0x%02x ", *(dns_name_start+i));

	printk("\n");
	#endif
	
	dns_data2str(dns_name_start, data->str, MAX_DNS_STR_LEN);	

	write_lock_bh(&dns_list_lock);
	list_add(&data->list,&dns_list);
	record_count+=1;
	write_unlock_bh(&dns_list_lock);
	
bypass:
	return XT_CONTINUE;
}

static int classify_dns_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct proc_dir_entry *proc_classify_dns = NULL;

char monthname[12][4] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

static int classify_dns_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
#if 1
	char buf[3072];
	int len = 0;
	struct list_head *next;
	//Oct/28/2011 09:03:03;DNSQUERY;00:26:5A:15:6D:AA;eclick.baidu.com;

	read_lock_bh(&dns_list_lock);
	if (list_empty(&dns_list))
		goto done;

	memset(buf,0,sizeof(buf));
	
	list_for_each(next,&dns_list)
	{
		DNS_DATA *data = list_entry(next, DNS_DATA, list);
		#if 1
		len += sprintf	(&buf[strlen(buf)], "%s/%d/%d %02d:%02d:%02d;DNSQUERY;%02X:%02X:%02X:%02X:%02X:%02X;%s;\n",
							monthname[data->qtime.month-1],
							data->qtime.monthday,
							data->qtime.year,
							data->qtime.hour,
							data->qtime.minute,
							data->qtime.second,
							data->mac[0],data->mac[1],data->mac[2],data->mac[3],data->mac[4],data->mac[5],
							data->str);
		#else
		printk("%s/%d/%d %02d:%02d:%02d;DNSQUERY;%02X:%02X:%02X:%02X:%02X:%02X;%s;\n",
				monthname[data->qtime.month-1],
				data->qtime.monthday,
				data->qtime.year,
				data->qtime.hour,
				data->qtime.minute,
				data->qtime.second,
				data->mac[0],data->mac[1],data->mac[2],data->mac[3],data->mac[4],data->mac[5],
				"data");
		#endif
	}
	
	len=sprintf(page,"%s",buf);
	
done:
	read_unlock_bh(&dns_list_lock);
	
	if (len <= off+count) *eof = 1;
	*start = page + off;
	len -= off;
	if (len>count) len = count;
	if (len<0) len = 0;
	return len;
#else
	int len = 0;

	printk("off = %d, count = %d\n", off, count);

	len = sprintf(page, "%d\n", 12345);
	if (len <= off+count) *eof = 1;
	*start = page + off;
	len -= off;
	if (len>count) len = count;
	if (len<0) len = 0;
	return len;
#endif


}

static struct xt_target classify_dns_tg_reg[] __read_mostly = {
	{
		.name		= "CLASSIFY_DNS",
		.family		= NFPROTO_UNSPEC,
		.checkentry	= classify_dns_tg_check,
		.target		= classify_dns_tg,
		.targetsize	= sizeof(struct xt_classify_dns_target_info),
		.table		= "mangle",
		.hooks		= (1 << NF_INET_PRE_ROUTING),
		.me			= THIS_MODULE,
	}
};

static int __init classify_dns_tg_init(void)
{
	if (isInit == 0)
	{
		isInit = 1;
		
		proc_classify_dns=create_proc_entry("classify_dns",0,NULL);
		if (proc_classify_dns) 
		{
			proc_classify_dns->read_proc=classify_dns_read_proc;
		}	
	}

	return xt_register_targets(classify_dns_tg_reg, ARRAY_SIZE(classify_dns_tg_reg));
}

static void __exit classify_dns_tg_exit(void)
{
	xt_unregister_targets(classify_dns_tg_reg, ARRAY_SIZE(classify_dns_tg_reg));
}

module_init(classify_dns_tg_init);
module_exit(classify_dns_tg_exit);

