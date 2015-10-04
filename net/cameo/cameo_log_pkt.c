#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <net/cameo/cameo_log_pkt.h>
#include <linux/netfilter.h>

#define LOG_PKT_DBG 0

static int log_pkt_enable;
static int proc_write(struct file *file, const __user char *buf, unsigned long len, void *data)
{
	int ret;
	char str_buf[8];
	int val = 0;

	if(len > 8){
		#if LOG_PKT_DBG
		printk("Usage: echo NF_INET_PRE_ROUTING 1 > /proc/log_pkt \n");
		#endif
		return -EINVAL;
	}

	if(copy_from_user(str_buf, buf, len)){
		#if LOG_PKT_DBG
		printk("copy_from_user failed\n");
		#endif
		return -EFAULT;
	}

	str_buf[len] = '\0';

	ret = sscanf(str_buf, "%d", (int*)&val);
	if(ret != 1 || val < 0 ){
		#if LOG_PKT_DBG
		printk("Usage: echo NF_INET_PRE_ROUTING 1 > /proc/log_pkt \n");
		#endif
		return len;
	}

	#if LOG_PKT_DBG
	printk("enable:%d\n", val);
	#endif
	log_pkt_enable = val;

	#if LOG_PKT_DBG
	printk("Error: Unkown command.\n");
	#endif
	return len;
}

static int proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	char *out = page;
	int len = 0;

	out += sprintf(out, "%d\n", log_pkt_enable);

	len = out - page;
	len -= off;
	if (len < count) {
		*eof = 1;
		if (len <= 0)
			return 0;
	} else
		len = count;

	*start = page + off;
	return len;
}

inline int cameo_log_pkt_enable(const struct sk_buff *skb)
{
	return (skb==NULL || skb->aclmatchtag & (1 << CAMEOMARK_LOGGED)) ? 0 : log_pkt_enable;
}
EXPORT_SYMBOL(cameo_log_pkt_enable);

static int __init log_pkt_init(void)
{
	struct proc_dir_entry *entry;

	entry = create_proc_entry("cameo_log_pkt", 0666, NULL);
	if(entry==NULL)
		return -ENOMEM;

	entry->write_proc = proc_write;
	entry->read_proc = proc_read;
	log_pkt_enable = 0;
	return 0;
}

static void __exit log_pkt_exit(void)
{
	remove_proc_entry("cameo_log_pkt", NULL);
	log_pkt_enable = 0;
}

module_init(log_pkt_init);
module_exit(log_pkt_exit);

MODULE_LICENSE("GPL");
