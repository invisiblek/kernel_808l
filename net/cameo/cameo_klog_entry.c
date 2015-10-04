#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/kfifo.h>
#include <asm/uaccess.h>
#include <net/cameo/cameo_klog_entry.h>

#define DEV_NAME "cameo_klog_entry"
#define BUF_NUMS 4

#define CAMEO_KLOG_ENTRY_DBG 0
#if CAMEO_KLOG_ENTRY_DBG
#include <linux/proc_fs.h>
#endif

MODULE_LICENSE("Dual BSD/GPL");

struct cameo_klog_entry_data_t{
	wait_queue_head_t	read_wait;
	#if CAMEO_KLOG_ENTRY_DBG
	unsigned int		enable;
	#endif
	struct kfifo		read_queue, write_queue; 
	unsigned char		buf[BUF_NUMS][KLOG_BUF_SIZ];
};

static struct cameo_klog_entry_data_t pdata;
static struct semaphore main_gate;
static int dev_count = 1; /* device count */
static int cameo_klog_entry_major = 0; /* dynamic allocation */
static struct cdev cameo_klog_entry_cdev;
static struct class *cameo_klog_entry_class = NULL;

unsigned int cameo_klog_entry_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = POLLOUT | POLLWRNORM;

	poll_wait(filp, &pdata.read_wait, wait);
	if(!kfifo_is_empty(&pdata.read_queue))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

ssize_t cameo_klog_entry_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos)
{
	//Xavier: no support now.
	return -EFAULT;
}

int cameo_klog_entry_put(const char *buf, const size_t len)
{
	int ret = 0;
	__u8 index;

	#if CAMEO_KLOG_ENTRY_DBG
	if(!pdata.enable)
		return ret;
	#endif

	if(kfifo_is_empty(&pdata.write_queue))
		return -ENOMEM;

	kfifo_out(&pdata.write_queue, &index, sizeof(__u8));
	ret = len > KLOG_BUF_SIZ ? KLOG_BUF_SIZ : len;
	memcpy(pdata.buf[index], buf, ret);
	kfifo_in(&pdata.read_queue, &index, sizeof(__u8));
	return ret;
}

ssize_t cameo_klog_entry_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	__u8 index;
	int read_cnt = 0;

	if(kfifo_is_empty(&pdata.read_queue)){
		int ret;

		if(filp->f_flags & O_NONBLOCK) //non-blocking mode
			return -EAGAIN;

		do{
			ret = wait_event_interruptible_timeout(pdata.read_wait, !kfifo_is_empty(&pdata.read_queue), 3*HZ);
			if(ret==-ERESTARTSYS)
				return -ERESTARTSYS;
		}while(ret==0);//timeout
	}

	kfifo_out(&pdata.read_queue, &index, sizeof(__u8));
	read_cnt = count > KLOG_BUF_SIZ ? KLOG_BUF_SIZ : count;
	if(copy_to_user(buf, &pdata.buf[index], read_cnt))
		return -EFAULT;

	kfifo_in(&pdata.write_queue, &index, sizeof(__u8));
	return read_cnt;
}

int cameo_klog_entry_close(struct inode *inode, struct file *filp)
{
	kfifo_reset(&pdata.read_queue);
	kfifo_reset(&pdata.write_queue);

	up(&main_gate);
	return 0;
}

int cameo_klog_entry_open(struct inode *inode, struct file *filp)
{
	__u8 i;
	if(down_trylock(&main_gate))
		return -ETXTBSY;

	for(i=0; i<BUF_NUMS; i++)
		kfifo_in(&pdata.write_queue, &i, sizeof(__u8));

	return 0;
}

struct file_operations cameo_klog_entry_fops = {
	.owner		= THIS_MODULE,
	.open		= cameo_klog_entry_open,
	.release	= cameo_klog_entry_close,
	.read		= cameo_klog_entry_read,
	.write		= cameo_klog_entry_write,
	.poll		= cameo_klog_entry_poll,
};

static char *cameo_klog_entry_devnode(struct device *dev, mode_t *mode)
{
	if (!mode)
		return NULL;
	if (dev->devt == MKDEV(cameo_klog_entry_major, 0))
		*mode = 0666;
	return NULL;
}

#if CAMEO_KLOG_ENTRY_DBG
static int proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	char *out = page;
	char rbuf[BUF_NUMS];
	char wbuf[BUF_NUMS];
	int len;
	int i, read_max, write_max;

	memset(rbuf, 0, BUF_NUMS);
	memset(wbuf, 0, BUF_NUMS);
	kfifo_out_peek(&pdata.write_queue, wbuf, BUF_NUMS);
	kfifo_out_peek(&pdata.read_queue, rbuf, BUF_NUMS);
	read_max = kfifo_len(&pdata.read_queue);
	write_max = kfifo_len(&pdata.write_queue);

	out += sprintf(out, "device major:%d buf_num:%d buf_size:%d enable:%d\n",
		cameo_klog_entry_major, BUF_NUMS, KLOG_BUF_SIZ, pdata.enable);

	out += sprintf(out, "Write Queue: ");
	for(i=0; i<write_max; i++)
		out += sprintf(out, "%02x ", wbuf[i]&0xff);
	out += sprintf(out, "\n");

	out += sprintf(out, "Read  Queue: ");
	for(i=0; i<read_max; i++)
		out += sprintf(out, "%02x ", rbuf[i]&0xff);
	out += sprintf(out, "\n");

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

static int proc_write(struct file *file, const __user char *buf, unsigned long len, void *data)
{
	int ret;
	char str_buf[8];
	int val = 0;

	if(len > 8)
		return -EINVAL;

	if(copy_from_user(str_buf, buf, len))
		return -EFAULT;

	str_buf[len] = '\0';

	ret = sscanf(str_buf, "%d", (int*)&val);
	if(ret != 1 || val < 0 )
		return len;

	pdata.enable = val;

	return len;
}
#endif

static int cameo_klog_entry_init(void)
{
	dev_t dev = MKDEV(cameo_klog_entry_major, 0);
	int cdev_err = 0;
	int alloc_ret = 0;
	int wkfifo_ret = 0;
	int rkfifo_ret = 0;
	#if CAMEO_KLOG_ENTRY_DBG
	struct proc_dir_entry *entry;

	entry = create_proc_entry("cameo_klog_entry_dbg", 0666, NULL);
	if(entry){
		entry->read_proc = proc_read;
		entry->write_proc = proc_write;
	}
	pdata.enable = 1;
	#endif

	alloc_ret = alloc_chrdev_region(&dev, 0, dev_count, DEV_NAME);
	if(alloc_ret)
		goto error;

	cameo_klog_entry_major = MAJOR(dev);

	cdev_init(&cameo_klog_entry_cdev, &cameo_klog_entry_fops);
	cameo_klog_entry_cdev.owner = THIS_MODULE;

	cdev_err = cdev_add(&cameo_klog_entry_cdev, MKDEV(cameo_klog_entry_major, 0), dev_count);
	if(cdev_err)
		goto error;

	cameo_klog_entry_class = class_create(THIS_MODULE, DEV_NAME);
	if(IS_ERR(cameo_klog_entry_class))
		goto error;

	cameo_klog_entry_class->devnode = cameo_klog_entry_devnode;
	device_create(cameo_klog_entry_class, NULL, MKDEV(cameo_klog_entry_major, 0), NULL, DEV_NAME);

	rkfifo_ret = kfifo_alloc(&pdata.read_queue, BUF_NUMS*sizeof(__u8), GFP_KERNEL);
	if(rkfifo_ret)
		goto error;

	wkfifo_ret = kfifo_alloc(&pdata.write_queue, BUF_NUMS*sizeof(__u8), GFP_KERNEL);
	if(rkfifo_ret)
		goto error;

	init_waitqueue_head(&pdata.read_wait);
	sema_init(&main_gate, 1);
	return 0;

error:
	if(cdev_err==0)
		cdev_del(&cameo_klog_entry_cdev);

	if(alloc_ret==0)
		unregister_chrdev_region(MKDEV(cameo_klog_entry_major, 0), dev_count);
	
	if(!IS_ERR(cameo_klog_entry_class))
		class_destroy(cameo_klog_entry_class);

	if(rkfifo_ret==0)
		kfifo_free(&pdata.read_queue);

	if(wkfifo_ret==0)
		kfifo_free(&pdata.write_queue);

	return -1;
}

static void cameo_klog_entry_exit(void)
{
	#if CAMEO_KLOG_ENTRY_DBG
	remove_proc_entry("cameo_klog_entry_dbg", NULL);
	#endif
	
	kfifo_free(&pdata.read_queue);
	kfifo_free(&pdata.write_queue);
	device_destroy(cameo_klog_entry_class, MKDEV(cameo_klog_entry_major, 0));
	class_destroy(cameo_klog_entry_class);
	cdev_del(&cameo_klog_entry_cdev);
	unregister_chrdev_region(MKDEV(cameo_klog_entry_major, 0), dev_count);
}

module_init(cameo_klog_entry_init);
module_exit(cameo_klog_entry_exit);
