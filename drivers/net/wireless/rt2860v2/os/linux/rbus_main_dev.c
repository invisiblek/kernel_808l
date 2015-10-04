/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

    Module Name:
    rbus_main_dev.c

    Abstract:
    Create and register network interface for RBUS based chipsets in linux platform.

    Revision History:
    Who         When            What
    --------    ----------      ----------------------------------------------
*/
#define RTMP_MODULE_OS

#include "rt_config.h"


static struct net_device *rt2880_dev = NULL;


VOID __exit rt2880_module_exit(VOID);
int __init rt2880_module_init(VOID);

#define RalinkRT7620_PROC_DIR_NAME "ralink"
#define RalinkRT7620_PROC_VERSION "version"
#define RalinkRT7620_PROC_VERSION_DATE "date"
static struct proc_dir_entry *ralink_proc_directory;
static struct proc_dir_entry *ralink_proc_version;
static struct proc_dir_entry *ralink_proc_version_date;

static int readVersion(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len;
	len = sprintf(page, "%s\n", AP_DRIVER_VERSION);
	
	return len;
}
static int readVersionDate(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len;
	len = sprintf(page, "%s\n", AP_DRIVER_VERSION_DATE);
	
	return len;
}

int RalinkRT7620_proc_init(void)
{
	ralink_proc_directory = proc_mkdir(RalinkRT7620_PROC_DIR_NAME,NULL);

	if(ralink_proc_directory){
		if ((ralink_proc_version = create_proc_entry(RalinkRT7620_PROC_VERSION, 0, ralink_proc_directory))){
			ralink_proc_version->read_proc = (read_proc_t*)&readVersion;
		}else{
			return -ENOMEM;
		}
		if ((ralink_proc_version_date = create_proc_entry(RalinkRT7620_PROC_VERSION_DATE, 0, ralink_proc_directory))){
			ralink_proc_version_date->read_proc = (read_proc_t*)&readVersionDate;
		}else{
			return -ENOMEM;		
		}

	}

	return 0;
}

int RalinkRT7620_proc_cleanup(void)
{

	if(ralink_proc_directory)
	{
		if(ralink_proc_version){
			remove_proc_entry(RalinkRT7620_PROC_VERSION,ralink_proc_directory);
			ralink_proc_version =NULL;
		}
		if(ralink_proc_version_date){
			remove_proc_entry(RalinkRT7620_PROC_VERSION_DATE,ralink_proc_directory);
			ralink_proc_version_date = NULL;		
		}
		remove_proc_entry(RalinkRT7620_PROC_DIR_NAME, NULL);
		ralink_proc_directory = NULL;
	}

	return 0;
}
module_init(rt2880_module_init);
module_exit(rt2880_module_exit);

#if defined(CONFIG_RA_CLASSIFIER)&&(!defined(CONFIG_RA_CLASSIFIER_MODULE)) 	 
extern int (*ra_classifier_init_func) (void) ; 	 
extern void (*ra_classifier_release_func) (void) ; 	 
extern struct proc_dir_entry *proc_ptr, *proc_ralink_wl_video;	 
#endif

int rt2880_module_init(VOID)
{
	struct  net_device		*net_dev;
	ULONG				csr_addr;
	INT					rv;
	PVOID				*handle = NULL;
	RTMP_ADAPTER		*pAd;
	unsigned int			dev_irq;
	RTMP_OS_NETDEV_OP_HOOK	netDevHook;
	
	RalinkRT7620_proc_init();
	DBGPRINT(RT_DEBUG_TRACE, ("===> rt2880_probe\n"));	


/*RtmpRaBusInit============================================ */
	/* map physical address to virtual address for accessing register */
	csr_addr = (unsigned long)RTMP_MAC_CSR_ADDR;
	dev_irq = RTMP_MAC_IRQ_NUM;
	

/*RtmpDevInit============================================== */
	/* Allocate RTMP_ADAPTER adapter structure */
/*	handle = kmalloc(sizeof(struct os_cookie) , GFP_KERNEL); */
	os_alloc_mem(NULL, (UCHAR **)&handle, sizeof(struct os_cookie));
	if (!handle)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("Allocate memory for os_cookie failed!\n"));
		goto err_out;
	}
	NdisZeroMemory(handle, sizeof(struct os_cookie));

#ifdef OS_ABL_FUNC_SUPPORT
	/* get DRIVER operations */
	RTMP_DRV_OPS_FUNCTION(pRtmpDrvOps, NULL, NULL, NULL);
#endif /* OS_ABL_FUNC_SUPPORT */

	rv = RTMPAllocAdapterBlock(handle, (VOID **)&pAd);
	if (rv != NDIS_STATUS_SUCCESS)
	{
		DBGPRINT(RT_DEBUG_ERROR, (" RTMPAllocAdapterBlock !=  NDIS_STATUS_SUCCESS\n"));
/*		kfree(handle); */
		os_free_mem(NULL, handle);
		
		goto err_out;
	}
	/* Here are the RTMP_ADAPTER structure with rbus-bus specific parameters. */
	pAd->CSRBaseAddress = (PUCHAR)csr_addr;

	RtmpRaDevCtrlInit(pAd, RTMP_DEV_INF_RBUS);


/*NetDevInit============================================== */
	net_dev = RtmpPhyNetDevInit(pAd, &netDevHook);
	if (net_dev == NULL)
		goto err_out_free_radev;

	/* Here are the net_device structure with pci-bus specific parameters. */
	net_dev->irq = dev_irq;			/* Interrupt IRQ number */
	net_dev->base_addr = csr_addr;		/* Save CSR virtual address and irq to device structure */
	((POS_COOKIE)handle)->pci_dev = net_dev;

#ifdef CONFIG_STA_SUPPORT
    pAd->StaCfg.OriDevType = net_dev->type;
#endif /* CONFIG_STA_SUPPORT */


	
#ifdef RT_CFG80211_SUPPORT
	/*
		In 2.6.32, cfg80211 register must be before register_netdevice();
		We can not put the register in rt28xx_open();
		Or you will suffer NULL pointer in list_add of
		cfg80211_netdev_notifier_call().
	*/
	CFG80211_Register(pAd, pAd->pCfgDev, pNetDev);
#endif /* RT_CFG80211_SUPPORT */

/*All done, it's time to register the net device to kernel. */
	/* Register this device */
	rv = RtmpOSNetDevAttach(pAd->OpMode, net_dev, &netDevHook);
	if (rv)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("failed to call RtmpOSNetDevAttach(), rv=%d!\n", rv));
		goto err_out_free_netdev;
	}

	/* due to we didn't have any hook point when do module remove, we use this static as our hook point. */
	rt2880_dev = net_dev;
	
	wl_proc_init();

	DBGPRINT(RT_DEBUG_TRACE, ("%s: at CSR addr 0x%lx, IRQ %ld. \n", net_dev->name, (ULONG)csr_addr, net_dev->irq));

	DBGPRINT(RT_DEBUG_TRACE, ("<=== rt2880_probe\n"));

#if defined(CONFIG_RA_CLASSIFIER)&&(!defined(CONFIG_RA_CLASSIFIER_MODULE)) 	 
    proc_ptr = proc_ralink_wl_video; 	 
    if(ra_classifier_init_func!=NULL) 	 
	    ra_classifier_init_func(); 	 
#endif

	return 0;

err_out_free_netdev:
	RtmpOSNetDevFree(net_dev);

err_out_free_radev:
	/* free RTMP_ADAPTER strcuture and os_cookie*/
	RTMPFreeAdapter(pAd);
		
err_out:
	return -ENODEV;
	
}


VOID rt2880_module_exit(VOID)
{
	struct net_device   *net_dev = rt2880_dev;
	RTMP_ADAPTER *pAd;
	RalinkRT7620_proc_cleanup();

	if (net_dev == NULL)
		return;
	
	/* pAd = net_dev->priv; */
	GET_PAD_FROM_NET_DEV(pAd, net_dev);

	if (pAd != NULL)
	{
		RtmpPhyNetDevExit(pAd, net_dev);
		RtmpRaDevCtrlExit(pAd);
	}
	else
	{
		RtmpOSNetDevDetach(net_dev);
	}
	
	/* Free the root net_device. */
	RtmpOSNetDevFree(net_dev);
	
#if defined(CONFIG_RA_CLASSIFIER)&&(!defined(CONFIG_RA_CLASSIFIER_MODULE))
    proc_ptr = proc_ralink_wl_video; 	 
    if(ra_classifier_release_func!=NULL) 	 
	    ra_classifier_release_func(); 	 
#endif

	wl_proc_exit();
}

