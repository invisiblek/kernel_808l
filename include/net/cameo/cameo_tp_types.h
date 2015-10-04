#ifndef  CAMEO_TP_TYPES_H
#define CAMEO_TP_TYPES_H

#ifdef __linux__
#ifdef __KERNEL__
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
#include <linux/config.h>
#endif
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#endif /*__KERNEL__*/
#endif /*__linux__*/

#ifndef NULL
#define NULL	0
#endif
#ifndef TRUE
#define TRUE	1
#endif
#ifndef FALSE
#define FALSE	0
#endif

#ifndef SUCCESS
#define SUCCESS		0
#endif
#ifndef FAILED
#define FAILED		-1
#endif

/* CONFIG_CAMEO_TP_NEW */

enum cameo_tp_dir_enum {
	enOR,	/* IP_CT_DIR_ORIGINAL */
	enRE,	/* IP_CT_DIR_REPLY */
};

#endif /* #ifndef CAMEO_TP_TYPES_H */
