#ifndef  CAMEO_CT_TYPES_H
#define CAMEO_CT_TYPES_H

#ifdef __linux__
#ifdef __KERNEL__
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
#include <linux/config.h>
#endif
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/string.h>
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

#if defined(CONFIG_CAMEO_CT_NEW)

enum cameo_state_enum {
	/* TCP */
	enNO,	/* TCP_CONNTRACK_NONE */
	enSS,	/* TCP_CONNTRACK_SYN_SENT */
	enSR,	/* TCP_CONNTRACK_SYN_RECV */
	enES,	/* TCP_CONNTRACK_ESTABLISHED */
	enFW,	/* TCP_CONNTRACK_FIN_WAIT */
	enCW,	/* TCP_CONNTRACK_CLOSE_WAIT */
	enLA,	/* TCP_CONNTRACK_LAST_ACK */
	enTW,	/* TCP_CONNTRACK_TIME_WAIT */
	enCL,	/* TCP_CONNTRACK_CLOSE */
	enLI,	/* TCP_CONNTRACK_LISTEN */
	/* UDP */
	enUR,	/* UDP_UNREPLY */
	enAS	/* UDP_ASSURED */
};

struct cameo_state_list {
	enum cameo_state_enum state;
	struct list_head *state_list;
};

extern struct cameo_state_list Cameo_State_List[];

#endif /* #if defined(CONFIG_CAME_CT_NEW) */

#endif /* #ifndef CAMEO_CT_TYPES_H */
