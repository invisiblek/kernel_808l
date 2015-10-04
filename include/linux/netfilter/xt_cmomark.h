#ifndef _XT_CAMEOMARK_H
#define _XT_CAMEOMARK_H

#include <linux/types.h>

typedef enum
{
	type_time = 0,
	type_acl,
	type_acl_val,
	type_acl_or
}type;

struct xt_cameomark_info {
	unsigned int	offset;
	unsigned short	type;
};

#endif /*_XT_CAMEOMARK_H*/
