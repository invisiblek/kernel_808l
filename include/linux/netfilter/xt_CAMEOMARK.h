#ifndef _XT_CAMEOMARK_H_target
#define _XT_CAMEOMARK_H_target

#include <linux/types.h>

typedef enum
{
	ACLMARK_WEBLOGONLY = 1,
	ACLMARK_WEBFILTER_LOG,
	ACLMARK_WEBFILTER,
	ACLMARK_OTHER,

	ACLMARK_BLOCKALL = 31, //drop
	ACLMARK_PORTFILTER = 31, //drop
}ACLMark_t;

#define CMARK(offset) (1<<offset)
#define ACL_MARKS (CMARK(ACLMARK_WEBLOGONLY) | CMARK(ACLMARK_WEBFILTER_LOG) | CMARK(ACLMARK_WEBFILTER) | CMARK(ACLMARK_BLOCKALL) | CMARK(ACLMARK_PORTFILTER))

typedef enum
{
	type_time = 0,
	type_acl,
	type_acl_other_machines,
}type;

struct xt_cameomark_target_info {
	unsigned int	offset;
	unsigned short	type;
};

#endif /*_XT_CAMEOMARK_H_target */
