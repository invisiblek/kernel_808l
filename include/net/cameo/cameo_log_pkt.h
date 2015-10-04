#ifndef _CAMEO_LOG_PKT_H
#define _CAMEO_LOG_PKT_H

#include <linux/netfilter.h>

#define CAMEOMARK_LOGGED 19

int cameo_log_pkt_enable(const struct sk_buff *skb);

#endif
