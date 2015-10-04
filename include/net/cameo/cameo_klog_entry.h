#ifndef _CAMEO_KLOG_ENTRY_H
#define _CAMEO_KLOG_ENTRY_H

#define KLOG_BUF_SIZ 256
int cameo_klog_entry_put(const char *buf, const size_t len);

#endif
