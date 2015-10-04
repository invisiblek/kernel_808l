/*
  File: sshinetmapped.c

  Description:
        IP mapped related functions and definitions.

  Copyright:
        Copyright (c) 2002, 2003, 2004, 2005 SFNT Finland Oy.
        All rights reserved
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetMapped"

/* Check if ipv6 address is just an ipv4 address mapped into ipv6 mask. */

Boolean ssh_inet_addr_is_ip6_mapped_ip4(SshIpAddr ip_addr)
{
  if (! SSH_IP_IS6(ip_addr))
    return FALSE;
  SSH_ASSERT(ip_addr->mask_len == 128);
  return ((ip_addr->addr_data[0] == 0x0) &&
          (ip_addr->addr_data[1] == 0x0) &&
          (ip_addr->addr_data[2] == 0x0) &&
          (ip_addr->addr_data[3] == 0x0) &&
          (ip_addr->addr_data[4] == 0x0) &&
          (ip_addr->addr_data[5] == 0x0) &&
          (ip_addr->addr_data[6] == 0x0) &&
          (ip_addr->addr_data[7] == 0x0) &&
          (ip_addr->addr_data[8] == 0x0) &&
          (ip_addr->addr_data[9] == 0x0) &&
          (ip_addr->addr_data[10] == 0xff) &&
          (ip_addr->addr_data[11] == 0xff));
}

/* Convert if ipv6 mapped ipv4 address to an ipv4 address, if possible. */

Boolean ssh_inet_convert_ip6_mapped_ip4_to_ip4(SshIpAddr ip_addr)
{
  if (! ssh_inet_addr_is_ip6_mapped_ip4(ip_addr))
    return FALSE;
  memcpy(ip_addr->addr_data, &(ip_addr->addr_data[12]), 4);
  memset(&(ip_addr->addr_data[4]), 0, 12);
  ip_addr->mask_len = 32;
  ip_addr->type = SSH_IP_TYPE_IPV4;
  return TRUE;
}
