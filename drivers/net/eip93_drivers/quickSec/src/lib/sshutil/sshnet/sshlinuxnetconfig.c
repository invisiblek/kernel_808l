/*
  File: sshlinuxnetconfig.c

  Copyright:
        Copyright (c) 2007 - 2008 SFNT Finland Oy.
        All rights reserved

  Description:
        Linux implementation of the sshnetconfig.h API. This implementation
	uses the Linux netlink socket and ioctl interfaces. 
*/


#include "sshincludes.h"
#include "sshinet.h"
#include "sshnetconfig.h"

#ifdef SSHDIST_PLATFORM_LINUX
#ifdef __linux__

#include "sshlinuxnetconfig_i.h"
#include <linux/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

/* These types need to be defined locally 
   due to a bug in linux kernel header files. */
#define u64 __u64
#define u32 __u32
#define u16 __u16
#define u8 __u8
#include <linux/ethtool.h>
#undef u64
#undef u32
#undef u16
#undef u8

/* Some linux variants do not define NLMSG_HDRLEN */
#ifndef NLMSG_HDRLEN
#define NLMSG_HDRLEN ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#endif /* NLMSG_HDRLEN */

#ifndef NETLINK_ROUTE
#error "sshlinuxnetconfig.c requires NETLINK_ROUTE"
#endif /* !NETLINK_ROUTE */

#define SSH_DEBUG_MODULE "SshLinuxNetconfig"

#ifdef IFF_LOWER_UP

#define SSH_NETCONFIG_LINUX_LINK_FLAGS_MASK \
(SSH_NETCONFIG_LINK_UP |  SSH_NETCONFIG_LINK_LOOPBACK | \
SSH_NETCONFIG_LINK_BROADCAST | SSH_NETCONFIG_LINK_POINTOPOINT | \
SSH_NETCONFIG_LINK_LOWER_DOWN)

#else /* IFF_LOWER_UP */

#define SSH_NETCONFIG_LINUX_LINK_FLAGS_MASK \
(SSH_NETCONFIG_LINK_UP |  SSH_NETCONFIG_LINK_LOOPBACK | \
SSH_NETCONFIG_LINK_BROADCAST | SSH_NETCONFIG_LINK_POINTOPOINT)

#endif /* IFF_LOWER_UP */


/************************** Netlink message handling ***********************/

typedef struct SshLinuxNetlinkRequestRec
{
  struct nlmsghdr nh;    /* Netlink message header */
  union
  {
    struct ifaddrmsg ifa; /* RTM_NEWADDR / RTM_DELADDR payload */
    struct ifinfomsg ifi; /* RTM_GETLINK / RTM_SETLINK payload */
    struct rtmsg rtm;     /* RTM_NEWROUTE / RTM_DELROUTE payload */
    struct rtgenmsg rtgen;   /* RTM_GETROUTE payload */
    char buf[128];         /* Some pad for netlink attributes. */
  } u;
} SshLinuxNetlinkRequestStruct, *SshLinuxNetlinkRequest;

/* This type of callback is called for each netlink response. This function
   is always called synchronously. */
typedef void (*SshLinuxNetlinkMsgParseCallback)(int nl_error, 
						struct nlmsghdr *nh, 
						void *context);

/* Global sequence number for netlink messages. */
static int sequence;

/* Conversion between SSH_NETCONFIG_LINK_* and IFF_* flags. */

static SshUInt32 netconfig_iff_to_link_flags(unsigned iff_flags)
{
  SshUInt32 flags = 0;

  if (iff_flags & IFF_UP)
    flags |= SSH_NETCONFIG_LINK_UP;
  if (iff_flags & IFF_LOOPBACK)
    flags |= SSH_NETCONFIG_LINK_LOOPBACK;
  if (iff_flags & IFF_BROADCAST)
    flags |= SSH_NETCONFIG_LINK_BROADCAST;
  if (iff_flags & IFF_POINTOPOINT)
    flags |= SSH_NETCONFIG_LINK_POINTOPOINT;
#ifdef IFF_LOWER_UP
  if ((iff_flags & IFF_LOWER_UP) == 0)
    flags |= SSH_NETCONFIG_LINK_LOWER_DOWN;
#endif /* IFF_LOWER_UP */

  return flags;
}

static unsigned netconfig_link_to_iff_flags(SshUInt32 flags)
{
  unsigned iff_flags = 0;

  if (flags & SSH_NETCONFIG_LINK_UP)
    iff_flags |= IFF_UP;
  if (flags & SSH_NETCONFIG_LINK_LOOPBACK)
    iff_flags |= IFF_LOOPBACK;
  if (flags & SSH_NETCONFIG_LINK_BROADCAST)
    iff_flags |= IFF_BROADCAST;
  if (flags & SSH_NETCONFIG_LINK_POINTOPOINT)
    iff_flags |= IFF_POINTOPOINT;
#ifdef IFF_LOWER_UP
  if (flags & SSH_NETCONFIG_LINK_LOWER_DOWN)
    iff_flags &= ~IFF_LOWER_UP;
#endif /* IFF_LOWER_UP */

  return iff_flags;
}

/* Conversion between SSH_NETCONFIG_ADDR_* and IFA_F_* flags. */

static SshUInt32 netconfig_ifa_to_addr_flags(unsigned ifa_flags)
{
  SshUInt32 flags = 0;

  if (ifa_flags & IFA_F_TENTATIVE)
    flags |= SSH_NETCONFIG_ADDR_TENTATIVE;

  return flags;
}

static unsigned netconfig_addr_to_ifa_flags(SshUInt32 flags)
{
  unsigned ifa_flags = 0;
  
  if (flags & SSH_NETCONFIG_ADDR_TENTATIVE)
    ifa_flags |= IFA_F_TENTATIVE;

  return ifa_flags;
}

/* Conversion from standard errno values to SSH_NETCONFIG_ERROR_* */

static SshNetconfigError netconfig_errno_to_error(int error)
{
  if (error == 0)
    return SSH_NETCONFIG_ERROR_OK;
  
  switch (error)
    {
    case EINVAL:
      return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
    case ENOMEM:
      return SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
    case ENOENT:
    case ESRCH:
    case ENXIO:
    case ENODEV:
      return SSH_NETCONFIG_ERROR_NON_EXISTENT;
    default:
      return SSH_NETCONFIG_ERROR_UNDEFINED;
    }
}

/********************* Sending requests and parsing responses ***************/

static Boolean
linux_netlink_do_operation(SshLinuxNetlinkRequest req,
			   SshLinuxNetlinkMsgParseCallback parse_cb, 
			   void *context)
{
  int sd;
  struct sockaddr_nl nladdr;
  unsigned char response_buf[4096];  
  struct nlmsghdr *nh;
  struct iovec iov;
  struct msghdr msg;
  struct nlmsgerr *errmsg;
  int res, offset;
  int nl_error;
  
  /* Open a netlink/route socket. This should not require root
     permissions or special capabilities. */
  sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sd < 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("failed to open PF_NETLINK/NETLINK_ROUTE socket"));
      goto fail;
    }

  /* Fill netlink destination address. */
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pid = 0; /* Message is directed to kernel */
  
  /* Send the request. This request should not require
     root permissions or any special capabilities. */
  if (sendto(sd, &req->nh, req->nh.nlmsg_len, 0,
             (struct sockaddr *) &nladdr,
	     (ssh_socklen_t) sizeof(nladdr)) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("sendto() of RTM_GETLINK request failed."));
      goto fail;
    }

  nh = NULL; 
  do {
    /* Read a response from the kernel, for some very odd reason
       recvmsg() seemed to work better in this instance during
       testing.. */
    msg.msg_name = (struct sockaddr *) &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iov.iov_base = response_buf;
    iov.iov_len = sizeof(response_buf);
    
    res = recvmsg(sd, &msg, 0);
    if (res <= 0)
      {
        SSH_DEBUG(SSH_D_FAIL, ("recvmsg() failed"));
        goto fail;
      }
    
    /* This response contains several netlink messages
       concatenated. */
    nh = NULL;
    for (offset = 0; offset < res; offset += nh->nlmsg_len)
      {
        nh = (struct nlmsghdr *)((unsigned char *) response_buf + offset);
	nl_error = 0;

        if (nh->nlmsg_len == 0)
          {
            SSH_DEBUG(SSH_D_ERROR,
                      ("Received netlink message of length 0.."));
            goto fail;
          }
	
	if (nh->nlmsg_seq != req->nh.nlmsg_seq)
	  {
	    SSH_DEBUG(SSH_D_LOWOK,
		      ("Ignoring response with unexpected sequence %d "
		       "(expected %d).", nh->nlmsg_seq, req->nh.nlmsg_seq));
	    continue;
	  }

        if (nh->nlmsg_type == NLMSG_ERROR)
          {
	    /* Acknowledgements are sent with errorcode 0. */
            errmsg = NLMSG_DATA(nh);
	    nl_error = errmsg->error;
	    if (nl_error)
	      {
		SSH_DEBUG(SSH_D_FAIL,
			  ("PF_NETLINK/NETLINK_ROUTE request "
			   "returned error %d", errmsg->error));
	      }
	  }
	
	(*parse_cb)(nl_error, nh, context);

	if (nh->nlmsg_type == NLMSG_DONE)
	  goto out;
      }
  } while((nh != NULL) && (nh->nlmsg_flags & NLM_F_MULTI) != 0);

 out:  
  close(sd);
  return TRUE;

 fail:
  if (sd)
    close(sd);
  return FALSE;
}

/***************************** RTM_GETLINK *********************************/

static Boolean
linux_netlink_get_link(SshLinuxNetlinkMsgParseCallback parse_cb, void *context)
{
  Boolean ret = FALSE;
  SshLinuxNetlinkRequestStruct req;

  /* Build a dump request for all interfaces */
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.u.ifi));
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
  req.nh.nlmsg_type = RTM_GETLINK;
  req.nh.nlmsg_seq = sequence++;
  req.nh.nlmsg_pid = getpid(); /* Message originates from user process. */ 
  
  req.u.ifi.ifi_family = AF_UNSPEC;
  
  /* Send request, parse response and call callback for each response. */
  ret = linux_netlink_do_operation(&req, parse_cb, context);      

  return ret;
}


/***************************** RTM_SETLINK *********************************/

/* sshlinuxnetconfig.c is compiled using the standars headers in /usr/include/,
   and those standard headers and the kernel headers might be out of sync. 
   The kernel headers are checked for RTM_SETLINK during configure, and the
   standard headers are checked here.  */






#undef LINUX_HAS_RTM_SETLINK

#ifdef LINUX_HAS_RTM_SETLINK

/* If RTM_SETLINK is not defined in standard headers, but we know that the 
   kernel supports it, then we simply define RTM_SETLINK locally here. */
#ifndef RTM_SETLINK
#define RTM_SETLINK (RTM_BASE+3)
#endif /* RTM_SETLINK */

static Boolean
linux_netlink_set_link(SshUInt32 ifnum, SshUInt32 mtu, SshUInt32 flags,
		       SshUInt32 mask,
		       SshLinuxNetlinkMsgParseCallback parse_cb, void *context)
{
  Boolean ret = FALSE;
  SshLinuxNetlinkRequestStruct req;
  struct rtattr *rta;
  size_t data_len;

  /* Build a dump request for all interfaces */
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.u.ifi));
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.nh.nlmsg_type = RTM_SETLINK;
  req.nh.nlmsg_seq = sequence++;
  req.nh.nlmsg_pid = getpid(); /* Message originates from user process. */ 
  
  req.u.ifi.ifi_family = AF_UNSPEC;
  req.u.ifi.ifi_index = SSH_LINUX_NETCONFIG_IFNUM_TO_IF_INDEX(ifnum);

  req.u.ifi.ifi_change = netconfig_link_to_iff_flags(mask);
  req.u.ifi.ifi_flags = netconfig_link_to_iff_flags(flags);

  /* Add mtu, IFLA_MTU. */
  if (mtu)
    {
      data_len = 4;
      if (NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len)) 
	  > sizeof(req))
	goto fail;
      
      rta = (struct rtattr *) ((char *) &req.nh 
			       + NLMSG_ALIGN(req.nh.nlmsg_len));
      rta->rta_type = IFLA_MTU;
      rta->rta_len = RTA_LENGTH(data_len);
      memcpy(RTA_DATA(rta), &mtu, data_len);
      
      req.nh.nlmsg_len = (NLMSG_ALIGN(req.nh.nlmsg_len) 
			  + RTA_ALIGN(rta->rta_len));      
    }

  /* Send request, parse response and call callback for each response. */
  ret = linux_netlink_do_operation(&req, parse_cb, context);      

 fail:

  return ret;
}

#else /* LINUX_HAS_RTM_SETLINK */

/* If kernel does not support RTM_SETLINK, then fallback to using ioctl for
   setting link flags and link mtu. */

static Boolean 
linux_netlink_set_link_ioctl(SshUInt32 ifnum, SshUInt32 mtu, SshUInt32 flags,
			     SshUInt32 mask)
{
  int sd = 0;
  struct ifreq ifr;

  sd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sd < 0)
    goto fail;

  /* Resolve ifname. */
  memset(&ifr, 0, sizeof(ifr));
  if (ssh_netconfig_resolve_ifnum(ifnum, ifr.ifr_name, sizeof(ifr.ifr_name))
      != SSH_NETCONFIG_ERROR_OK)
    goto fail;
  
  /* Fetch link flags. */
  if (ioctl(sd, SIOCGIFFLAGS, &ifr))
    goto fail;

  /* Calculate new link flags. */
  ifr.ifr_flags &= ~(netconfig_link_to_iff_flags(mask));
  ifr.ifr_flags |= (netconfig_link_to_iff_flags(flags) 
		    & netconfig_link_to_iff_flags(mask));

  /* Set link flags. */
  if (ioctl(sd, SIOCSIFFLAGS, &ifr))
    goto fail;

  /* Set link mtu. */
  if (mtu)
    {
      ifr.ifr_mtu = mtu;
      if (ioctl(sd, SIOCSIFMTU, &ifr))
	goto fail;
    }

  close(sd);
  return TRUE;

 fail:
  if (sd)
    close(sd);
  return FALSE;
}

#endif /* LINUX_HAS_RTM_SETLINK */


/****************************** RTM_GETADDR *********************************/

static Boolean
linux_netlink_get_addr(SshLinuxNetlinkMsgParseCallback parse_cb, void *context)
{
  Boolean ret = FALSE;
  SshLinuxNetlinkRequestStruct req;
  
  /* Build a dump request for all addresses */
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.u.rtgen));
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
  req.nh.nlmsg_type = RTM_GETADDR;
  req.nh.nlmsg_seq = sequence++;
  req.nh.nlmsg_pid = getpid(); /* Message originates from user process. */ 
  
  req.u.rtgen.rtgen_family = AF_UNSPEC;
  
  /* Send request, parse response and call callback for each response. */
  ret = linux_netlink_do_operation(&req, parse_cb, context);      

  return ret;
}


/************************* RTM_NEWADDR / RTM_DELADDR ***********************/

static Boolean
linux_netlink_modify_addr(Boolean add, 
			  SshIpAddr address,
			  SshIpAddr broadcast,
			  SshUInt32 ifnum,
			  SshUInt32 flags,
			  SshLinuxNetlinkMsgParseCallback parse_cb, 
			  void *context)
{
  Boolean ret = FALSE;
  SshLinuxNetlinkRequestStruct req;
  struct rtattr *rta;
  size_t data_len;

  /* Build a request to add or delete an address. */
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.u.ifa));
  if (add)
    {
      req.nh.nlmsg_flags = (NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE |
			    NLM_F_ACK);
      req.nh.nlmsg_type = RTM_NEWADDR;
    }
  else
    {
      req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      req.nh.nlmsg_type = RTM_DELADDR;
    }
  req.nh.nlmsg_seq = sequence++;
  req.nh.nlmsg_pid = getpid(); /* Message originates from user process. */
  
  /* Build ifaddr header. */
  SSH_ASSERT(address != NULL);
  if (SSH_IP_IS4(address))
    req.u.ifa.ifa_family = AF_INET;
  else if (SSH_IP_IS6(address))
    {
      /* Broadcast is only valid for IPv4. */
      if (flags & SSH_NETCONFIG_ADDR_BROADCAST)
	goto fail;
      req.u.ifa.ifa_family = AF_INET6;
    }
  else
    goto fail;

  req.u.ifa.ifa_prefixlen = SSH_IP_MASK_LEN(address);
  req.u.ifa.ifa_flags = netconfig_addr_to_ifa_flags(flags);
  if (add)
    req.u.ifa.ifa_flags |= IFA_F_PERMANENT; 
  req.u.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
  req.u.ifa.ifa_index = SSH_LINUX_NETCONFIG_IFNUM_TO_IF_INDEX(ifnum);
  
  /* Add address data, IFA_LOCAL. */
  SSH_ASSERT(SSH_IP_DEFINED(address));
  data_len = SSH_IP_ADDR_LEN(address);
  if (NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len)) 
      > sizeof(req))
    goto fail;

  rta = (struct rtattr *) ((char *) &req.nh + NLMSG_ALIGN(req.nh.nlmsg_len));
  rta->rta_type = IFA_LOCAL;
  rta->rta_len = RTA_LENGTH(data_len);
  SSH_IP_ENCODE(address, RTA_DATA(rta), data_len);
  
  req.nh.nlmsg_len = (NLMSG_ALIGN(req.nh.nlmsg_len) 
		      + RTA_ALIGN(rta->rta_len));
  
  /* Add broadcast, IFA_BROADCAST */
  if (flags & SSH_NETCONFIG_ADDR_BROADCAST)
    {
      SSH_ASSERT(broadcast != NULL);
      SSH_ASSERT(SSH_IP_DEFINED(broadcast));
      data_len = SSH_IP_ADDR_LEN(broadcast);
      if (NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len)) 
	  > sizeof(req))
	goto fail;

      rta = (struct rtattr *) ((char *) &req.nh 
			       + NLMSG_ALIGN(req.nh.nlmsg_len));
      rta->rta_type = IFA_BROADCAST;
      rta->rta_len = RTA_LENGTH(data_len);
      SSH_IP_ENCODE(broadcast, RTA_DATA(rta), data_len);
      
      req.nh.nlmsg_len = (NLMSG_ALIGN(req.nh.nlmsg_len) 
			  + RTA_ALIGN(rta->rta_len));
    }
  
  /* Send request, parse response and call callback for each response. */
  ret = linux_netlink_do_operation(&req, parse_cb, context);      

 fail:
  
  return ret;
}

/****************************** RTM_GETROUTE *******************************/

static Boolean
linux_netlink_get_route(SshLinuxNetlinkMsgParseCallback parse_cb, 
			void *context)
{
  Boolean ret = FALSE;
  SshLinuxNetlinkRequestStruct req;

  /* Build a request for all routes */
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.u.rtgen));
  req.nh.nlmsg_type = RTM_GETROUTE;
  req.nh.nlmsg_flags = (NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH);
  req.nh.nlmsg_seq = sequence++;
  req.nh.nlmsg_pid = getpid(); /* Message originates from user process. */
  
  /* Build rtmsg header. */
  req.u.rtgen.rtgen_family = AF_UNSPEC;
  
  /* Send request, parse response and call callback for each response. */
  ret = linux_netlink_do_operation(&req, parse_cb, context);      

  return ret;
}

/************************ RTM_NEWROUTE / RTM_DELROUTE **********************/

static Boolean
linux_netlink_modify_route(Boolean add, 
			   SshIpAddr prefix,
			   SshIpAddr gateway,			
			   SshUInt32 ifnum,
			   SshUInt32 metric,
			   SshLinuxNetlinkMsgParseCallback parse_cb, 
			   void *context)
{
  Boolean ret = FALSE;
  SshLinuxNetlinkRequestStruct req;
  struct rtattr *rta;
  size_t data_len;
  int if_index;

  /* Build a request to add or delete a route. */
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.u.rtm));

  if (add)
    {
      req.nh.nlmsg_flags = (NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE |
			    NLM_F_ACK);
      req.nh.nlmsg_type = RTM_NEWROUTE;
    }
  else
    {
      req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      req.nh.nlmsg_type = RTM_DELROUTE;
    }
  req.nh.nlmsg_seq = sequence++;
  req.nh.nlmsg_pid = getpid(); /* Message originates from user process. */
  
  /* Build rtmsg header. */
  if (SSH_IP_IS6(prefix))
    req.u.rtm.rtm_family = AF_INET6;
  else
    req.u.rtm.rtm_family = AF_INET;

  SSH_ASSERT(prefix != NULL);
  req.u.rtm.rtm_dst_len = SSH_IP_MASK_LEN(prefix);
  req.u.rtm.rtm_src_len = 0;
  req.u.rtm.rtm_tos = 0;
  req.u.rtm.rtm_table = RT_TABLE_MAIN;
  
  if (add)
    {
      req.u.rtm.rtm_protocol = RTPROT_STATIC;
      if (gateway)
	req.u.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
      else
	req.u.rtm.rtm_scope = RT_SCOPE_LINK;
      req.u.rtm.rtm_type = RTN_UNICAST;
    }
  else
    {
      req.u.rtm.rtm_scope = RT_SCOPE_NOWHERE;
      req.u.rtm.rtm_type = RTN_UNSPEC;
    }
  
  req.u.rtm.rtm_flags = 0;
  
  /* Add prefix, RTA_DST. */
  if (req.u.rtm.rtm_dst_len > 0)
    {
      data_len = SSH_IP_ADDR_LEN(prefix);
      if (NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len)) 
	  > sizeof(req))
	goto fail;
      
      rta = (struct rtattr *) ((char *) &req.nh 
			       + NLMSG_ALIGN(req.nh.nlmsg_len));
      rta->rta_type = RTA_DST;
      rta->rta_len = RTA_LENGTH(data_len);
      SSH_IP_ENCODE(prefix, RTA_DATA(rta), data_len);
      
      req.nh.nlmsg_len = (NLMSG_ALIGN(req.nh.nlmsg_len) 
			  + RTA_ALIGN(rta->rta_len));
    }

  /* Add gateway, RTA_GATEWAY. */
  if (gateway != NULL)
    {
      data_len = SSH_IP_ADDR_LEN(gateway);
      if (NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len)) 
	  > sizeof(req))
	goto fail;

      rta = (struct rtattr *)((char *) &req.nh 
			      + NLMSG_ALIGN(req.nh.nlmsg_len));
      rta->rta_type = RTA_GATEWAY;
      rta->rta_len = RTA_LENGTH(data_len);
      SSH_IP_ENCODE(gateway, RTA_DATA(rta), data_len);
      
      req.nh.nlmsg_len = (NLMSG_ALIGN(req.nh.nlmsg_len) 
			  + RTA_ALIGN(rta->rta_len));
    }
  
  /* Add outbound interface, RTA_OIF. */
  if (ifnum != SSH_INVALID_IFNUM)
    {
      if_index = SSH_LINUX_NETCONFIG_IFNUM_TO_IF_INDEX(ifnum);
      data_len = 4;
      if (NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len)) 
	  > sizeof(req))
	goto fail;

      rta = (struct rtattr *) ((char *) &req.nh 
			       + NLMSG_ALIGN(req.nh.nlmsg_len));
      rta->rta_type = RTA_OIF;
      rta->rta_len = RTA_LENGTH(data_len);
      memcpy(RTA_DATA(rta), &if_index, data_len);
      
      req.nh.nlmsg_len = (NLMSG_ALIGN(req.nh.nlmsg_len) 
			  + RTA_ALIGN(rta->rta_len));
    }
  
  /* Add route metric, RTA_PRIORITY. */
  if (metric > 0)
    {
      data_len = 4;
      if (NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len)) 
	  > sizeof(req))
	goto fail;

      rta = (struct rtattr *) ((char *) &req.nh 
			       + NLMSG_ALIGN(req.nh.nlmsg_len));
      rta->rta_type = RTA_PRIORITY;
      rta->rta_len = RTA_LENGTH(data_len);
      memcpy(RTA_DATA(rta), &metric, data_len);
      
      req.nh.nlmsg_len = (NLMSG_ALIGN(req.nh.nlmsg_len) 
			  + RTA_ALIGN(rta->rta_len));
    }
  
  /* Send request, parse response and call callback for each response. */
  ret = linux_netlink_do_operation(&req, parse_cb, context);      

 fail:
  
  return ret;
}


/************************* Ethtool ******************************************/

static Boolean
linux_ethtool_get(unsigned char *ifname, SshNetconfigLink link)
{
  int sd = -1;
  struct ifreq ifr;
  struct ethtool_cmd ecmd;
  struct ethtool_value edata;

  SSH_ASSERT(link != NULL);

  SSH_DEBUG(SSH_D_LOWOK, ("Getting ethtool properties for link %s", ifname));

  sd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sd < 0)
    goto fail;

  /* Fetch ethtool properties. */
  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, ifname);
  
  memset(&ecmd, 0, sizeof(ecmd));
  ecmd.cmd = ETHTOOL_GSET;
  ifr.ifr_data = (caddr_t) &ecmd;
  
  if (ioctl(sd, SIOCETHTOOL, &ifr))
    goto fail;

  SSH_DEBUG(SSH_D_LOWOK, ("speed %d", ecmd.speed));

  switch (ecmd.speed)
    {
    case 0:
      link->speed = 0;
      break;

    case SPEED_10:
      link->speed = 10000;
      break;
    case SPEED_100:
      link->speed = 100000;
      break;
    case SPEED_1000:
      link->speed = 1000000;
      break;
      
#ifdef SPEED_2500
      /* Introduced in linux-2.6.15 */
    case SPEED_2500:
      link->speed = 2500000;
      break;
#endif /* SPEED_2500 */
      
#ifdef SPEED_10000
      /* Introduced in linux-2.4.22 */
    case SPEED_10000:
      link->speed = 10000000;
      break;
#endif /* SPEED_10000 */
      
    case 0xffff:



      link->speed = 0;
      break;
      
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unknown link speed setting %d", ecmd.speed));
      link->speed = 0;
      break;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("duplex %d", ecmd.duplex));

  switch (ecmd.duplex)
    {
    case DUPLEX_HALF:
      link->properties |= SSH_NETCONFIG_LINK_PROPERTY_HALF_DUPLEX;
      break;
    case DUPLEX_FULL:
      link->properties |= SSH_NETCONFIG_LINK_PROPERTY_FULL_DUPLEX;
      break;

    case 0xff:



      break;

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unknown link duplex setting %d", ecmd.duplex));
      break;
    }
  
  /* Fetch ethtool link state. */
  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, ifname);
  
  memset(&edata, 0, sizeof(edata));
  edata.cmd = ETHTOOL_GLINK;
  ifr.ifr_data = (caddr_t) &edata;
  
  if (ioctl(sd, SIOCETHTOOL, &ifr))
    goto fail;
  
  SSH_DEBUG(SSH_D_LOWOK, ("link %sdetected", edata.data ? "" : "not "));

  /* Link detected */
  if (edata.data)
    link->flags &= ~SSH_NETCONFIG_LINK_LOWER_DOWN;

  /* No link detected */
  else
    link->flags |= SSH_NETCONFIG_LINK_LOWER_DOWN;

  close(sd);

  return TRUE;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("linux_ethtool_get failed"));
  if (sd >= 0)
    close(sd);
  return FALSE;
}

/************************* SshNetconfig API implementation ******************/

/* Parser for netlink errors (and acks). */

static void
netconfig_error_parser(int nl_error, struct nlmsghdr *nh, void *context)
{
  SshNetconfigError *error = context;
  *error = netconfig_errno_to_error(-nl_error);
}


/*********************** Getting Link State *********************************/

typedef struct SshLinuxNetconfigGetLinkRec
{
  SshNetconfigError error;
  unsigned char ifname[IFNAMSIZ];
  SshNetconfigLink link;
} SshLinuxNetconfigGetLinkStruct, *SshLinuxNetconfigGetLink;

static void
netconfig_get_link_parser(int nl_error, struct nlmsghdr *nh, 
			  void *context)
{
  SshLinuxNetconfigGetLink ctx = context;
  struct ifinfomsg *ifi;
  struct rtattr *rta;
  size_t offset;

  if (nl_error)
    {
      ctx->error = netconfig_errno_to_error(nl_error);
      return;
    }

  SSH_ASSERT(nh != NULL);

  if (nh->nlmsg_type == RTM_GETLINK || nh->nlmsg_type == RTM_NEWLINK
      || nh->nlmsg_type == RTM_DELLINK)
    {
      ifi = (struct ifinfomsg *) NLMSG_DATA(nh);
      
      if (SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(ifi->ifi_index)
	  != ctx->link->ifnum)
	{
	  if (ctx->error == SSH_NETCONFIG_ERROR_UNDEFINED)
	    ctx->error = SSH_NETCONFIG_ERROR_NON_EXISTENT;
	  return;
	}

      ctx->link->flags = netconfig_iff_to_link_flags(ifi->ifi_flags);
      ctx->error = SSH_NETCONFIG_ERROR_OK;

      rta = NULL;
      for (offset = NLMSG_ALIGN(sizeof(*ifi));
	   offset < (nh->nlmsg_len - NLMSG_HDRLEN);
	   offset += RTA_ALIGN(rta->rta_len))
	{
	  rta = (struct rtattr *) (((unsigned char *) ifi) + offset);
	  
	  if (RTA_ALIGN(rta->rta_len) == 0)
	    break;
	  
	  switch (rta->rta_type)
	    {
	    case IFLA_MTU:
	      if (RTA_PAYLOAD(rta) == 4)
		ctx->link->mtu = *((int *) RTA_DATA(rta));
	      else
		ctx->error = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
	      break;

	    case IFLA_LINK:
	      if (RTA_PAYLOAD(rta) == 4)
		{
		  ctx->link->iflink = 
		    SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(*((int *) 
							    RTA_DATA(rta)));
		  if (ctx->link->iflink == 0)
		    ctx->link->iflink = SSH_INVALID_IFNUM;
		}
	      else
		ctx->error = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
	      break;

	    case IFLA_ADDRESS:
	      if (RTA_PAYLOAD(rta) <= sizeof(ctx->link->media_addr))
		{
		  memcpy(ctx->link->media_addr, RTA_DATA(rta), 
			 RTA_PAYLOAD(rta));
		  ctx->link->addr_len = RTA_PAYLOAD(rta);
		}
	      else
		ctx->error = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
	      break;

	    case IFLA_BROADCAST:
	      if (RTA_PAYLOAD(rta) <= sizeof(ctx->link->broadcast_addr))
		{
		  memcpy(ctx->link->broadcast_addr, RTA_DATA(rta), 
			 RTA_PAYLOAD(rta));
		  ctx->link->flags |= SSH_NETCONFIG_LINK_BROADCAST;
		}
	      else
		ctx->error = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
	      break;

	    case IFLA_IFNAME:
	      if (RTA_PAYLOAD(rta) <= sizeof(ctx->ifname))
		ssh_snprintf(ctx->ifname, sizeof(ctx->ifname),
			     "%s", RTA_DATA(rta));
	      break;

	    default:
	      break;
	    }
	}
    }
}

SshNetconfigError
ssh_netconfig_get_link(SshUInt32 ifnum, SshNetconfigLink link)
{
  SshLinuxNetconfigGetLinkStruct ctx;

  if (ifnum == SSH_INVALID_IFNUM || link == NULL)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  ctx.error = SSH_NETCONFIG_ERROR_UNDEFINED;
  ctx.link = link;

  ctx.link->ifnum = ifnum;
  ctx.link->mtu = 0;
  ctx.link->iflink = ifnum;
  ctx.link->flags = 0;
  ctx.link->flags_mask = SSH_NETCONFIG_LINUX_LINK_FLAGS_MASK;
  ctx.link->properties = 0;
  ctx.link->speed = 0;
  
  if (!linux_netlink_get_link(netconfig_get_link_parser, &ctx))
    return SSH_NETCONFIG_ERROR_UNDEFINED;
  
  if (ctx.error == SSH_NETCONFIG_ERROR_OK)
    {
      if (!linux_ethtool_get(ctx.ifname, ctx.link))
	{
	  ctx.link->properties &= ~(SSH_NETCONFIG_LINK_PROPERTY_HALF_DUPLEX
				    | SSH_NETCONFIG_LINK_PROPERTY_FULL_DUPLEX);
	  ctx.link->speed = 0;
	}
    }
  
  return ctx.error;
}

/*********************** Setting Link Flags *********************************/

SshNetconfigError
ssh_netconfig_set_link_flags(SshUInt32 ifnum, SshUInt32 flags, SshUInt32 mask)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_UNDEFINED;

  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
  
#ifdef LINUX_HAS_RTM_SETLINK
  if (!linux_netlink_set_link(ifnum, 0, flags, mask,
			      netconfig_error_parser, &error))
    return SSH_NETCONFIG_ERROR_UNDEFINED;
#else /*  LINUX_HAS_RTM_SETLINK*/
  if (linux_netlink_set_link_ioctl(ifnum, 0, flags, mask))
    error = SSH_NETCONFIG_ERROR_OK;
#endif /* LINUX_HAS_RTM_SETLINK */

  return error;
}

/*********************** Setting Link MTU ***********************************/

SshNetconfigError
ssh_netconfig_set_link_mtu(SshUInt32 ifnum, SshUInt16 mtu)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_UNDEFINED;

  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
  
#ifdef LINUX_HAS_RTM_SETLINK
  if (!linux_netlink_set_link(ifnum, mtu, 0, 0, 
			      netconfig_error_parser, &error))
    return SSH_NETCONFIG_ERROR_UNDEFINED;
#else /*  LINUX_HAS_RTM_SETLINK*/
  if (linux_netlink_set_link_ioctl(ifnum, mtu, 0, 0))
    error = SSH_NETCONFIG_ERROR_OK;
#endif /* LINUX_HAS_RTM_SETLINK */

  return error;
}

/************************* Ifname mapping ***********************************/

typedef struct SshLinuxNetconfigResolveIfnameRec
{
  Boolean resolve_ifname;
  unsigned char ifname[IFNAMSIZ];
  SshUInt32 ifnum;
  SshNetconfigError error;
} SshLinuxNetconfigResolveIfnameStruct, *SshLinuxNetconfigResolveIfname;

static void
netconfig_resolve_ifname_parser(int nl_error, struct nlmsghdr *nh, 
				void *context)
{
  SshLinuxNetconfigResolveIfname ctx = context;
  struct ifinfomsg *ifi;
  struct rtattr *rta;
  size_t offset;

  if (nl_error)
    {
      ctx->error = netconfig_errno_to_error(nl_error);
      return;
    }

  SSH_ASSERT(nh != NULL);

  if (nh->nlmsg_type == RTM_GETLINK || nh->nlmsg_type == RTM_NEWLINK
      || nh->nlmsg_type == RTM_DELLINK)
    {
      ifi = (struct ifinfomsg *) NLMSG_DATA(nh);
      rta = NULL;
      for (offset = NLMSG_ALIGN(sizeof(*ifi));
	   offset < (nh->nlmsg_len - NLMSG_HDRLEN);
	   offset += RTA_ALIGN(rta->rta_len))
	{
	  rta = (struct rtattr *) (((unsigned char *) ifi) + offset);
	  
	  if (RTA_ALIGN(rta->rta_len) == 0)
	    break;
	  
	  switch (rta->rta_type)
	    {
	    case IFLA_IFNAME:
	      if (ctx->resolve_ifname)
		{
		  if (RTA_PAYLOAD(rta) <= sizeof(ctx->ifname) &&
		      strncmp(ctx->ifname, RTA_DATA(rta), RTA_PAYLOAD(rta)) 
		      == 0)
		    {
		      ctx->ifnum = 
			SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(ifi->ifi_index);
		      ctx->error = SSH_NETCONFIG_ERROR_OK;
		    }
		}
	      
	      else 
		{
		  if (RTA_PAYLOAD(rta) <= sizeof(ctx->ifname)
		      && (SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(ifi->ifi_index)
			  == ctx->ifnum))
		    {
		      ssh_snprintf(ctx->ifname, sizeof(ctx->ifname),
				   "%s", RTA_DATA(rta));
		      ctx->error = SSH_NETCONFIG_ERROR_OK;
		    }
		}
	      break;
	      
	    default:
	      break;
	    }
	}
    }
}

SshNetconfigError
ssh_netconfig_resolve_ifname(const unsigned char *ifname, SshUInt32 *ifnum_ret)
{
  SshLinuxNetconfigResolveIfnameStruct ctx;

  if (ifname == NULL 
      || strlen(ifname) == 0 || strlen(ifname) > sizeof(ctx.ifname))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;  
  
  ctx.resolve_ifname = TRUE;
  ctx.error = SSH_NETCONFIG_ERROR_NON_EXISTENT;
  ctx.ifnum = SSH_INVALID_IFNUM;
  ssh_snprintf(ctx.ifname, sizeof(ctx.ifname), "%s", ifname);

  if (!linux_netlink_get_link(netconfig_resolve_ifname_parser, &ctx) 
      || ctx.error != SSH_NETCONFIG_ERROR_OK)
    return ctx.error;
  
  *ifnum_ret = ctx.ifnum;
  return SSH_NETCONFIG_ERROR_OK;
}

SshNetconfigError
ssh_netconfig_resolve_ifnum(SshUInt32 ifnum, unsigned char *ifname, 
			    size_t ifname_len)
{
  SshLinuxNetconfigResolveIfnameStruct ctx;
  
  if (ifnum == SSH_INVALID_IFNUM 
      || ifname == NULL || ifname_len < sizeof(ctx.ifname))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  ctx.resolve_ifname = FALSE;
  ctx.error = SSH_NETCONFIG_ERROR_NON_EXISTENT;
  ctx.ifnum = ifnum;
  ctx.ifname[0] = '\0';

  if (!linux_netlink_get_link(netconfig_resolve_ifname_parser, &ctx) 
      || ctx.error != SSH_NETCONFIG_ERROR_OK)
    return ctx.error;
  
  ssh_snprintf(ifname, ifname_len, "%s", ctx.ifname);
  return SSH_NETCONFIG_ERROR_OK;
}

/************************* Link multicast ***********************************/

SshNetconfigError
netconfig_link_multicast_membership(SshUInt32 ifnum,
				    unsigned char *mcast_addr,
				    size_t mcast_addr_len,
				    Boolean add_membership)
{
  int sd = 0;
  struct ifreq ifr;
  int request;

  if (mcast_addr_len > sizeof(ifr.ifr_hwaddr.sa_data))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  sd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sd < 0)
    goto fail;

  /* Resolve ifname. */
  memset(&ifr, 0, sizeof(ifr));
  if (ssh_netconfig_resolve_ifnum(ifnum, ifr.ifr_name, sizeof(ifr.ifr_name))
      != SSH_NETCONFIG_ERROR_OK)
    goto fail;
  
  ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
  memcpy(&ifr.ifr_hwaddr.sa_data, mcast_addr, mcast_addr_len);

  if (add_membership)
    request = SIOCADDMULTI;
  else
    request = SIOCDELMULTI;

  if (ioctl(sd, request, &ifr))
    goto fail;

  close(sd);
  return SSH_NETCONFIG_ERROR_OK;

 fail:
  if (sd)
    close(sd);
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}

SshNetconfigError
ssh_netconfig_link_multicast_add_membership(SshUInt32 ifnum,
                                            unsigned char *mcast_addr,
                                            size_t mcast_addr_len)
{
  return netconfig_link_multicast_membership(ifnum, mcast_addr, mcast_addr_len,
					     TRUE);
}

SshNetconfigError
ssh_netconfig_link_multicast_drop_membership(SshUInt32 ifnum,
                                             unsigned char *mcast_addr,
                                             size_t mcast_addr_len)
{
  return netconfig_link_multicast_membership(ifnum, mcast_addr, mcast_addr_len,
					     FALSE);
}


/*********************** Fetching IP Addresses *******************/

typedef struct SshLinuxNetconfigGetAddressesRec
{
  SshUInt32 ifnum;
  SshNetconfigInterfaceAddr addresses;
  SshUInt32 num_addresses;
  SshUInt32 num_addresses_return;
  SshNetconfigError error;
} SshLinuxNetconfigGetAddressesStruct, *SshLinuxNetconfigGetAddresses;

static void
netconfig_get_addresses_parser(int nl_error, struct nlmsghdr *nh, 
			       void *context)
{
  SshLinuxNetconfigGetAddresses ctx = context;
  struct ifaddrmsg *ifa;
  struct rtattr *rta;
  size_t offset;
  SshNetconfigInterfaceAddr address;

  if (nl_error)
    {
      ctx->error = netconfig_errno_to_error(nl_error);
      return;
    }

  SSH_ASSERT(nh != NULL);

  if (nh->nlmsg_type == RTM_GETADDR || nh->nlmsg_type == RTM_NEWADDR ||
      nh->nlmsg_type == RTM_DELADDR)
    {
      ifa = (struct ifaddrmsg *) NLMSG_DATA(nh);
      
      if (ctx->ifnum != SSH_INVALID_IFNUM 
	  && (ctx->ifnum 
	      != SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(ifa->ifa_index)))
	return;

      if (ctx->num_addresses_return >= ctx->num_addresses)
	{
	  ctx->error = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
	  return;
	}
      address = &ctx->addresses[ctx->num_addresses_return];
      
      address->flags = netconfig_ifa_to_addr_flags(ifa->ifa_flags);

      ctx->error = SSH_NETCONFIG_ERROR_OK;

      /* Initialize interface address structure. */
      SSH_IP_UNDEFINE(&address->address);
      SSH_IP_UNDEFINE(&address->broadcast);
      address->flags = 0;

      rta = NULL;
      for (offset = NLMSG_ALIGN(sizeof(*ifa));
	   offset < (nh->nlmsg_len - NLMSG_HDRLEN);
	   offset += RTA_ALIGN(rta->rta_len))
	{
	  rta = (struct rtattr *) (((unsigned char *) ifa) + offset);
	  
	  if (RTA_ALIGN(rta->rta_len) == 0)
	    break;

	  switch (rta->rta_type)
	    {
	    case IFA_LOCAL:
	      if (ifa->ifa_family == AF_INET && RTA_PAYLOAD(rta) == 4)
		{
		  if (SSH_IP_DEFINED(&address->address))
		    {
		      ctx->error = SSH_NETCONFIG_ERROR_UNDEFINED;
		      return;
		    }
		  SSH_IP4_MASK_DECODE(&address->address,
				      (unsigned char *) RTA_DATA(rta),
				      ifa->ifa_prefixlen);
		}
	      break;

	    case IFA_ADDRESS:
	      if (ifa->ifa_family == AF_INET6 && RTA_PAYLOAD(rta) == 16)
		{
		  if (SSH_IP_DEFINED(&address->address))
		    {
		      ctx->error = SSH_NETCONFIG_ERROR_UNDEFINED;
		      return;
		    }
		  SSH_IP6_MASK_DECODE(&address->address,
				      (unsigned char *) RTA_DATA(rta),
				      ifa->ifa_prefixlen);
		}
	      break;

	    case IFA_BROADCAST:
	      if (SSH_IP_DEFINED(&address->broadcast))
		{
		  ctx->error = SSH_NETCONFIG_ERROR_UNDEFINED;
		  return;
		}
	      if (ifa->ifa_family == AF_INET && RTA_PAYLOAD(rta) == 4)
		{
		  SSH_IP4_DECODE(&address->broadcast,
				 (unsigned char *) RTA_DATA(rta));
		  address->flags |= SSH_NETCONFIG_ADDR_BROADCAST;
		}
	      break;
	    }
	}
      
      if (!SSH_IP_DEFINED(&address->address))
	ctx->error = SSH_NETCONFIG_ERROR_UNDEFINED;
      else
	ctx->num_addresses_return++;
    }

  /* It is ok for an interface not to have any addresses. */
  if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR
      || (nh->nlmsg_flags & NLM_F_MULTI) == 0)
    {
      if (ctx->error == SSH_NETCONFIG_ERROR_UNDEFINED)
	ctx->error = SSH_NETCONFIG_ERROR_OK;
    }
}

SshNetconfigError
ssh_netconfig_get_addresses(SshUInt32 ifnum, SshUInt32 *num_addresses,
			    SshNetconfigInterfaceAddr addresses)
{
  SshLinuxNetconfigGetAddressesStruct ctx;

  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  ctx.ifnum = ifnum;
  ctx.addresses = addresses;
  ctx.num_addresses = *num_addresses;
  ctx.num_addresses_return = 0;
  ctx.error = SSH_NETCONFIG_ERROR_UNDEFINED;

  if (!linux_netlink_get_addr(netconfig_get_addresses_parser, &ctx))
      return SSH_NETCONFIG_ERROR_UNDEFINED;

  if (ctx.error != SSH_NETCONFIG_ERROR_OK)
    return ctx.error;

  *num_addresses = ctx.num_addresses_return;

  return SSH_NETCONFIG_ERROR_OK;
}


/*********************** Adding and Deleting IP Addresses *******************/

SshNetconfigError
ssh_netconfig_add_address(SshUInt32 ifnum,
			  SshNetconfigInterfaceAddr address)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_UNDEFINED;
  
  if (ifnum == SSH_INVALID_IFNUM
      || address == NULL || !SSH_IP_DEFINED(&address->address))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  if (!linux_netlink_modify_addr(TRUE, &address->address, &address->broadcast, 
				 ifnum, address->flags,
				 netconfig_error_parser, &error))
    return SSH_NETCONFIG_ERROR_UNDEFINED;
  
  return error;
}

SshNetconfigError
ssh_netconfig_del_address(SshUInt32 ifnum, 
			  SshNetconfigInterfaceAddr address)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_UNDEFINED;

  if (ifnum == SSH_INVALID_IFNUM
      || address == NULL || !SSH_IP_DEFINED(&address->address))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
  
  /* Clear broadcast address as on linux it always bound to 
     the unicast address. */
  address->flags &= ~SSH_NETCONFIG_ADDR_BROADCAST;

  if (!linux_netlink_modify_addr(FALSE, &address->address, NULL, 
				 ifnum, address->flags,
				 netconfig_error_parser, &error))
    return SSH_NETCONFIG_ERROR_UNDEFINED;
  
  return error;
}


/*********************** Flushing IP Addresses ******************************/

#define SSH_LINUX_NETCONFIG_MAX_ADDRESSES 16

SshNetconfigError
ssh_netconfig_flush_addresses(SshUInt32 ifnum)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_OK;
  SshNetconfigInterfaceAddrStruct addresses[SSH_LINUX_NETCONFIG_MAX_ADDRESSES];
  SshUInt32 num_addresses = SSH_LINUX_NETCONFIG_MAX_ADDRESSES;
  int i;

  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  error = ssh_netconfig_get_addresses(ifnum, &num_addresses, addresses);
  if (error != SSH_NETCONFIG_ERROR_OK)
    return error;

  for (i = 0; i < num_addresses; i++)
    {
      error = ssh_netconfig_del_address(ifnum, &addresses[i]);
      if (error != SSH_NETCONFIG_ERROR_OK)
	return error;
    }

  return error;
}


/*********************** Fetching Routes ************************************/

typedef struct SshLinuxNetconfigGetRouteRec
{
  SshIpAddr prefix;
  SshNetconfigRoute routes;
  SshUInt32 num_routes;
  SshUInt32 num_routes_return;
  SshNetconfigError error;
} SshLinuxNetconfigGetRouteStruct, *SshLinuxNetconfigGetRoute;

static void
netconfig_get_route_parser(int nl_error, struct nlmsghdr *nh, 
			   void *context)
{
  SshLinuxNetconfigGetRoute ctx = context;
  struct rtmsg *rtm;
  struct rtattr *rta;
  size_t offset;
  int if_index;
  
  if (nl_error)
    {
      ctx->error = netconfig_errno_to_error(nl_error);
      return;
    }

  SSH_ASSERT(nh != NULL);

  if (nh->nlmsg_type == RTM_GETROUTE || nh->nlmsg_type == RTM_NEWROUTE ||
      nh->nlmsg_type == RTM_DELROUTE)
    {
      SshNetconfigRoute route;

      rtm = (struct rtmsg *) NLMSG_DATA(nh);

      if (rtm->rtm_table != RT_TABLE_MAIN)
	return;

      /* Do not consider blackhole, unreachable, prohibited or nat routes. */ 
      if (rtm->rtm_type != RTN_UNICAST
	  && rtm->rtm_type != RTN_LOCAL
	  && rtm->rtm_type != RTN_BROADCAST
	  && rtm->rtm_type != RTN_ANYCAST
	  && rtm->rtm_type != RTN_MULTICAST)
	return;

      if (ctx->num_routes_return >= ctx->num_routes)
	{
	  ctx->error = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
	  return;
	}
      route = &ctx->routes[ctx->num_routes_return];

      ctx->error = SSH_NETCONFIG_ERROR_OK;

      /* Initialize route structure. */
      SSH_IP_UNDEFINE(&route->prefix);
      SSH_IP_UNDEFINE(&route->gateway);
      route->ifnum = SSH_INVALID_IFNUM;
      route->metric = 0;
      route->flags = 0;

      rta = NULL;
      for (offset = NLMSG_ALIGN(sizeof(*rtm));
	   offset < (nh->nlmsg_len - NLMSG_HDRLEN);
	   offset += RTA_ALIGN(rta->rta_len))
	{
	  rta = (struct rtattr *) (((unsigned char *) rtm) + offset);
	  
	  if (RTA_ALIGN(rta->rta_len) == 0)
	    break;

	  switch (rta->rta_type)
	    {
	    case RTA_DST:
	      if (rtm->rtm_family == AF_INET && RTA_PAYLOAD(rta) == 4)
		{
		  SSH_IP4_MASK_DECODE(&route->prefix,
				      (unsigned char *) RTA_DATA(rta),
				      rtm->rtm_dst_len);
		}
	      else if (rtm->rtm_family == AF_INET6 && RTA_PAYLOAD(rta) == 16)
		{
		  SSH_IP6_MASK_DECODE(&route->prefix,
				      (unsigned char *) RTA_DATA(rta),
				      rtm->rtm_dst_len);
		}
	      break;

	    case RTA_GATEWAY:
	      if (rtm->rtm_family == AF_INET && RTA_PAYLOAD(rta) == 4)
		{
		  if (!SSH_IP_DEFINED(&route->prefix))
		    {
		      ssh_ipaddr_parse(&route->prefix, SSH_IPADDR_ANY_IPV4);
		      SSH_IP_MASK_LEN(&route->prefix) = rtm->rtm_dst_len;
		    }
		  SSH_IP4_DECODE(&route->gateway,
				 (unsigned char *) RTA_DATA(rta));
		}
	      else if (rtm->rtm_family == AF_INET6 && RTA_PAYLOAD(rta) == 16)
		{
		  if (!SSH_IP_DEFINED(&route->prefix))
		    {
		      ssh_ipaddr_parse(&route->prefix, SSH_IPADDR_ANY_IPV6);
		      SSH_IP_MASK_LEN(&route->prefix) = rtm->rtm_dst_len;
		    }
		  SSH_IP6_DECODE(&route->gateway,
				 (unsigned char *) RTA_DATA(rta));
		}
	      break;

	    case RTA_PRIORITY:
	      route->metric = *((SshUInt32 *) RTA_DATA(rta));
	      break;	      	    

	    case RTA_OIF:
	      if_index = *((SshUInt32 *) RTA_DATA(rta));
	      route->ifnum = SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(if_index);
	      break;	      	    
	    }
	}

      if (!SSH_IP_DEFINED(&route->prefix))
	ctx->error = SSH_NETCONFIG_ERROR_UNDEFINED;	  
      else if (ctx->prefix == NULL 
	       || SSH_IP_MASK_EQUAL(&route->prefix, ctx->prefix))
	ctx->num_routes_return++;
    }

  /* It is ok to not have any matching routes. */
  if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR
      || (nh->nlmsg_flags & NLM_F_MULTI) == 0)
    {
      if (ctx->error == SSH_NETCONFIG_ERROR_UNDEFINED)
	ctx->error = SSH_NETCONFIG_ERROR_OK;
    }
}

SshNetconfigError
ssh_netconfig_get_route(SshIpAddr prefix,
			SshUInt32 *num_routes,
			SshNetconfigRoute routes)
{
  SshLinuxNetconfigGetRouteStruct ctx;

  ctx.prefix = prefix;
  ctx.routes = routes;
  ctx.num_routes = *num_routes;
  ctx.num_routes_return = 0;
  ctx.error = SSH_NETCONFIG_ERROR_OK;

  if (!linux_netlink_get_route(netconfig_get_route_parser, &ctx))
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  if (ctx.error != SSH_NETCONFIG_ERROR_OK)
    return ctx.error; 
  
  *num_routes = ctx.num_routes_return;

  return SSH_NETCONFIG_ERROR_OK;
}

/*********************** Adding and Deleting Routes *************************/

SshNetconfigError
ssh_netconfig_add_route(SshNetconfigRoute route)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_UNDEFINED;
  SshIpAddr gateway = NULL;

  if (route == NULL || !SSH_IP_DEFINED(&route->prefix))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  if (SSH_IP_DEFINED(&route->gateway))
    gateway = &route->gateway;

  if (!linux_netlink_modify_route(TRUE, &route->prefix, gateway, 
				  route->ifnum, route->metric,
				  netconfig_error_parser, &error))
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  return error;
}

SshNetconfigError
ssh_netconfig_del_route(SshNetconfigRoute route)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_UNDEFINED;
  SshIpAddr gateway = NULL;

  if (route == NULL || !SSH_IP_DEFINED(&route->prefix))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
  
  if (SSH_IP_DEFINED(&route->gateway))
    gateway = &route->gateway;

  if (!linux_netlink_modify_route(FALSE, &route->prefix, gateway,
				  route->ifnum, route->metric,
				  netconfig_error_parser, &error))
    return SSH_NETCONFIG_ERROR_UNDEFINED;
  
  return error;
}

SshUInt32
ssh_netconfig_route_metric(SshRoutePrecedence precedence, Boolean ipv6)
{
   switch (precedence)
    {
    case SSH_ROUTE_PREC_LOWEST:
      if (ipv6)
	return 1044;
      else
	return 255;
      break;
    case SSH_ROUTE_PREC_BELOW_SYSTEM:
      if (ipv6)
	return 1024;
      else
	return 21;
      break;
    case SSH_ROUTE_PREC_SYSTEM:
      if (ipv6)
	return 256;
      else
	return 0;
      break;
    case SSH_ROUTE_PREC_ABOVE_SYSTEM:
      if (ipv6)
	return 20;
      else
	return 0;
      break;
    case SSH_ROUTE_PREC_HIGHEST:
      if (ipv6)
	return 1;
      else
	return 0;
      break;
    }
   
   return 0xffffffff;
}

#endif /* __linux__ */
#endif /* SSHDIST_PLATFORM_LINUX */
