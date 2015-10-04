/*

  File: sshudp-ip.c

  Copyright:
 	Copyright (c) 2002, 2003, 2004, 2005 SFNT Finland Oy.
        All rights reserved.

  Generic code of the UDP communications interface.

*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshudp.h"
#include "sshtimeouts.h"
#include "ssheloop.h"
#include "sshglobals.h"






/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshUdpGeneric"

/* UDP listener. */
struct SshUdpListenerRec
{
  /* Methods. */
  SshUdpMethods methods;

  /* Instance context. */
  void *context;
};

/***************************** Utility Functions ****************************/

const char *
ssh_udp_error_string(SshUdpError error)
{
  switch (error)
    {
    case SSH_UDP_OK:
     return "OK";
    case SSH_UDP_HOST_UNREACHABLE:
     return "Destination Host Unreachable";
    case SSH_UDP_PORT_UNREACHABLE:
     return "Destination Port Unreachable";
    case SSH_UDP_NO_DATA:
     return "No Data";
    default:
     return "Unknown Error";
    }
  /* NOTREACHED */
}

typedef unsigned char SshUdpDatagramBufferArray[SSH_UDP_DATAGRAM_BUFFER_SIZE];
SSH_GLOBAL_DECLARE(SshUdpDatagramBufferArray, udp_datagram_buffer);
SSH_GLOBAL_DEFINE_INIT(SshUdpDatagramBufferArray, udp_datagram_buffer);
#define udp_datagram_buffer SSH_GLOBAL_USE_INIT(udp_datagram_buffer)

unsigned char *ssh_udp_get_datagram_buffer(size_t *datagram_buffer_len)
{
  *datagram_buffer_len = sizeof(udp_datagram_buffer);
  return &udp_datagram_buffer[0];
}

/****************** Platform dependent UDP implementation *******************/

/* Fetch the platform dependent UDP methods and constructor
   context. */
SshUdpMethods ssh_udp_platform_methods(void **constructor_context_return);


/***************************** Public functions *****************************/

SshUdpListener
ssh_udp_make_listener_ip(SshIpAddr local_address,
			 SshUInt16 local_port,
			 SshIpAddr remote_address,
			 SshUInt16 remote_port,
			 SshUdpListenerParams params,
			 SshUdpCallback callback,
			 void *context)
{
  SshUdpListener listener;
  void *make_listener_context;

  listener = ssh_calloc(1, sizeof(*listener));
  if (listener == NULL)
    return NULL;

  if (params && params->udp_methods)
    {
      listener->methods = params->udp_methods;
      make_listener_context = params->make_listener_method_context;
    }
  else
    {
      listener->methods = ssh_udp_platform_methods(&make_listener_context);
    }

  listener->context
    = (*listener->methods->make_listener)(make_listener_context,
                                          listener,
                                          local_address, local_port,
                                          remote_address, remote_port,
                                          params,
                                          callback, context);
  if (listener->context == NULL)
    {
      ssh_free(listener);
      return NULL;
    }

  return listener;
}


void
ssh_udp_destroy_listener(SshUdpListener listener)
{
  (*listener->methods->destroy_listener)(listener->context);
  ssh_free(listener);
}


SshUdpError
ssh_udp_read_ip(SshUdpListener listener,
		SshIpAddr remote_address, SshUInt16 *remote_port,
		unsigned char *datagram_buffer,
		size_t datagram_buffer_len,
		size_t *datagram_len_return)
{
  SshUdpError rv;









  rv = (*listener->methods->read)(listener->context,
				  remote_address, remote_port,
				  datagram_buffer, datagram_buffer_len,
				  datagram_len_return);

































  return rv;
}


SshUdpError
ssh_udp_send_ip(SshUdpListener listener,
		SshIpAddr remote_address, SshUInt16 remote_port,
		const unsigned char *datagram_buffer,
		size_t datagram_len)
{
  SshUdpError rv;




























































  rv = (*listener->methods->send)(listener->context,
				  remote_address, remote_port,
				  datagram_buffer, datagram_len);
















  return rv;
}


SshUdpError
ssh_udp_multicast_add_membership_ip(SshUdpListener listener,
				    SshIpAddr group_to_join,
				    SshIpAddr interface_to_join)
{
  return (*listener->methods->multicast_add_membership)(listener->context,
                                                        group_to_join,
                                                        interface_to_join);
}

SshUdpError
ssh_udp_multicast_drop_membership_ip(SshUdpListener listener,
				     SshIpAddr group_to_drop,
				     SshIpAddr interface_to_drop)
{
  return (*listener->methods->multicast_drop_membership)(listener->context,
                                                         group_to_drop,
                                                         interface_to_drop);
}

const SshKeywordStruct ssh_udp_status_keywords[] = {
  { "OK", SSH_UDP_OK },
  { "Remote host unreachable", SSH_UDP_HOST_UNREACHABLE },
  { "Remote port unreachable", SSH_UDP_PORT_UNREACHABLE },
  { "Data not available", SSH_UDP_NO_DATA },
  { "Invalid Arguments", SSH_UDP_INVALID_ARGUMENTS }
};
