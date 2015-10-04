/**
   
   @copyright
   Copyright (c) 2002 - 2010, AuthenTec Oy.  All rights reserved.
   
   usermodeinterceptor.h
   
   This file is an (internal) header file for the usermode
   interceptor interface implemented in usermodeinterceptor.c.
   
*/


#include "interceptor.h"
#include "engine.h"
#include "kernel_mutex.h"
#include "kernel_timeouts.h"
#include "sshencode.h"
#include "usermodeforwarder.h"
#include "usermodeinterceptor.h"
#include "sshtimeouts.h"
#include "sshpacketstream.h"
#include "sshdevicestream.h"
#include "sshlocalstream.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshinetencode.h"
#include "sshmutex.h"
#include "sshglobals.h"
#include "sshthreadedmbox.h"

#ifndef USERMODEINTERCEPTOR_INTERNAL_H
#define USERMODEINTERCEPTOR_INTERNAL_H

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#include "virtual_adapter.h"
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/* Pointer to the interceptor object.  Only one interceptor is supported by
   this implementation. */
extern SshInterceptor ssh_usermode_interceptor;

/* Flags for the usermode interceptor.  These can be used to cause it
   to generate fake errors at random. */
extern SshUInt32 ssh_usermode_interceptor_flags;

/* Data structure for route operations that has been sent to the kernel but
   for which no reply has yet been received.  These are kept on a list,
   linked by the `next' field. */
typedef struct SshInterceptorRouteOpRec
{
  /* Unique identifier for this route operation. */
  SshUInt32 id;

  /* The address for which this route operation was performed. */
  SshIpAddrStruct destination;

  /* Completion function from the route request. This will be called when
     the reply is received from the kernel. */
  SshInterceptorRouteCompletion completion_cb;

  /* Context argument to be passed to the completion function. */
  void *context;

  /* Pointer to next route request in the list. */
  struct SshInterceptorRouteOpRec *next;

  /** Route lookup result. */
  struct {
    Boolean reachable;
    Boolean next_hop_ok;
    SshUInt32 ifnum;
    SshUInt32 mtu;
    SshIpAddrStruct next_hop_gw;
  } result;
} *SshInterceptorRouteOp;

/* Data structure for route modify operations that has been sent to the kernel 
   but for which no reply has yet been received.  These are kept on a list,
   linked by the `next' field. */
typedef struct SshInterceptorRouteModifyOpRec
{
  /* Unique identifier for this route operation. */
  SshUInt32 id;

  /* The address for which this route operation was performed. */
  SshIpAddrStruct destination;

  /* Completion function for the routing table manipulation operation. */
  SshInterceptorRouteSuccessCB success_cb;

  /* Context argument to be passed to the completion function. */
  void *context;

  /* Pointer to next route request in the list. */
  struct SshInterceptorRouteModifyOpRec *next;

  /** Result status code. */
  SshInterceptorRouteError result;
} *SshInterceptorRouteModifyOp;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

/* Data structure for a pending virtual adapter operation. */
typedef struct SshInterceptorVirtualAdapterOpRec
{
  /* Pointer to the next pending request. */
  struct SshInterceptorVirtualAdapterOpRec *next;

  /* Is the operation aborted? */
  Boolean aborted;

  /* Is this virtual_adapter_attach operation? */
  Boolean attach;

  /* Unique identifier for this operation.  This is used to match
     usermode forwarder's replies to requests. */
  SshUInt32 id;

  /* Completion callback for the pending operation. */
  SshVirtualAdapterStatusCB status_cb;

  /* Context data for the completion callback. */
  void *context;

  /* Data needed for the attach operation. */
  SshVirtualAdapterPacketCB packet_cb;
  SshVirtualAdapterDetachCB detach_cb;
  void *adapter_context;

  /* The operation handle of this operation. */
  SshOperationHandle handle;
} *SshInterceptorVirtualAdapterOp;

/* A registry for an existing virtual adapter. */
typedef struct SshInterceptorVirtualAdapterRec
{
  /* Pointer to the next known virtual adapter. */
  struct SshInterceptorVirtualAdapterRec *next;

  /* Adapter's unique id. */
  SshInterceptorIfnum adapter_ifnum;

  /* User-supplied packet callback. */
  SshVirtualAdapterPacketCB packet_cb;

  /* User-supplied data destructor */
  SshVirtualAdapterDetachCB detach_cb;
  
  void *adapter_context;
} *SshInterceptorVirtualAdapter;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


/* Data structure for the user-mode interceptor.  This implements a
   fake interceptor for the engine.  The real interceptor is in the
   kernel, and this communicates with it. */
struct SshInterceptorRec
{
  SshInterceptorPacketMgrStruct pktmgr;

  /* Mutex to protect all concurrent accesses to some of the fields in
     this structure */
  SshMutex mutex;

  /* Machine context argument passsed to ssh_interceptor_open.  This
     should actually be a string naming the device used to talk to the
     kernel. */
  void *machine_context;

  /* Packet callback. */
  SshInterceptorPacketCB packet_cb;
  void *packet_cb_context;

  /* Interface callback. */
  SshInterceptorInterfacesCB interfaces_cb;

  /* Route change callback. */
  SshInterceptorRouteChangeCB route_change_cb;

  /* Context argument to pass to the callbacks. */
  void *context;

  /* Interface information. */
  SshInterceptorInterface *ifs;
  SshUInt32 num_ifs;

  /* This is set to TRUE when ssh_interceptor_stop is called.  If this is
     set then the interceptor will not make any packet, interface, route
     changed, or debug callbacks to the engine. */
  Boolean stopping;

  /* This is set to TRUE when ssh_interceptor_stop returns TRUE.  This is
     used for sanity checks in ssh_interceptor_close. */
  Boolean stopped;

  /* Number of calls out to the callbacks that haven't returned.
     Route requests are also counted here.  This is used to determine
     when ssh_interceptor_stop can return TRUE. Protected by icept
     mutex. */
  SshUInt32 num_outcalls;

  /* Packet wrapper for talking to the kernel. */
  SshPacketWrapper wrapper;

  /* Next identifier to use for route requests.  This is incremented by
     one every time this is used.  It is silently assumed that route requests
     do not live long enough for this to wrap. Protected by icept mutex. */
  SshUInt32 next_route_id;

  /* List of route entries for which no reply has yet been
     received. Protected by icept mutex. */
  SshInterceptorRouteOp route_operations;

  /* List of route modify entries for which no reply has yet been
     received. Protected by icept mutex. */
  SshInterceptorRouteModifyOp route_modify_operations;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* List of pending virtual adapter operations. Protected by icept mutex. */
  SshInterceptorVirtualAdapterOp virtual_adapter_operations;

  /* The next unique ID for virtual adapter operations. Protected by
     icept mutex. */
  SshUInt32 virtual_adapter_op_id;

  /* Existing virtual adapters. Protected by icept mutex. */
  SshInterceptorVirtualAdapter virtual_adapters;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
};

typedef struct SshInterceptorTimeoutsRec {
  /* Mutex protecting this structure and all timeouts wraps */
  SshMutex mutex;

  /* Timeout list */
  struct SshInterceptorTimeoutWrapRec *timeouts;
  struct SshInterceptorTimeoutWrapRec *timeouts_tail;
} *SshInterceptorTimeouts, SshInterceptorTimeoutsStruct;

#if ((SSH_USERMODE_INTERCEPTOR_NUM_THREADS > 0) || defined(DEBUG_LIGHT))
#define SSH_USERMODE_INTERCEPTOR_LOCK(interceptor)	\
  ssh_mutex_lock((interceptor)->mutex)
#define SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor)	\
  ssh_mutex_unlock((interceptor)->mutex)
#define SSH_USERMODE_TIMEOUT_LOCK(timeouts)	\
  ssh_mutex_lock((timeouts)->mutex)
#define SSH_USERMODE_TIMEOUT_UNLOCK(timeouts)	\
  ssh_mutex_unlock((timeouts)->mutex)
#else /*((SSH_USERMODE_INTERCEPTOR_NUM_THREADS > 0) || defined(DEBUG_LIGHT))*/
#define SSH_USERMODE_INTERCEPTOR_LOCK(interceptor)
#define SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor)
#define SSH_USERMODE_TIMEOUT_LOCK(timeouts)
#define SSH_USERMODE_TIMEOUT_UNLOCK(timeouts)
#endif /*((SSH_USERMODE_INTERCEPTOR_NUM_THREADS > 0) || defined(DEBUG_LIGHT))*/

/* Directly forward a data block to the interceptor, bypassing normal
   encode-wrapping */
Boolean ssh_usermode_interceptor_send(SshInterceptor icept, SshPacketType type,
                                      const unsigned char * data, size_t len);

/* Send a message to the kernel interceptor, performing normal
   encoding etc. This is semantically (but not implemented directly
   as) calling ssh_packet_wrapper_send_encode on the same arguments
   (sans icept->wrapper). */
Boolean ssh_usermode_interceptor_send_encode(SshInterceptor icept,
                                          SshPacketType type, ...);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
/* Handle for virtual adapter messages. */
void ssh_kernel_receive_virtual_adapter(SshPacketType type,
                                        const unsigned char *data, size_t len);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#ifdef SSH_USERMODE_INTERCEPTOR_DISABLE_TESTS
/** Returns a pointer to the packet data buffer. This is used when
    encoding packet data for sending to usermodeforwarder in kernel.
    This functions is only available when usermodeinterceptor packet
    API test features are disabled (as in this case the packet data
    buffer is always linearized). */
unsigned char *
ssh_usermode_interceptor_packet_ptr(SshInterceptorPacket pp);
#endif /* SSH_USERMODE_INTERCEPTOR_DISABLE_TESTS */

#endif /* USERMODEINTERCEPTOR_INTERNAL_H */
