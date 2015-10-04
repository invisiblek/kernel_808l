/*
 * engine_rule_execute.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Code for "executing" a policy rule (that is, processing the packet
 * according to the rule).  This file also contains the code to
 * manipulate "next hop" nodes.
 *
 * The rule execution is implemented as a simple state machine.  The
 * state machine has separate states for forwarded, inbound, and
 * outbound packets.  In the first phase, the state machine resolves
 * the `forward' path - the actions to be taken when processing the
 * packet in its current direction.  In the second step, the state
 * machine resolves the `reverse' path.  The reverse path is used to
 * create the actions of the reverse flow.  The `reverse' path is not
 * executed for `no-flow' rules.
 *
 * Notes on stack usage:
 * The rule execution starts from ssh_engine_execute_rule(), which calls
 * ssh_engine_execute_rule_step() to step the rule execution state machine
 * forward. Each step in turn calls ssh_engine_execute_rule_step(), until
 * the rule execution reaches the final step or fails. The final step is
 * performed in a separate function, ssh_engine_execute_rule_step_final()
 * to minimize the amount if useless local variables (and stack usage).
 * The recursion is eliminated in ssh_engine_execute_rule_step(). The actual 
 * work is done in ssh_engine_execute_rule_step_internal(), which is always 
 * called from the bottom of the stack. Any error handling must be performed 
 * in ssh_engine_execute_rule_step_internal(), and errors and possible error
 * actions must be signalled to ssh_engine_execute_rule_step() using the
 * SshEngineRuleExecuteError.
 */

#include "sshincludes.h"
#include "engine_internal.h"
#include "sshmp-xuint.h"

#define SSH_DEBUG_MODULE "SshEngineRuleExecute"

/* Some prototype declarations for functions defined later in this file. */
void 
ssh_engine_execute_rule_step(SshEnginePacketContext pc, 
			     SshEngineRuleExecuteError error);

void
ssh_engine_route_change_final(SshEnginePacketContext pc,
                              SshEngineRuleExecuteError error);

void
ssh_engine_route_change_next(void *context);


/* States names of the rule execution state machine. */
#ifdef DEBUG_LIGHT
SSH_RODATA
static const char *ssh_engine_rule_state_names[] =
{
#ifdef SSHDIST_IPSEC_FIREWALL
  "ST_ROUTE_APPGW",
  "ST_ROUTE_APPGW_REDIRECT",
  "ST_ROUTE_APPGW_DONE",
#endif /* SSHDIST_IPSEC_FIREWALL */
  "ST_INIT",
  "ST_FW_ROUTE_TN_DST",
  "ST_FW_ROUTE_TN_SRC",
  "ST_TL_ROUTE_SRC",
  "ST_TL_ROUTE_TN_SRC",
  "ST_FL_ROUTE_TN_DST",
  "ST_FL_ROUTE_DST",
  "ST_LOOPBACK",
  "ST_FINAL",
};
#endif /* DEBUG_LIGHT */


/* Set the next state for the rule execution state machine.  This
   function also continues the state machine by calling
   ssh_engine_execute_rule_step. */

void ssh_engine_execute_rule_next_state(SshEngine engine,
                                        SshEnginePacketContext pc)
{
#ifdef DEBUG_LIGHT
  int old_state = pc->u.rule.state;
#endif /* DEBUG_LIGHT */

  SSH_INTERCEPTOR_STACK_MARK();

  /* Resolve the next state. */
  if (pc->rule && pc->rule->flags & SSH_ENGINE_NO_FLOW)
    {
      pc->u.rule.state = SSH_ENGINE_ST_FINAL;
    }
  else
    {
      switch (pc->u.rule.state)
        {
#ifdef SSHDIST_IPSEC_FIREWALL
          /* Creating mappings for the application level gateways. */
        case SSH_ENGINE_ST_ROUTE_APPGW:
          pc->u.rule.state = SSH_ENGINE_ST_ROUTE_APPGW_REDIRECT;
          break;

        case SSH_ENGINE_ST_ROUTE_APPGW_REDIRECT:
          pc->u.rule.state = SSH_ENGINE_ST_ROUTE_APPGW_DONE;
          break;

        case SSH_ENGINE_ST_ROUTE_APPGW_DONE:
          SSH_NOTREACHED;
	  ssh_engine_execute_rule_step(pc, 
				       SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE);
          break;
#endif /* SSHDIST_IPSEC_FIREWALL */

          /* Init state. */
        case SSH_ENGINE_ST_INIT:
          SSH_NOTREACHED;
	  ssh_engine_execute_rule_step(pc, 
				       SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE);
          break;

          /* Forwarded packets. */
        case SSH_ENGINE_ST_FW_ROUTE_TN_DST:
          pc->u.rule.state = SSH_ENGINE_ST_FW_ROUTE_TN_SRC;
          break;

        case SSH_ENGINE_ST_FW_ROUTE_TN_SRC:
          pc->u.rule.state = SSH_ENGINE_ST_FINAL;
          break;

          /* To-local (inbound) packets. */
        case SSH_ENGINE_ST_TL_ROUTE_SRC:
          pc->u.rule.state = SSH_ENGINE_ST_TL_ROUTE_TN_SRC;
          break;

        case SSH_ENGINE_ST_TL_ROUTE_TN_SRC:
          pc->u.rule.state = SSH_ENGINE_ST_FINAL;
          break;

          /* From-local (outbound) packets. */
        case SSH_ENGINE_ST_FL_ROUTE_TN_DST:
          pc->u.rule.state = SSH_ENGINE_ST_FL_ROUTE_DST;
          break;

        case SSH_ENGINE_ST_FL_ROUTE_DST:
          pc->u.rule.state = SSH_ENGINE_ST_FINAL;
          break;

          /* Loopback packets. */
        case SSH_ENGINE_ST_LOOPBACK:
          pc->u.rule.state = SSH_ENGINE_ST_FINAL;
          break;

          /* Terminal state. */
        case SSH_ENGINE_ST_FINAL:
	default:
          SSH_NOTREACHED;
	  ssh_engine_execute_rule_step(pc, 
				       SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE);
          break;
        }
    }

  SSH_DEBUG(SSH_D_MIDOK, ("State transition from `%s' to `%s'",
                          ssh_engine_rule_state_names[old_state],
                          ssh_engine_rule_state_names[pc->u.rule.state]));

  /* Continue rule execution. */
  ssh_engine_execute_rule_step(pc, SSH_ENGINE_RULE_EXECUTE_ERROR_OK);
}

/* This function returns the Interface handle matching the ifnum, and
   selects from its addresses the one that best matches the address
   'pattern' and fills it into 'if_address'.  If the 'pattern' is
   NULL, this match is not made. */
SshInterceptorInterface *
engine_select_interface(SshEngine engine,
			SshEngineIfnum ifnum,
			SshIpAddr pattern, SshIpAddr *if_address)
{
  SshInterceptorInterface *ifp;
  SshIpAddr best = NULL;
  int best_mask_len = 0, i;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
  if (ifp && pattern && if_address)
    {
      for (i = 0; i < ifp->num_addrs; i++)
	{
	  if (SSH_IP_WITH_MASK_EQUAL(pattern,
				     &ifp->addrs[i].addr.ip.ip,
				     &ifp->addrs[i].addr.ip.mask))
	    {
	      if (SSH_IP_MASK_LEN(&ifp->addrs[i].addr.ip.mask) > best_mask_len)
		{
		  best = &ifp->addrs[i].addr.ip.ip;
		  best_mask_len = SSH_IP_MASK_LEN(&ifp->addrs[i].addr.ip.mask);
		}
	    }
	}
      *if_address = best;
    }
  return ifp;
}

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* This is called during the construction of a new flow when an ARP
   request completes.  Note that two ARP requests may need to be done
   when creating a flow: one for each direction.  This completes
   initialization of the next hop entry
   pc->u.rule.next_hop_index_{src,dst}, based on the current state.
   This then calls ssh_engine_execute_rule_next_state to continue
   creating the flow and ssh_engine_execute_rule_step for indicating
   an error, if the ARP lookup failed. */

void ssh_engine_execute_rule_arp_cb(SshEnginePacketContext pc,
                                    const unsigned char *src,
                                    const unsigned char *dst,
                                    SshUInt16 ethertype)
{
  SshEngine engine = pc->engine;
  SshEngineNextHopControl c_nh = NULL;
  SshEngineNextHopData d_nh = NULL;
  SshUInt32 i = 0; /* Keep compiler quiet */
  size_t min_packet_len;
  SshInterceptorProtocol protocol;
  SshEngineRuleExecuteError error;

  SSH_INTERCEPTOR_STACK_MARK();

  /* Check if the arp lookup has failed. */
  if (src == NULL || dst == NULL)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("ARP failed during flow creation"));
      error = SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;

      /* Report failure. */
      if ((pc->rule != NULL)
          && (pc->flags & SSH_ENGINE_PC_REROUTE_FLOW) == 0)
        {
	  /* If we can not resolve the destination, send the ICMP so
	     that it appears to be coming from the interface towards
	     the destination, not from the destination (e.g. patch
	     packet context appropriately. Here we take the first
	     address from the local outbound interface. */
	  if (pc->pp->flags & SSH_PACKET_FROMADAPTER)
	    {
	      SshIpAddr srcip = NULL;
	      SshInterceptorInterface *ifp;

	      ssh_kernel_mutex_lock(engine->interface_lock);
	      ifp = engine_select_interface(engine,
					    pc->u.rule.ifnum_dst,
					    &pc->dst, &srcip);
	      if (ifp != NULL && srcip != NULL)
		pc->dst = *srcip;
	      ssh_kernel_mutex_unlock(engine->interface_lock);
	    }

	  error = SSH_ENGINE_RULE_EXECUTE_ERROR_SEND_ICMP;
        }

      ssh_engine_execute_rule_step(pc, error);
      return;
    }

  /* Take the lock to protect the flags update. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Update the next-hop entry to hold the new ARP info.  There should
     not be any other thread that could be changing the status of the
     next hop node while it is embryonic.  Thus we can evaluate this
     assertion without locking.  Also, we can save the new information
     in the next hop node without locking.  It is only the flags
     update (and processing of any queued packets) that must be
     protected. */
  switch (pc->u.rule.state)
    {
#ifdef SSHDIST_IPSEC_FIREWALL
    case SSH_ENGINE_ST_ROUTE_APPGW:
      /* Get the index of the next hop entry. */
      i = pc->u.rule.next_hop_index_appgw;

      /* Obtain pointer to the next hop entry, and sanity check it. */
      c_nh = SSH_ENGINE_GET_NH(engine, i);
      d_nh = FASTPATH_GET_NH(engine->fastpath, i);

      SSH_ASSERT(d_nh->flags & SSH_ENGINE_NH_EMBRYONIC);
      SSH_ASSERT(c_nh->refcnt > 0);

      /* Save new information in the next hop node. */
      SSH_DEBUG(SSH_D_MIDOK,
                ("Creating appgw ethernet header: dst=%@ src=%@ type=%04x",
                 ssh_etheraddr_render, dst,
                 ssh_etheraddr_render, src,
                 (unsigned int) ethertype));
      d_nh->media_hdr_len = (SshUInt8)
	ssh_engine_make_media_header(pc->u.rule.to_mediatype,
				     src, dst, ethertype,
				     d_nh->mediahdr,
				     &min_packet_len,
				     &protocol);
      break;


    case SSH_ENGINE_ST_ROUTE_APPGW_REDIRECT:
      break;

    case SSH_ENGINE_ST_ROUTE_APPGW_DONE:
      SSH_NOTREACHED;
      break;
#endif /* SSHDIST_IPSEC_FIREWALL */

    case SSH_ENGINE_ST_INIT:
      SSH_NOTREACHED;
      break;

    case SSH_ENGINE_ST_FW_ROUTE_TN_DST:
    case SSH_ENGINE_ST_FL_ROUTE_TN_DST:
      /* Get the index of the next hop entry. */
      i = pc->u.rule.next_hop_index_dst;

      /* Obtain pointer to the next hop entry, and sanity check it. */
      c_nh = SSH_ENGINE_GET_NH(engine, i);
      d_nh = FASTPATH_GET_NH(engine->fastpath, i);
      SSH_ASSERT(d_nh->flags & SSH_ENGINE_NH_EMBRYONIC);
      SSH_ASSERT(c_nh->refcnt > 0);

      /* Save new information in the next hop node. */
      SSH_DEBUG(SSH_D_MIDOK,
                ("Creating forward ethernet header: dst=%@ src=%@ type=%04x",
                 ssh_etheraddr_render, dst,
                 ssh_etheraddr_render, src,
                 (unsigned int) ethertype));
      d_nh->media_hdr_len = (SshUInt8)
	ssh_engine_make_media_header(pc->u.rule.to_mediatype,
				     src, dst, ethertype,
				     d_nh->mediahdr,
				     &min_packet_len,
				     &protocol);
      break;

    case SSH_ENGINE_ST_FW_ROUTE_TN_SRC:
    case SSH_ENGINE_ST_TL_ROUTE_TN_SRC:
      /* Get the index of the next hop entry. */
      i = pc->u.rule.next_hop_index_src;

      /* Obtain pointer to the next hop entry, and sanity check it. */
      c_nh = SSH_ENGINE_GET_NH(engine, i);
      d_nh = FASTPATH_GET_NH(engine->fastpath, i);
      SSH_ASSERT(d_nh->flags & SSH_ENGINE_NH_EMBRYONIC);
      SSH_ASSERT(c_nh->refcnt > 0);

      /* Save new information in the next hop node. */
      SSH_DEBUG(SSH_D_MIDOK,
                ("Creating reverse ethernet header: dst=%@ src=%@ type=%04x",
                 ssh_etheraddr_render, dst,
                 ssh_etheraddr_render, src,
                 (unsigned int) ethertype));
      d_nh->media_hdr_len = (SshUInt8)
	ssh_engine_make_media_header(pc->u.rule.to_mediatype,
				     src, dst, ethertype,
				     d_nh->mediahdr,
				     &min_packet_len,
				     &protocol);
      break;

    case SSH_ENGINE_ST_TL_ROUTE_SRC:
      /* Get the index of the next hop entry. */
      i = pc->u.rule.next_hop_index_dst;

      /* Obtain pointer to the next hop entry, and sanity check it. */
      c_nh = SSH_ENGINE_GET_NH(engine, i);
      d_nh = FASTPATH_GET_NH(engine->fastpath, i);
      SSH_ASSERT(d_nh->flags & SSH_ENGINE_NH_EMBRYONIC);
      SSH_ASSERT(c_nh->refcnt > 0);

      /* Save new information in the next hop node. */
      SSH_DEBUG(SSH_D_MIDOK,
                ("Creating forward ethernet header: dst=%@ src=%@ type=%04x",
                 ssh_etheraddr_render, src,
                 ssh_etheraddr_render, dst,
                 (unsigned int) ethertype));
      d_nh->media_hdr_len = (SshUInt8)
	ssh_engine_make_media_header(pc->u.rule.to_mediatype,
				     dst, src, ethertype,
				     d_nh->mediahdr,
				     &min_packet_len,
				     &protocol);
      break;

    case SSH_ENGINE_ST_FL_ROUTE_DST:
      /* Get the index of the next hop entry. */
      i = pc->u.rule.next_hop_index_src;

      /* Obtain pointer to the next hop entry, and sanity check it. */
      c_nh = SSH_ENGINE_GET_NH(engine, i);
      d_nh = FASTPATH_GET_NH(engine->fastpath, i);
      SSH_ASSERT(d_nh->flags & SSH_ENGINE_NH_EMBRYONIC);
      SSH_ASSERT(c_nh->refcnt > 0);

      /* Save new information in the next hop node. */
      SSH_DEBUG(SSH_D_MIDOK,
                ("Creating reverse ethernet header: dst=%@ src=%@ type=%04x",
                 ssh_etheraddr_render, src,
                 ssh_etheraddr_render, dst,
                 (unsigned int) ethertype));
      d_nh->media_hdr_len = (SshUInt8)
	ssh_engine_make_media_header(pc->u.rule.to_mediatype,
				     dst, src, ethertype,
				     d_nh->mediahdr,
				     &min_packet_len,
				     &protocol);
      break;

    case SSH_ENGINE_ST_LOOPBACK:
      SSH_NOTREACHED;
      break;

    case SSH_ENGINE_ST_FINAL:
      SSH_NOTREACHED;
      break;
    }

  /* Perform final initialization for the next-hop node. */
  if (c_nh != NULL)
    {
      SSH_ASSERT(d_nh != NULL);
      d_nh->min_packet_len = (SshUInt8) min_packet_len;
      d_nh->media_protocol =
	(protocol != SSH_PROTOCOL_OTHER) ? protocol : pc->pp->protocol;

      /* The next-hop node is now valid. */
      d_nh->flags &= ~SSH_ENGINE_NH_EMBRYONIC;
      d_nh->flags |= SSH_ENGINE_NH_VALID;

      FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
    }





  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Continue rule execution by setting the next state. */
  ssh_engine_execute_rule_next_state(engine, pc);
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* This is called during flow creation when a route lookup completes.
   This looks up (or creates) a next hop entry for the next hop gateway.  If
   a new one needs to be created, this does an ARP lookup.  Otherwise this
   just increments the reference count of an existing entry for the next
   hop gateway and uses the same entry.  This (or a function called from this)
   calls ssh_engine_execute_rule_step when done. */

void ssh_engine_execute_rule_route_cb(SshEngine engine,
                                      SshUInt32 flags,
                                      const SshIpAddr dst,
                                      const SshIpAddr next_hop_gw,
                                      SshEngineIfnum ifnum,
                                      size_t mtu,
                                      void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshInterceptorInterface *ifp = NULL;
  SshEngineRuleExecuteError error;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt32 i;
  SshEngineNextHopControl c_nh = NULL;
  SshEngineNextHopData d_nh = NULL;
  SshEngineIfnum nh_ifnum;
  SshUInt32 nh_flags = 0;         /* Initialized to keep compiler quiet. */
  Boolean nh_create = TRUE;
  SshIpAddr next_hop_ip = NULL;   /* Initialized to keep compiler quiet. */
  SshIpAddr src_ip = NULL;
  unsigned char iface_media_addr[SSH_ETHERH_ADDRLEN];
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_MIDOK, ("Processing route result for state `%s'",
                          ssh_engine_rule_state_names[pc->u.rule.state]));

  /* If the destination is not reachable, report failure. */
  if (!(flags & SSH_PME_ROUTE_REACHABLE))
    {
      SSH_DEBUG(SSH_D_FAIL, ("host not reachable"));
      error = SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;

      if ((pc->rule != NULL)
          && (pc->flags & SSH_ENGINE_PC_REROUTE_FLOW) == 0)
	error = SSH_ENGINE_RULE_EXECUTE_ERROR_SEND_ICMP;

      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ROUTEDROP);
      ssh_engine_execute_rule_step(pc, error);
      return;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("flags=0x%x, dst=%@ nexthop=%@, ifnum=%d, mtu=%d",
                          (int)flags,
                          ssh_ipaddr_render, dst,
                          ssh_ipaddr_render, next_hop_gw,
                          (int)ifnum, (int)mtu));

  /* Grab interface lock, lookup outgoing interface and fetch interface MTU.
     Use interface MTU if the engine is going to do IPsec transform towards
     the routed destination, as in this case we do not want to utilize the
     PMTU information from system stack but rely on the PMTU information
     in the transform object. If no IPsec transform is performed then use
     the route MTU, but check that it is not larger than interface MTU. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
  if (ifp != NULL)
    {
      size_t ifmtu = 0; 

      /* Prefer always IPv4 in MTU selection
	 (i.e. dst is not defined / does not exist). */
      if (pc->pp->flags & SSH_ENGINE_P_TOLOCAL)
	{
	  ifmtu = 
	    SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_protocol,
					   (dst ? SSH_IP_IS6(dst) : FALSE));
	}
      else
	{
	  ifmtu = 
	    SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter,
					   (dst ? SSH_IP_IS6(dst) : FALSE));
	}
      
      if (mtu == 0 || ifmtu < mtu 
	  || (pc->u.rule.route_selector & 
	      SSH_INTERCEPTOR_ROUTE_KEY_FLAG_TRANSFORM_APPLIED))
	mtu = ifmtu;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      memcpy(iface_media_addr, ifp->media_addr, sizeof(iface_media_addr));
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    }

  /* Store routing information based on the current state.  If control
     does not return from within this switch, the block is called with
     interfaces lock held, and shall release that lock and take flow
     control table lock. However for IP only interceptor the flow
     control lock must not be after the switch. */
  switch (pc->u.rule.state)
    {
#ifdef SSHDIST_IPSEC_FIREWALL
    case SSH_ENGINE_ST_ROUTE_APPGW:
      pc->u.rule.ifnum_appgw = ifnum;

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->u.rule.mtu_appgw = mtu;
      pc->u.rule.local_appgw = (flags & SSH_PME_ROUTE_LOCAL) != 0;
      ssh_kernel_mutex_unlock(engine->interface_lock);
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      if (ifp != NULL)
        {
          if (pc->pp->flags & SSH_ENGINE_P_TOLOCAL)
            pc->u.rule.to_mediatype = ifp->to_protocol.media;
          else
            pc->u.rule.to_mediatype = ifp->to_adapter.media;
        }
      if (ifp == NULL
          || pc->u.rule.to_mediatype == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);
          SSH_DEBUG(SSH_D_FAIL, ("Invalid appgw destination interface %d",
                                 (int) ifnum));
	  goto error;
        }
      ssh_kernel_mutex_unlock(engine->interface_lock);

      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      /* Lookup or create a next-hop node for the destination. */
      next_hop_ip = next_hop_gw;
      c_nh =
	ssh_engine_lookup_nh_node(engine, NULL, next_hop_ip,
				  (flags & SSH_PME_ROUTE_LOCAL
				   ? (SSH_ENGINE_NH_INBOUND
				      | SSH_ENGINE_NH_LOCAL)
				   : (pc->pp->flags & SSH_ENGINE_P_FROMLOCAL
				      ? SSH_ENGINE_NH_OUTBOUND
				      : 0)),
				  ifnum, pc->u.rule.to_mediatype, mtu, &i);
      if (c_nh == NULL)
        {
          /* Operation failed.  The lookup function has already
             reported the error with SSH_DEBUG. */
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
	  goto error;
        }
      /* We have now allocated the slot `i' in the next-hop table.
         The variable `nh' points to that node. */
      pc->u.rule.next_hop_index_appgw = i;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      break;

      /* Route the original IP address prior to redirection. This
         is needed in the appgw_ifnum / gw_ip assignment later on
         for redirects to the local stack. Record the ifnum
         and exit immediately without considering anything else. */

    case SSH_ENGINE_ST_ROUTE_APPGW_REDIRECT:
      /* Cache the original destination ifnum for later use. */
      pc->u.rule.ifnum_dst_orig = ifnum;
      ssh_kernel_mutex_unlock(engine->interface_lock);
      ssh_engine_execute_rule_next_state(engine, pc);
      return;

    case SSH_ENGINE_ST_ROUTE_APPGW_DONE:
      SSH_NOTREACHED;
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto error;
#endif /* SSHDIST_IPSEC_FIREWALL */
      
    case SSH_ENGINE_ST_INIT:
      SSH_NOTREACHED;
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto error;

    case SSH_ENGINE_ST_FW_ROUTE_TN_DST:
    case SSH_ENGINE_ST_TL_ROUTE_SRC:
    case SSH_ENGINE_ST_FL_ROUTE_TN_DST:
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
      if (SSH_IP_EQUAL(&pc->u.rule.appgw_orig_dst, &pc->dst))
        pc->u.rule.ifnum_dst_orig = ifnum;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

      pc->u.rule.ifnum_dst = ifnum;

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      if (pc->u.rule.state == SSH_ENGINE_ST_FW_ROUTE_TN_DST)
        {
          pc->u.rule.local_dst = (flags & SSH_PME_ROUTE_LOCAL ? TRUE : FALSE);
          pc->u.rule.mtu_dst = mtu;
        }
      else
        {
          pc->u.rule.local_dst = ((pc->pp->flags & SSH_ENGINE_P_TOLOCAL)
                                  ? TRUE : FALSE);
          pc->u.rule.mtu_dst = mtu;
        }
      ssh_kernel_mutex_unlock(engine->interface_lock);
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      if (ifp != NULL)
        {
          if (pc->pp->flags & SSH_ENGINE_P_TOLOCAL)
            pc->u.rule.to_mediatype = ifp->to_protocol.media;
          else
            pc->u.rule.to_mediatype = ifp->to_adapter.media;
        }
      if (ifp == NULL
          || pc->u.rule.to_mediatype == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid destination interface %d "
                                 "(ifp %p) type %d",
                                 (int) ifnum, ifp,
                                 (int)pc->u.rule.to_mediatype));

          ssh_kernel_mutex_unlock(engine->interface_lock);
	  goto error;
        }
      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* Lookup or create a next-hop node for the destination. */      
      nh_flags = 0;
      if (pc->u.rule.route_selector & 
	  SSH_INTERCEPTOR_ROUTE_KEY_FLAG_TRANSFORM_APPLIED)
	nh_flags |= SSH_ENGINE_NH_TRANSFORM_APPLIED;

      switch (pc->u.rule.state)
        {
        case SSH_ENGINE_ST_TL_ROUTE_SRC:
          nh_flags |= (SSH_ENGINE_NH_INBOUND | SSH_ENGINE_NH_LOCAL);
          next_hop_ip = &pc->dst;
          src_ip = &pc->src;
          break;

        case SSH_ENGINE_ST_FL_ROUTE_TN_DST:
        case SSH_ENGINE_ST_FW_ROUTE_TN_DST:
          nh_flags |= (pc->u.rule.state == SSH_ENGINE_ST_FW_ROUTE_TN_DST
		       ? 0 : SSH_ENGINE_NH_OUTBOUND);
          next_hop_ip = next_hop_gw;
          if (pc->rule &&
              (pc->rule->type == SSH_ENGINE_RULE_TRIGGER
               && pc->rule->transform_index == SSH_IPSEC_INVALID_INDEX
               && (pc->rule->flags & SSH_ENGINE_NO_FLOW) == 0)
              && (pc->flags & SSH_ENGINE_PC_REROUTE_FLOW) == 0)
            nh_create = FALSE;
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      ssh_kernel_mutex_lock(engine->flow_control_table_lock);

      c_nh = NULL;
      if (nh_create == TRUE)
        {
          c_nh = ssh_engine_lookup_nh_node(engine, NULL, next_hop_ip,
					   nh_flags, ifnum,
					   pc->u.rule.to_mediatype, mtu, &i);
          if (c_nh == NULL)
            {
              /* Operation failed.  The lookup function has already
                 reported the error with SSH_DEBUG. */
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
	      goto error;
            }
          /* We have now allocated the slot `i' in the next-hop table.
             The variable `nh' points to that node. */
          pc->u.rule.next_hop_index_dst = i;




	  d_nh = FASTPATH_GET_NH(engine->fastpath, i);
	  d_nh->mtu = mtu;
	  FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
        }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      break;

    case SSH_ENGINE_ST_FW_ROUTE_TN_SRC:
    case SSH_ENGINE_ST_TL_ROUTE_TN_SRC:
    case SSH_ENGINE_ST_FL_ROUTE_DST:
      pc->u.rule.ifnum_src = ifnum;

      /* Do not check the interface number of the packet matches 
	 that of the route when reverse interface filtering is disabled
	 or if the packet has come from a tunnel. */
#ifdef SSH_IPSEC_REVERSE_IFNUM_FILTERING
      /* For appgw flows, the test for the triggering packet has been
         made already. */
      if (pc->pp->ifnum_in != ifnum
          && pc->rule != NULL
          && ((pc->flags & SSH_ENGINE_PC_REROUTE_FLOW) == 0)
          && ((pc->rule->flags & SSH_ENGINE_NO_FLOW) == 0)
	  && pc->tunnel_id == 0)
        {
          /* The state-based filtering of packets requires that the initial
             packet (as all other packets) comes from the interface
             that the route says it has arrived on. */
	  ssh_kernel_mutex_unlock(engine->interface_lock);
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Dropping packet due to ingress filtering."));
	  goto error;
        }
#endif /* SSH_IPSEC_REVERSE_IFNUM_FILTERING */

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->u.rule.local_src = ((pc->pp->flags & SSH_ENGINE_P_FROMLOCAL)
                              ? TRUE : FALSE);
      pc->u.rule.mtu_src = mtu;
      ssh_kernel_mutex_unlock(engine->interface_lock);
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      if (ifp != NULL)
        {
          if (pc->pp->flags & SSH_ENGINE_P_FROMLOCAL)
            pc->u.rule.to_mediatype = ifp->to_protocol.media;
          else
            pc->u.rule.to_mediatype = ifp->to_adapter.media;
        }
      if (ifp == NULL
          || pc->u.rule.to_mediatype == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid source interface %d", (int) ifnum));
          ssh_kernel_mutex_unlock(engine->interface_lock);
	  goto error;
        }

      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* Lookup or create a next-hop node for the destination. */
      nh_flags = 0;
      if (pc->u.rule.route_selector & 
	  SSH_INTERCEPTOR_ROUTE_KEY_FLAG_TRANSFORM_APPLIED)
	nh_flags |= SSH_ENGINE_NH_TRANSFORM_APPLIED;

      switch (pc->u.rule.state)
        {
        case SSH_ENGINE_ST_FW_ROUTE_TN_SRC:
          next_hop_ip = next_hop_gw;
          break;

        case SSH_ENGINE_ST_TL_ROUTE_TN_SRC:
          nh_flags |= SSH_ENGINE_NH_OUTBOUND;
          next_hop_ip = next_hop_gw;
          break;

        case SSH_ENGINE_ST_FL_ROUTE_DST:
          nh_flags |= (SSH_ENGINE_NH_INBOUND | SSH_ENGINE_NH_LOCAL);
          next_hop_ip = &pc->src;
          break;

        default:
          SSH_NOTREACHED;
	  goto error;
        }

      ssh_kernel_mutex_lock(engine->flow_control_table_lock);




      c_nh = ssh_engine_lookup_nh_node(engine, src_ip, next_hop_ip, nh_flags,
				       ifnum, pc->u.rule.to_mediatype,
				       mtu, &i);
      if (c_nh == NULL)
        {
          /* Operation failed.  The lookup function has already
             reported the error with SSH_DEBUG. */
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
	  goto error;
        }

      /* We have now allocated the slot `i' in the next-hop table.
         The variable `nh' points to that node. */
      pc->u.rule.next_hop_index_src = i;

      d_nh = FASTPATH_GET_NH(engine->fastpath, i);
      d_nh->mtu = mtu;
      FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      break;

    case SSH_ENGINE_ST_LOOPBACK:
      SSH_NOTREACHED;
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto error;

    case SSH_ENGINE_ST_FINAL:
      SSH_NOTREACHED;
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto error;
    }

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Set the next state and continue rule exeuction. */
  ssh_engine_execute_rule_next_state(engine, pc);
  return;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* If we are not creating a next hop node, then skip the rest */
  if (c_nh == NULL)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      ssh_engine_execute_rule_next_state(engine, pc);
      return;
    }

  /* The theoretical maximum value for a next hop reference count is
     twice the flow table size (one reference for each direction) plus
     three times the number of packets being concurrently
     processed. */
  SSH_ASSERT(c_nh->refcnt
             <= (2 * engine->flow_table_size
                 + 3 * SSH_ENGINE_MAX_PACKET_CONTEXTS));

  d_nh = FASTPATH_GET_NH(engine->fastpath, i);

  if (d_nh->flags & SSH_ENGINE_NH_REROUTE)
    {
      d_nh->flags &= ~(SSH_ENGINE_NH_REROUTE|SSH_ENGINE_NH_VALID);
      d_nh->flags |= SSH_ENGINE_NH_EMBRYONIC;
    }
  if (d_nh->flags & SSH_ENGINE_NH_VALID)
    {
      FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      ssh_engine_execute_rule_next_state(engine, pc);
      return;
    }
  SSH_ASSERT(d_nh->flags & SSH_ENGINE_NH_EMBRYONIC);

  /* If the interface takes plain packets (without a media header), then
     complete the operation without performing an ARP lookup. */
  if (pc->u.rule.to_mediatype == SSH_INTERCEPTOR_MEDIA_PLAIN)
    {
      d_nh->media_hdr_len = 0;
      d_nh->min_packet_len = 0;
      d_nh->media_protocol = SSH_PROTOCOL_OTHER;

      d_nh->flags &= ~SSH_ENGINE_NH_EMBRYONIC;
      d_nh->flags |= SSH_ENGINE_NH_VALID;




      FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      SSH_DEBUG(SSH_D_LOWOK, ("plain interface, resuming execute rule"));
      ssh_engine_execute_rule_next_state(engine, pc);
      return;
    }

  /* Don't perform ARP lookups for the null-address, for DHCP server's
     reply packets, for local addresses, and for IPv6 router
     advertisement packets (the
     server can be replying with client's new IP address that is
     assigned with this packet - therefore the client can't reply to
     our ARPs and the packet would never go out). */
  if (SSH_IP_IS_NULLADDR(next_hop_gw)
      || ((d_nh->flags & SSH_ENGINE_NH_LOCAL)
          && pc->u.rule.state == SSH_ENGINE_ST_TL_ROUTE_SRC
          && (SSH_IP_IS_MULTICAST(next_hop_ip)
              || SSH_IP_IS_BROADCAST(next_hop_ip)))
      || ((pc->u.rule.state == SSH_ENGINE_ST_FL_ROUTE_DST
           || pc->u.rule.state == SSH_ENGINE_ST_FL_ROUTE_TN_DST)
          && SSH_IP_EQUAL(next_hop_gw, &pc->dst)
          && pc->ipproto == SSH_IPPROTO_UDP
          && pc->u.rule.src_port == 67
          && pc->u.rule.dst_port == 68)
      || (SSH_IP_IS6(next_hop_gw)
          && pc->ipproto == SSH_IPPROTO_IPV6ICMP
          && pc->icmp_type == SSH_ICMP6_TYPE_ROUTER_ADVERTISEMENT))
    {
      SshEnginePacketData pd;
      unsigned char src_addr[SSH_ETHERH_ADDRLEN];
      unsigned char dst_addr[SSH_ETHERH_ADDRLEN];

      SSH_DEBUG(SSH_D_LOWOK,
                ("Taking media addresses from packet/interfaces for %s "
                 "`%@.%d > %@.%d'",
                 ((pc->ipproto == SSH_IPPROTO_UDP
                   && pc->u.rule.src_port == 67
                   && pc->u.rule.dst_port == 68)
                  ? "DHCP reply"
                  : (pc->ipproto == SSH_IPPROTO_IPV6ICMP
                     ? "IPv6 packet"
                     : "null-destination/local packet")),
                 ssh_ipaddr_render, &pc->src,
                 (int) pc->u.rule.src_port,
                 ssh_ipaddr_render, &pc->dst,
                 (int) pc->u.rule.dst_port));

      /* Check if the packet contains a cached media address. */
      SSH_ASSERT(pc->pp != NULL);
      pd = SSH_INTERCEPTOR_PACKET_DATA(pc->pp, SshEnginePacketData);

      /* A next hop node is being made for 'next_hop_ip' */
      if (d_nh->flags & SSH_ENGINE_NH_LOCAL)
        {
          memcpy(dst_addr, iface_media_addr, sizeof(dst_addr));

          if (pd->media_protocol != d_nh->media_protocol)
            memset(src_addr, 255, sizeof(src_addr));
          else
            memcpy(src_addr, pd->mediahdr + SSH_ETHERH_OFS_SRC,
                   SSH_ETHERH_ADDRLEN);
        }

      if (pd->media_protocol != d_nh->media_protocol)
        {
          /* No luck.  Just make the destination address the ethernet
             broadcast address and use the interface's media address
             as the source address. */
          memset(dst_addr, 255, sizeof(dst_addr));
	  memcpy(src_addr, iface_media_addr, sizeof(src_addr));
        }
      else
        {
          /* Found it from the packet. */
          memcpy(src_addr, pd->mediahdr + SSH_ETHERH_OFS_SRC,
                 SSH_ETHERH_ADDRLEN);
          memcpy(dst_addr, pd->mediahdr + SSH_ETHERH_OFS_DST,
                 SSH_ETHERH_ADDRLEN);
        }

      /* Release the lock. */
      FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* And complete the ARP by hand. */
      if (nh_flags & SSH_ENGINE_NH_INBOUND)
        /* The `to-local route source' and `from-local route
           destination' will do the arp query for the reverse
           direction.  Therefore, we must swap the source and
           destination media addresses when we take them directly from
           the original forward direction packet. */
        ssh_engine_execute_rule_arp_cb(pc, dst_addr, src_addr,
                                       (SSH_IP_IS6(next_hop_gw)
                                        ? SSH_ETHERTYPE_IPv6
                                        : SSH_ETHERTYPE_IP));
      else
        /* Pass the packet's source and destination media addresses
           as-is to the ARP callback. */
        ssh_engine_execute_rule_arp_cb(pc, src_addr, dst_addr,
                                       (SSH_IP_IS6(next_hop_gw)
                                        ? SSH_ETHERTYPE_IPv6
                                        : SSH_ETHERTYPE_IP));
      return;
    }
  nh_ifnum = d_nh->ifnum;

  /* Release the lock. */
  FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_LOWOK, ("about to perform arp lookup"));

  /* We must perform ARP to obtain the media address for the node.
     Note that we perform ARP lookup for the route's `next_hop_gw',
     not for the next-hop node's destination. */
  ssh_engine_arp_lookup(pc, next_hop_gw, nh_ifnum,
                        ssh_engine_execute_rule_arp_cb);

  return;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  SSH_NOTREACHED;

 error:
  ssh_engine_execute_rule_step(pc, SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE);
  return;
}

#ifdef SSHDIST_IPSEC_NAT

#ifdef SSHDIST_IPSEC_FIREWALL
/* Helper function that does actual address selection between
   nat_ip_low and nat_ip_high, depending on source address and flags. */
static void engine_nat_select_address(SshIpAddr nat_ip_out,
                     SshIpAddr orig_ip,
                     unsigned char rule_ip_c[SSH_IP_ADDR_SIZE],
	             SshInterceptorProtocol protocol,
                     SshIpAddr nat_ip_low,
                     SshIpAddr nat_ip_high,
                     Boolean do_one_to_one)
{
  if (!SSH_IP_DEFINED(nat_ip_low))
  {
     /* No mapping defined. */
      SSH_DEBUG(SSH_D_MIDOK, ("engine_nat_select_address called without"
                              " target NAT ip addresses"));
     return;
  }
 
  if (SSH_IP_CMP(nat_ip_low,nat_ip_high)==0)
    {
      /* Only single address in the range => 
         we'll just use that... */
      *nat_ip_out = *nat_ip_low;

      SSH_DEBUG(SSH_D_MIDOK, ("NAT-Select: Successfully mapped %@ to %@.",
			      ssh_ipaddr_render, orig_ip,
			      ssh_ipaddr_render, nat_ip_out));
      return;
    }
  
  if (do_one_to_one)
    {
      /* Direct one-to-one mapping, calculate the mapping. */
      SshXUInt128 distance128;
      SshXUInt128 nat_orig128;
      SshXUInt128 nat_target128;
      SshIpAddrStruct rule_ip;
  
      if (protocol == SSH_PROTOCOL_IP4)
        SSH_IP4_DECODE(&rule_ip, rule_ip_c);
      else
        {
          SSH_ASSERT(protocol == SSH_PROTOCOL_IP6);
          SSH_IP6_DECODE(&rule_ip, rule_ip_c);
        }

      SSH_XUINT128_FROM_IP(nat_orig128, &rule_ip);
      SSH_XUINT128_FROM_IP(nat_target128, nat_ip_low);
      SSH_XUINT128_SUB(distance128,
                       nat_target128,
                       nat_orig128);

      ssh_engine_ipaddr_add_128(nat_ip_out,
                                orig_ip,
                                distance128);

      SSH_DEBUG(SSH_D_MIDOK, ("NAT-Select: Successfully mapped %@ to %@ "
			      "from [%@-%@] (one-to-one). Distance=~0x%x.",
			      ssh_ipaddr_render, orig_ip,
			      ssh_ipaddr_render, nat_ip_out,
			      ssh_ipaddr_render, nat_ip_low,
			      ssh_ipaddr_render, nat_ip_high,
                              SSH_XUINT128_TO_UINT32_SATURATED(distance128)));

      /* Make sure result of NAT is inside nat target area
	 as defined in the rule. */
      SSH_ASSERT(SSH_IP_CMP(nat_ip_low,nat_ip_out) <= 0);
      SSH_ASSERT(SSH_IP_CMP(nat_ip_high,nat_ip_out) >= 0);      
    }
  else
    {
      /* Need to use hashing to find the mapping. */
      SshXUInt128 temp128;
      SshUInt32 scaler;
      SshUInt32 hash;
      ssh_engine_ipaddr_subtract_128(nat_ip_high,
                                     nat_ip_low,
                                     temp128);

      scaler = SSH_XUINT128_TO_UINT32_SATURATED(temp128);

      scaler++;
      hash = SSH_IP_HASH(orig_ip);

      /* Scale unless there is 32-bits (or more)
         available address space to use. */
      if (scaler) hash %= scaler;
      
      /* Build resulting address */
      SSH_XUINT128_BUILD(temp128, hash, 0, 0, 0);
      ssh_engine_ipaddr_add_128(nat_ip_out,
                                nat_ip_low,
                                temp128);

      SSH_DEBUG(SSH_D_MIDOK, ("NAT-Select: Successfully mapped %@ to %@ "
			      "from [%@-%@].",
			      ssh_ipaddr_render, orig_ip,
			      ssh_ipaddr_render, nat_ip_out,
			      ssh_ipaddr_render, nat_ip_low,
			      ssh_ipaddr_render, nat_ip_high ));

      /* Make sure result of NAT is inside nat target area
	 as defined in the rule. */
      SSH_ASSERT(SSH_IP_CMP(nat_ip_low,nat_ip_out) <= 0);
      SSH_ASSERT(SSH_IP_CMP(nat_ip_high,nat_ip_out) >= 0);
    }
}

/* Helper function to handle user forced nat rules. 
   Returns false if suitable NAT mapping cannot be found. */
static void engine_nat_map(SshEngine engine,
			   SshEnginePolicyRule rule,
			   SshEnginePacketContext pc,
			   SshIpAddr nat_src_ip_out,
			   SshUInt16 *nat_src_port_out,
			   SshIpAddr nat_dst_ip_out,
			   SshUInt16 *nat_dst_port_out,
			   Boolean do_src_nat,
			   Boolean do_dst_nat,
			   SshUInt16 *flow_flags_p,
			   Boolean isicmp,
			   Boolean isipv6,
			   SshPmNatFlags nat_flags)
{
  Boolean do_port_mapping = !isicmp;
  Boolean got_src_port = FALSE;
  /* ICMP is a special case on port issue, as srcport 
     is always ICMP ID, and we'll keep that. */

  if (isicmp)
    *nat_dst_port_out = *nat_src_port_out;

  if (do_src_nat == 0 && do_dst_nat == 0) return;
      
  /* NAT to the fixed port (given in the rule). */

  if (do_src_nat)
    {
      engine_nat_select_address(nat_src_ip_out,
                                &pc->src,
                                rule->src_ip_low,
                                rule->protocol,
                                &(rule->nat_src_ip_low),
                                &(rule->nat_src_ip_high),
                                !!(rule->nat_flags & 
                                   SSH_PM_NAT_ONE_TO_ONE_SRC));
    }

  if (do_dst_nat)
    {
      engine_nat_select_address(nat_dst_ip_out,
                                &(pc->dst),
                                rule->dst_ip_low,
                                rule->protocol,
                                &(rule->nat_dst_ip_low),
                                &(rule->nat_dst_ip_high),
                                !!(rule->nat_flags & 
                                   SSH_PM_NAT_ONE_TO_ONE_DST));
    }

  if (do_port_mapping)
    {
      if (do_src_nat && rule->nat_src_port)
	{
	  *nat_src_port_out = rule->nat_src_port;
	}
      else
	{
	  /* Try to keep current port unless disallowed by the flags. */
	  if (do_dst_nat && rule->nat_dst_port)
	    *nat_dst_port_out = rule->nat_dst_port;
	  if (!(rule->nat_flags & SSH_PM_NAT_NO_TRY_KEEP_PORT))
	    {
	      got_src_port = 
		ssh_engine_get_random_port(engine,
					   !(rule->nat_flags & 
					     SSH_PM_NAT_SHARE_PORT_SRC),
					   isipv6, 0,
					   nat_src_ip_out,
					   NULL,
					   *nat_src_port_out,
					   *nat_src_port_out,
					   NULL, 0,
					   NULL, nat_src_port_out);
	    }
	  /* Get suitable NAT source port according to nat_flags given. */
	  if (!got_src_port)
	    {
	      got_src_port = 
		ssh_engine_get_random_port(engine,
					   !!(rule->nat_flags & 
					     SSH_PM_NAT_NO_SHARE_PORT_DST),
					   isipv6, 0,
					   nat_src_ip_out,
					   NULL,
					   (rule->nat_flags & 
					    SSH_PM_NAT_KEEP_PORT)?
					   *nat_src_port_out: 0,
					   *nat_src_port_out,
					   NULL, 0,
					   NULL, nat_src_port_out);
	    }
	  if (!got_src_port)
	    {
	      /* NAT Mapping failed. */
	      *flow_flags_p = 0xffff;
	      SSH_DEBUG(SSH_D_FAIL, ("NAT mapping failed: %@:%u->%@:%u"
				     "to %@:??? %@:%u (f=0x%x)",
				     ssh_ipaddr_render, &pc->src,
				     (unsigned int)pc->u.rule.src_port,
				     ssh_ipaddr_render, &pc->dst,
				     (unsigned int)pc->u.rule.dst_port,
				     ssh_ipaddr_render, nat_src_ip_out, 
				     ssh_ipaddr_render, nat_dst_ip_out,
				     (unsigned int)*nat_dst_port_out,
				     nat_flags));
	      return;
	    }
	  /* If source port translation done => mark it in flow. */
	  if (pc->u.rule.src_port != *nat_src_port_out)
	    do_src_nat = 1;
	}
    }
  *flow_flags_p |= (do_src_nat? SSH_ENGINE_FLOW_D_NAT_SRC: 0) |
                   (do_dst_nat? SSH_ENGINE_FLOW_D_NAT_DST: 0);
}
#endif /* SSHDIST_IPSEC_FIREWALL */

/* Allocates a NAT mapping for the given connection.  This modifies the
   IP addresses and ports from their before-NAT values to their after-NAT
   values.  This returns 0 if no NAT is to be performed, a combination
   of the SSH_ENGINE_FLOW_D_NAT* flags if NAT should be performed, and
   0xffff if an error occurred and the packet should be dropped.
   This should be called with engine->flow_control_table_lock held.  This sets
   *nat_{src,dst}_{ip,port}_out. If no NAT mapping is performed then
   the values are initialized to the ones in the 'pc' fields. pc->u.rule
   is assumed to be initialized to the state present in ST_FINAL state. */
SshUInt16
ssh_engine_nat_allocate(SshEngine engine,
                        SshEnginePacketContext pc,
                        SshEnginePolicyRule rule,
                        Boolean is_to_tunnel,
                        Boolean is_to_tunnel_nat,
                        Boolean nated_by_pm,
                        SshIpAddr nat_src_ip_out,
                        SshUInt16 *nat_src_port_out,
                        SshIpAddr nat_dst_ip_out,
                        SshUInt16 *nat_dst_port_out)
{
  SshEngineIfInfo srcinfo, dstinfo;
  Boolean src_is_local, dst_is_local, prev_transform_is_nat;
  Boolean isicmp, do_unforced_nat, is_internal_nat, src_is_dst;
  SshUInt16 flow_flags;
  SshInterceptorInterface *ifp_src, *ifp_dst;
  SshPmNatType dst_nat_type;
  SshUInt32 reverse_transform_index;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  *nat_src_ip_out = pc->src;
  *nat_dst_ip_out = pc->dst;
  *nat_src_port_out = pc->u.rule.src_port;
  *nat_dst_port_out = pc->u.rule.dst_port;
  prev_transform_is_nat = FALSE;

  /* Set reverse transform index to the transform that was
     used for decapsulation of the packet. */
  if ((pc->flags & SSH_ENGINE_PC_RESTARTED_OUT) == 0)
    reverse_transform_index = pc->prev_transform_index;
  else
    reverse_transform_index = SSH_IPSEC_INVALID_INDEX;

  /* Check if the `from_tunnel' specifies an option to make NAT-T
     clients unique. */
  prev_transform_is_nat = FALSE;
  is_internal_nat = FALSE;
  if (reverse_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineTransformControl c_trd;
      SshEngineTransformData d_trd;
      
      c_trd = SSH_ENGINE_GET_TRD(engine, reverse_transform_index);
      if (c_trd == NULL)
        /* from_tunnel has been deleted */
        return 0xffff;

      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, 
					 reverse_transform_index);
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      if (d_trd->transform & SSH_PM_IPSEC_INT_NAT)
        is_internal_nat = TRUE;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      if (d_trd->transform & SSH_PM_IPSEC_PORT_NAT)
        prev_transform_is_nat = TRUE;
      FASTPATH_RELEASE_TRD(engine->fastpath, reverse_transform_index);
    }
  /* Do not NAT media broadcast packets. */
  else if (pc->pp->flags & SSH_PACKET_MEDIABCAST)
    return 0;

  /* If we are either the recipient or the sender of the packet, then
     don't NAT. */
  src_is_local = ssh_engine_ip_is_local(engine, &pc->src);
  if (ssh_engine_ip_is_local(engine, &pc->dst)
      || ssh_engine_ip_is_broadcast(engine, &pc->dst))
    dst_is_local = TRUE;
  else
    dst_is_local = FALSE;

  /* Check whether packet is destined to local host */
  if ((pc->u.rule.ifnum_src == pc->u.rule.ifnum_dst
       && (dst_is_local || src_is_local))
      && is_internal_nat == FALSE
      && (rule == NULL
          || (rule->flags &
              (SSH_ENGINE_RULE_FORCE_NAT_SRC|SSH_ENGINE_RULE_FORCE_NAT_DST))
          == 0))
    return 0;

  ssh_kernel_mutex_lock(engine->interface_lock);

  ifp_src = ssh_ip_get_interface_by_ifnum(&engine->ifs, pc->u.rule.ifnum_src);
  ifp_dst = ssh_ip_get_interface_by_ifnum(&engine->ifs, pc->u.rule.ifnum_dst);

  /* Sanity check the interface numbers. */
  if (ifp_src == NULL || ifp_dst == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum_dst=%d ifnum_src=%d",
                             (int)pc->u.rule.ifnum_dst,
                             (int)pc->u.rule.ifnum_src));
      return 0xffff;
    }

  /* Get interface NAT information. */
  srcinfo = (SshEngineIfInfo) ifp_src->ctx_user;
  dstinfo = (SshEngineIfInfo) ifp_dst->ctx_user;

  SSH_ASSERT(srcinfo != NULL && dstinfo != NULL);

  src_is_dst = (srcinfo == dstinfo);
  dst_nat_type = dstinfo->nat_type;
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Check if we need NAT */
  if (!((rule != NULL
         && ((rule->flags &
              (SSH_ENGINE_RULE_FORCE_NAT_SRC|SSH_ENGINE_RULE_FORCE_NAT_DST))
             != 0))
        ||
        (((reverse_transform_index == SSH_IPSEC_INVALID_INDEX
           && is_to_tunnel == FALSE)
          || (reverse_transform_index != SSH_IPSEC_INVALID_INDEX
              && prev_transform_is_nat)
          || (reverse_transform_index == SSH_IPSEC_INVALID_INDEX
              && is_to_tunnel == TRUE
              && is_to_tunnel_nat))
         && dst_nat_type == SSH_PM_NAT_TYPE_PORT)
        || is_internal_nat == TRUE))
    return 0;

  isicmp = (pc->ipproto == SSH_IPPROTO_ICMP
#if defined (WITH_IPV6)
            || pc->ipproto == SSH_IPPROTO_IPV6ICMP
#endif /* WITH_IPV6 */
            );

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL

  /* Check if the `from_tunnel' specifies an option to make NAT-T
     clients unique. */
  if (is_internal_nat)
    {
#ifdef DEBUG_LIGHT
      SshIpAddrStruct orig_src = pc->src;
#endif /* DEBUG_LIGHT */

      /* Try to allocate an IP address from the internal NAT
         pool. */
      if (ssh_engine_get_internal_nat_ip(engine, nat_src_ip_out))
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Internal NAT from %@->%@",
                                   ssh_ipaddr_render, &orig_src,
                                   ssh_ipaddr_render, nat_src_ip_out));
          return SSH_ENGINE_FLOW_D_NAT_SRC;
        }

      /* No addresses left in the pool. */
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate IP address for the "
                             "internal NAT"));
      return 0xffff;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  flow_flags = 0;

  /* NAT is performed:
     - from_tunnel == null && to_tunnel == null
     - from_tunnel != null && from_transform_is_nat
     - from_tunnel == null && to_tunnel != null && to_transform_is_nat
     - A source NAT is configured for the destination interface
  */

  do_unforced_nat = FALSE;
  if ((reverse_transform_index == SSH_IPSEC_INVALID_INDEX
       && is_to_tunnel == FALSE)
      || (reverse_transform_index != SSH_IPSEC_INVALID_INDEX
          && prev_transform_is_nat)
      || (reverse_transform_index == SSH_IPSEC_INVALID_INDEX
          && is_to_tunnel == TRUE
          && is_to_tunnel_nat))
    do_unforced_nat = TRUE;

#ifdef SSHDIST_IPSEC_FIREWALL
  if (rule != NULL && 
      (rule->flags & (SSH_ENGINE_RULE_FORCE_NAT_SRC |
                      SSH_ENGINE_RULE_FORCE_NAT_DST)))
    {
      /* NAT to the fixed port (if given in the rule). 
         Either source or destination NAT. */

      engine_nat_map(engine, rule, pc,
		     nat_src_ip_out,
		     nat_src_port_out,
		     nat_dst_ip_out,
		     nat_dst_port_out,
		     !!(rule->flags & SSH_ENGINE_RULE_FORCE_NAT_SRC),
		     !nated_by_pm &&
		     !!(rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST),
		     &flow_flags,
		     isicmp,
		     pc->pp->protocol == SSH_PROTOCOL_IP6,
		     rule->nat_flags);

      if (flow_flags == 0xffff)
        return 0xffff;
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
  if ((rule == NULL || 
       !(rule->flags & SSH_ENGINE_RULE_FORCE_NAT_SRC)) &&
      do_unforced_nat)
    flow_flags |= ssh_engine_nat_get_mapping(engine,
                                             pc->flags,
                                             pc->ipproto,
			                     pc->icmp_type,
                                             TRUE,
                                             pc->u.rule.ifnum_src,
                                             pc->u.rule.ifnum_dst,
                                             &pc->src, &pc->dst,
                                             pc->u.rule.src_port,
                                             pc->u.rule.dst_port,
                                             nat_src_ip_out,
                                             nat_src_port_out,
                                             nat_dst_ip_out,
                                             nat_dst_port_out);

  if (flow_flags == 0xffff)
    return 0xffff;

  /* Only process destination mappings if the policy manager has not already
     provided a destination mapping. */
  if (!nated_by_pm &&
      (rule == NULL || 
       !(rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST)))
    {
        /* If the connection is not going to a tunnel, we can
           safely NAT the destination ip:destination port of the
           connection according to the configuration of the
           source interface. Signal this via the "outbound == FALSE"
           parameter. NAT mappings are not performed for the outbound
           address if srcinfo == dstinfo. */
        if (do_unforced_nat && !src_is_dst)
          flow_flags |= ssh_engine_nat_get_mapping(engine,
                                                   pc->flags,
                                                   pc->ipproto,
						   pc->icmp_type,
						   FALSE,
                                                   pc->u.rule.ifnum_src,
                                                   pc->u.rule.ifnum_dst,
                                                   &pc->src,
                                                   &pc->dst,
                                                   pc->u.rule.src_port,
                                                   pc->u.rule.dst_port,
                                                   nat_src_ip_out,
                                                   nat_src_port_out,
                                                   nat_dst_ip_out,
                                                   nat_dst_port_out);
      if (flow_flags == 0xffff)
        { /* An error occurred in the source-side NAT.  Free any mappings
             allocated for the destination side. */
          return 0xffff;
        }
    }

  return flow_flags;
}
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
/* Determine if a packet is an ok initial packet for a session. */
static  SshEngineProtocolMonitorRet
ssh_engine_is_packet_valid_initial(SshEngine engine, SshEnginePacketContext pc)
{
  unsigned char tcph[SSH_TCP_HEADER_LEN];
  SshUInt16 flags = 0;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Check from protocol monitor whether this is an acceptable
     "session-creation" packet. */
  switch (pc->ipproto)
    {
    case SSH_IPPROTO_TCP:

      if (pc->packet_len < pc->hdrlen + SSH_TCP_HEADER_LEN)
	return SSH_ENGINE_MRET_DROP;

      /* Get TCP header. */
      ssh_interceptor_packet_copyout(pc->pp, pc->hdrlen, tcph,
				     SSH_TCP_HEADER_LEN);
      flags = SSH_TCPH_FLAGS(tcph);
      flags &= 0x3f;

      if (flags == SSH_TCPH_FLAG_SYN)
	return SSH_ENGINE_MRET_PASS;
      else
	return SSH_ENGINE_MRET_REJECT;
      break;

    default:
      return SSH_ENGINE_MRET_PASS;
    }
}
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
/* Initial creation of appgw flows. The flows will not be fully defined
   after this operation. */
Boolean
ssh_engine_create_appgw_mapping_initial(SshEngine engine,
                                        SshEnginePacketContext pc)
{
  SshUInt32 flow_flags, rule_index;
  SshUInt32 initiator_flow_index;
  int level;
  SshIpAddrStruct nat_src, nat_dst;
  SshUInt16 nat_src_port, nat_dst_port;
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  Boolean send_tcp_rst = FALSE;
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
  SshUInt32 reverse_transform_index;

  SSH_INTERCEPTOR_STACK_MARK();

  if ((pc->flags & SSH_ENGINE_PC_RESTARTED_OUT) == 0)
    reverse_transform_index = pc->prev_transform_index;
  else
    reverse_transform_index = SSH_IPSEC_INVALID_INDEX;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Sanity check: only TCP and UDP are currently supported for
     application gateways. */
  SSH_ASSERT(pc->ipproto == SSH_IPPROTO_TCP || pc->ipproto == SSH_IPPROTO_UDP);
  SSH_ASSERT(pc->rule != NULL);
  SSH_ASSERT(pc->pp != NULL);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (pc->u.rule.next_hop_index_appgw != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_engine_decrement_next_hop_refcnt(engine,
                                           pc->u.rule.next_hop_index_appgw);
      pc->u.rule.next_hop_index_appgw = SSH_IPSEC_INVALID_INDEX;
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Initialize freeing_index values and other values accessed in error
     processing. */
  initiator_flow_index = SSH_IPSEC_INVALID_INDEX;
  rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, pc->rule);

  flow_flags = ssh_engine_nat_allocate(engine,
                                       pc,
                                       pc->rule,
                                       (pc->rule->flags
                                        & SSH_PM_ENGINE_RULE_TOTUNNEL
                                        ? TRUE : FALSE),
                                       (pc->rule->flags
                                        & SSH_PM_ENGINE_RULE_TT_NAT)
                                       ? TRUE : FALSE,
                                       FALSE,
                                       &nat_src,
                                       &nat_src_port,
                                       &nat_dst,
                                       &nat_dst_port);
  if (flow_flags == 0xffff)
    goto error;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("NAT result: %@:%d -> %@:%d",
             ssh_ipaddr_render, &nat_src, nat_src_port,
             ssh_ipaddr_render, &nat_dst, nat_dst_port));

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  /* Check from protocol monitor whether this is an acceptable
     "session-creation" packet. */
  switch (ssh_engine_is_packet_valid_initial(engine, pc))
    {
    case SSH_ENGINE_MRET_PASS:
      break;

    case SSH_ENGINE_MRET_REJECT:
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_MONITORDROP);
      send_tcp_rst = TRUE;
      SSH_DEBUG(SSH_D_FAIL, ("flow creation rejected by protocol monitor"));
      goto error;
      break;

    case SSH_ENGINE_MRET_DROP:
    default:
      SSH_DEBUG(SSH_D_FAIL, ("flow creation denied by protocol monitor"));
      goto error;
    }
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
  if ((pc->rule->flags & SSH_ENGINE_RATE_LIMIT)
      && ssh_engine_flow_rate_limit(engine, &pc->src, FALSE))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Appgw flows denied by rate limitation"));
      goto error;
    }
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

  level = ssh_engine_flow_reap_lru_level(engine, pc->u.rule.appgw_rule_index);

  if (ssh_engine_reap_flows(engine, level, 1) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to reap 1 flow with LRU levels at most %d",
                 level));
      goto error;
    }

  /* The purpose of this flow for the moment is to eat up packets
     matching the forward flow id and transform them to triggers
     (and possibly drop them...) */
  if (!ssh_engine_create_flow(engine,
                              rule_index,
                              pc->flow_id,
                              &pc->src,
                              &pc->dst,
                              pc->ipproto,
                              pc->u.rule.src_port,
                              pc->u.rule.dst_port,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                              pc->u.rule.ifnum_dst, pc->u.rule.ifnum_src,
                              pc->u.rule.local_dst, pc->u.rule.local_src,
                              pc->u.rule.mtu_dst, pc->u.rule.mtu_src,
			      pc->u.rule.route_selector_appgw,
			      0,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              pc->u.rule.next_hop_index_dst,
                              pc->u.rule.next_hop_index_src,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              pc->u.rule.ifnum_src,
                              pc->u.rule.ifnum_dst,
                              &nat_src,
                              &nat_dst,
                              nat_src_port,
                              nat_dst_port,
                              pc->protocol_xid,
			      (SSH_ENGINE_FLOW_C_TRIGGER
			       | SSH_ENGINE_FLOW_C_REROUTE_I
			       | SSH_ENGINE_FLOW_C_UNDEFINED),
                              (SSH_ENGINE_FLOW_D_NAT_SRC
                               | SSH_ENGINE_FLOW_D_NAT_DST
                               | SSH_ENGINE_FLOW_D_DROP_PKTS
                               | SSH_ENGINE_FLOW_D_DANGLING),
                              SSH_IPSEC_INVALID_INDEX,
                              reverse_transform_index,
                              SSH_ENGINE_DEFAULT_IDLE_TIMEOUT,
                              0,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                              pc->pp->extension,
#else
			      NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                              &initiator_flow_index))
    goto error;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("created temporary appgw trigger flow %d",
                               (int) initiator_flow_index));

  return TRUE;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("error"));

  if (initiator_flow_index != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_free_flow(engine, initiator_flow_index);
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  else
    {
      if (pc->u.rule.next_hop_index_src != SSH_IPSEC_INVALID_INDEX)
        {
          ssh_engine_decrement_next_hop_refcnt(engine,
                                               pc->u.rule.next_hop_index_src);
          pc->u.rule.next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
        }

      if (pc->u.rule.next_hop_index_dst != SSH_IPSEC_INVALID_INDEX)
        {
          ssh_engine_decrement_next_hop_refcnt(engine,
                                               pc->u.rule.next_hop_index_dst);
          pc->u.rule.next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;
        }
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Unlock. */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  if (send_tcp_rst)
    ssh_engine_send_tcp_rst(engine, pc);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
  return FALSE;
}

/* Finalize creation of an appgw mapping.  This is called from
   ssh_engine_execute_rule_step once the routing lookups have been
   done, if the operation was actually done in order to create the
   mappings for an application gateway.  This will eventually call
   pc->u.rule.appgw_callback, and will free pc. */

void ssh_engine_create_appgw_mapping_final(SshEngine engine,
                                           SshEnginePacketContext pc)
{
  SshIpAddrStruct gw_ip;
  SshUInt16 gw_initiator_port, gw_responder_port;
  SshUInt32 from_responder_tunnel_id;
  SshEngineTransformData trd;
  SshUInt32 initiator_flow_index, responder_flow_index, appgw_flow_index;
  SshUInt32 if_index, rf_index;
  SshUInt32 appgw_flow_generation;
  SshEngineFlowControl ic_flow, rc_flow;
  SshEngineIfnum appgw_ifnum;
  unsigned char from_initiator_flow_id[SSH_ENGINE_FLOW_ID_SIZE];
  unsigned char to_responder_flow_id[SSH_ENGINE_FLOW_ID_SIZE];
  Boolean is_local, nated_by_pm, is_ipv6;
  Boolean src_is_local, dst_is_local, orig_is_local;
  SshIpAddrStruct nat_src, nat_dst;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshUInt16 nat_src_port, nat_dst_port;
  int level;
  SshUInt32 reverse_transform_index;
  SshUInt32 ifp_flags;

  SSH_INTERCEPTOR_STACK_MARK();

  if ((pc->flags & SSH_ENGINE_PC_RESTARTED_OUT) == 0)
    reverse_transform_index = pc->prev_transform_index;
  else
    reverse_transform_index = SSH_IPSEC_INVALID_INDEX;  

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Sanity check: only TCP and UDP are currently supported for
     application gateways. */
  SSH_ASSERT(pc->ipproto == SSH_IPPROTO_TCP || pc->ipproto == SSH_IPPROTO_UDP);

  appgw_flow_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(pc->u.rule.appgw_flow_index);
  appgw_flow_generation =
    SSH_ENGINE_FLOW_UNWRAP_GENERATION(pc->u.rule.appgw_flow_index);

  SSH_ASSERT(pc->u.rule.appgw_flow_index != SSH_IPSEC_INVALID_INDEX);
  c_flow = SSH_ENGINE_GET_FLOW(engine, appgw_flow_index);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Increment the reference count of pc->u.rule.next_hop_index_appgw,
     since it is being put into two flows. */
  {
    SshEngineNextHopControl c_nh;
    c_nh = SSH_ENGINE_GET_NH(engine, pc->u.rule.next_hop_index_appgw);
    c_nh->refcnt++;
  }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, appgw_flow_index);

  /* Initialize freeing_index values and other values accessed in error
     processing. */
  initiator_flow_index = if_index = SSH_IPSEC_INVALID_INDEX;
  responder_flow_index = rf_index = SSH_IPSEC_INVALID_INDEX;

  /* Try to detect any race conditions and abort if necessary. It
     is sufficient to detect that the rule is correct, flows are
     still attached to it and that any reserved NAT allocation
     is still valid. Note that we later destroy these placeholder
     flows and create completely new ones, they are only used
     to:
     - cache NAT allocation
     - get packets which hit initiator the flow.
  */

  if (c_flow->rule_index != pc->u.rule.appgw_current_rule
      || d_flow->generation != appgw_flow_generation
      || (!((d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING)
	    && (c_flow->control_flags
		& (SSH_ENGINE_FLOW_C_UNDEFINED|SSH_ENGINE_FLOW_C_VALID))
	    == (SSH_ENGINE_FLOW_C_UNDEFINED|SSH_ENGINE_FLOW_C_VALID)))
      || d_flow->ipproto != pc->ipproto
      || (!SSH_IP_EQUAL(&d_flow->src_ip, &pc->src))
      || (!SSH_IP_EQUAL(&d_flow->dst_ip, &pc->u.rule.appgw_orig_dst))
      || d_flow->src_port != pc->u.rule.src_port
      || d_flow->dst_port != pc->u.rule.appgw_orig_dst_port)
    {
      FASTPATH_RELEASE_FLOW(engine->fastpath, appgw_flow_index);
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("race condition detected. appgw trigger flow=%d already "
                 "reused via flow idle timeout (flags d=0x%04x c=0x%04x)",
                 (int) pc->u.rule.appgw_flow_index,
		 (unsigned int) d_flow->data_flags,
		 c_flow->control_flags));
      goto error;
    }

  /* Cache NAT information and release the fastpath lock */
  nat_src = d_flow->nat_src_ip;
  nat_src_port = d_flow->nat_src_port;
  nat_dst = d_flow->nat_dst_ip;
  nat_dst_port = d_flow->nat_dst_port;

  FASTPATH_RELEASE_FLOW(engine->fastpath, appgw_flow_index);

  nated_by_pm = !SSH_IP_EQUAL(&pc->dst, &pc->u.rule.appgw_orig_dst) ||
    pc->u.rule.dst_port != pc->u.rule.appgw_orig_dst_port;

  /* If PM wishes to do NAT, then override any allocated NAT */
  if (nated_by_pm)
    {
      nat_dst  = pc->dst;
      nat_dst_port = pc->u.rule.dst_port;
    }

  /* Free the placeholder flow now, so that if we abort on error
     then the flow is also destroyed (the appgw negotiation in userspace
     will fail anyway)... */
  ssh_engine_free_flow(engine, appgw_flow_index);
#ifdef DEBUG_LIGHT
  pc->u.rule.appgw_flow_index = SSH_IPSEC_INVALID_INDEX;
  d_flow = NULL;
  c_flow = NULL;
#endif /* DEBUG_LIGHT */

  /* Extract an IP address for the appgw interface. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  if (!ssh_engine_get_ipaddr(engine,
                             pc->u.rule.ifnum_appgw,
                             pc->u.rule.appgw_protocol,
                             NULL, &gw_ip))
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto error;
    }

  /* Allocate port numbers for communicating with the responder and the
     initiator. */
  is_ipv6 = SSH_IP_IS6(&gw_ip);

  if (!ssh_engine_nat_get_unused_map(engine, is_ipv6,
                                     pc->u.rule.ifnum_appgw, &gw_ip, 
				     0, 0, 0, /*src*/
                                     pc->u.rule.ifnum_appgw, &gw_ip, 0, /*dst*/
                                     NULL, &gw_responder_port, /* src_return */
                                     NULL, &gw_initiator_port)) /*dst_return*/

    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto error;
    }

  /* Fetch interface flags here where we have the interface_lock taken. */
  ifp_flags = ssh_ip_get_interface_flags_by_ifnum(&engine->ifs,
						  pc->u.rule.ifnum_appgw);

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Check whether appgw, packet's source and destination addresses are
     local IP addresses. */
  is_local = ssh_engine_ip_is_local(engine, &pc->u.rule.appgw_ip);
  src_is_local = ssh_engine_ip_is_local(engine, &pc->src);
  dst_is_local = ssh_engine_ip_is_local(engine, &pc->dst);
  orig_is_local = ssh_engine_ip_is_local(engine, &pc->u.rule.appgw_orig_dst);

  /* If the application gateway resides on the local host, use the
     original source or destination address (whichever is not a local
     IP address) instead of the gateway address as the address that
     the appgw connects to.  This ensures that the interceptor will
     actually see the packets for that connection.  (The SSH
     interceptor API specifies that packets destined to localhost
     (e.g. 127.0.0.1) need not be seen by the interceptor, and in fact
     are not easily available on several major platforms.) */
  if (is_local)
    {
      /* Safe case number 1. */
      if (pc->u.rule.ifnum_appgw == pc->u.rule.ifnum_dst
          && !dst_is_local)
        {
          /* The destination address should be used if possible,
             because this allows the packets to be routed to
             the correct interface in both inbound and outbound
             cases. */
          gw_ip = pc->dst;
          /* Discovereed via routing in engine_rule_execute_step */
          appgw_ifnum = pc->u.rule.ifnum_dst;
        }
      /* Safe case number 2. */
      else if (pc->u.rule.ifnum_appgw == pc->u.rule.ifnum_src
               && !src_is_local)
        {
          /* The source IP address is not our local address. */
          gw_ip = pc->src;
          appgw_ifnum = pc->u.rule.ifnum_src;
        }
      /* Safe case for Appgw redirect cases. */
      else if (pc->u.rule.ifnum_dst_orig == pc->u.rule.ifnum_appgw
               && !orig_is_local)
        {
          /* The destination IP address and the source IP address are
             both local addresses or the interfaces are not nicely
             set up. We then try to use the original appgw responder
             address and interface for the gw_ip. This depending on
             ingress filtering, may or may not work. */
          gw_ip = pc->u.rule.appgw_orig_dst;
          appgw_ifnum = pc->u.rule.ifnum_dst_orig;
        }
      /* Heuristic. */
      else if (dst_is_local)
        {
          gw_ip = pc->src;
          appgw_ifnum = pc->u.rule.ifnum_src;
        }
      else if (ifp_flags & SSH_INTERFACE_FLAG_VIP)
        {
          gw_ip = pc->dst;
          appgw_ifnum = pc->u.rule.ifnum_appgw;
        }
      else
        {
          gw_ip = pc->dst;
          appgw_ifnum = pc->u.rule.ifnum_dst;
        }
    }
  else 
    appgw_ifnum = pc->u.rule.ifnum_appgw;

  /* Determine the tunnel id for traffic coming from the responder. */
  from_responder_tunnel_id = 0;
  if (pc->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, pc->transform_index);
      SSH_ASSERT(trd != NULL);
      from_responder_tunnel_id = trd->inbound_tunnel_id;
      FASTPATH_RELEASE_TRD(engine->fastpath, pc->transform_index);
    }

  /* Compute flow id for packets from the initiator. */
  if (!ssh_engine_compute_tcpudp_flowid(engine, pc->ipproto,
					pc->tunnel_id,
					&pc->src, &pc->u.rule.appgw_orig_dst,
					pc->u.rule.src_port,
					pc->u.rule.appgw_orig_dst_port,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
					pc->pp->extension,
#else
					NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
					from_initiator_flow_id,
					src_is_local ? FALSE : TRUE))
    goto error;

      /* Compute flow id for packets to the responder. */
  if (!ssh_engine_compute_tcpudp_flowid(engine, pc->ipproto, 0,
					&pc->u.rule.appgw_ip, &gw_ip,
					pc->u.rule.appgw_responder_port,
					gw_responder_port,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
					pc->pp->extension,
#else
					NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
					to_responder_flow_id,
					is_local ? FALSE : TRUE))
    goto error;
      
  /* Ensure that we have two flows available, before we do anything else.. */
  level = ssh_engine_flow_reap_lru_level(engine, pc->u.rule.appgw_rule_index);

  if (ssh_engine_reap_flows(engine, level, 2) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to reap 2 flows with LRU levels at most %d",
                 level));
      goto error;
    }

  /* Create a flow for the initiator-appgw mapping. */
  if (!ssh_engine_create_flow(engine,
                              pc->u.rule.appgw_rule_index,
                              from_initiator_flow_id,
                              &pc->src,
                              &pc->u.rule.appgw_orig_dst,
                              pc->ipproto,
                              pc->u.rule.src_port,
                              pc->u.rule.appgw_orig_dst_port,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                              pc->u.rule.ifnum_appgw, pc->u.rule.ifnum_src,
                              pc->u.rule.local_appgw, pc->u.rule.local_src,
                              pc->u.rule.mtu_appgw, pc->u.rule.mtu_src,
			      pc->u.rule.route_selector_appgw,
			      pc->u.rule.route_selector_src,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              pc->u.rule.next_hop_index_appgw,
                              pc->u.rule.next_hop_index_src,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              pc->u.rule.ifnum_src,
                              appgw_ifnum,
                              &gw_ip,
                              &pc->u.rule.appgw_ip,
                              gw_initiator_port,
                              pc->u.rule.appgw_initiator_port,
                              pc->protocol_xid,
			      (SSH_ENGINE_FLOW_C_NOTIFY_DELETE
			       | SSH_ENGINE_FLOW_C_REROUTE_I),
                              (SSH_ENGINE_FLOW_D_NAT_SRC
                               | SSH_ENGINE_FLOW_D_NAT_DST
                               | SSH_ENGINE_FLOW_D_DROP_PKTS),
			       SSH_IPSEC_INVALID_INDEX,
                              reverse_transform_index,
                              pc->u.rule.appgw_flow_idle_timeout,
                              0,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                              pc->pp->extension,
#else
			      NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                              &initiator_flow_index))
    goto error;

  /* Create a flow for the responder-appgw mapping. */
  if (!ssh_engine_create_flow(engine,
                              pc->u.rule.appgw_rule_index,
                              to_responder_flow_id,
                              &pc->u.rule.appgw_ip,
                              &gw_ip,
                              pc->ipproto,
                              pc->u.rule.appgw_responder_port,
                              gw_responder_port,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                              pc->u.rule.ifnum_dst, pc->u.rule.ifnum_appgw,
                              pc->u.rule.local_dst, pc->u.rule.local_appgw,
                              pc->u.rule.mtu_dst, pc->u.rule.mtu_appgw,
			      pc->u.rule.route_selector_dst,
			      pc->u.rule.route_selector_appgw,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              pc->u.rule.next_hop_index_dst,
                              pc->u.rule.next_hop_index_appgw,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              appgw_ifnum,
                              pc->u.rule.ifnum_dst,
                              &nat_src,
                              &nat_dst,
                              nat_src_port,
                              nat_dst_port,
                              pc->protocol_xid,
			      (SSH_ENGINE_FLOW_C_NOTIFY_DELETE
			       | SSH_ENGINE_FLOW_C_REROUTE_R),
                              (SSH_ENGINE_FLOW_D_NAT_SRC
                               | SSH_ENGINE_FLOW_D_NAT_DST),
                              pc->transform_index,
                              SSH_IPSEC_INVALID_INDEX,
                              pc->u.rule.appgw_flow_idle_timeout,
                              0,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                              pc->pp->extension,
#else
			      NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                              &responder_flow_index))
    goto error;

  SSH_DEBUG(SSH_D_HIGHOK, ("appgw mapping success, "
                           "gw_initiator_port=%u gw_responder_port=%u",
                           gw_initiator_port,
                           gw_responder_port));

  /* Encode mappings between I<->R flows */
  SSH_ASSERT(initiator_flow_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(responder_flow_index != SSH_IPSEC_INVALID_INDEX);

  if_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(initiator_flow_index);
  rf_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(responder_flow_index);
  ic_flow = SSH_ENGINE_GET_FLOW(engine, if_index);
  rc_flow = SSH_ENGINE_GET_FLOW(engine, rf_index);
  ic_flow->pair_flow_idx = rf_index;
  rc_flow->pair_flow_idx = if_index;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* This is ugly, but the logic of flow_undangle() assumes that
     find_reverse_rule() produces the same result for both i_flow
     and r_flow, and hence we must secure the same inputs for both
     cases. */
  memcpy(rc_flow->initiator_peer_id, ic_flow->initiator_peer_id,
	 sizeof(ic_flow->initiator_peer_id));
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */


#ifdef DEBUG_LIGHT
  {
    SshUInt32 rule_idx;

    rule_idx = ssh_engine_find_appgw_totunnel_rule(engine,
					        rf_index,
					        SSH_ENGINE_ATT_MATCH_UNUSED);
    SSH_ASSERT(rule_idx != SSH_IPSEC_INVALID_INDEX);

    rule_idx = ssh_engine_find_appgw_totunnel_rule(engine,
					        if_index,
					        SSH_ENGINE_ATT_MATCH_UNUSED);
    SSH_ASSERT(rule_idx != SSH_IPSEC_INVALID_INDEX);
  }
#endif /* DEBUG_LIGHT */

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Call the callback to indicate success. */
  (*pc->u.rule.appgw_callback)(engine->pm, &gw_ip,
                               gw_initiator_port, gw_responder_port,
                               initiator_flow_index, responder_flow_index,
                               &nat_src, nat_src_port, &nat_dst, nat_dst_port,
                               pc->u.rule.appgw_context);

 free_pc:
  /* Release the packet context.  The callback should already have been
     called when we get here. */

  /* Free the dummy packet. */
  SSH_ASSERT(pc->pp != NULL);
  ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;

  /* Recycle packet context. */
  ssh_engine_free_pc(engine, pc);
  return;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("error"));

  if (initiator_flow_index != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_free_flow(engine, if_index);
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  else
    {
      /* Decrement next hop node refcounts manually. */
      if (pc->u.rule.next_hop_index_appgw != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_decrement_next_hop_refcnt(engine,
                                             pc->u.rule.next_hop_index_appgw);
      if (pc->u.rule.next_hop_index_src != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_decrement_next_hop_refcnt(engine,
                                             pc->u.rule.next_hop_index_src);
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (responder_flow_index != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_free_flow(engine, rf_index);
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  else
    {
      /* Decrement next hop node refcounts manually. */
      if (pc->u.rule.next_hop_index_dst != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_decrement_next_hop_refcnt(engine,
                                             pc->u.rule.next_hop_index_dst);
      if (pc->u.rule.next_hop_index_appgw != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_decrement_next_hop_refcnt(engine,
                                             pc->u.rule.next_hop_index_appgw);
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Unlock. */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Call the callback to signal error. */
  (*pc->u.rule.appgw_callback)(engine->pm, NULL, 0, 0, 0, 0, NULL, 0,
                               NULL, 0,
                               pc->u.rule.appgw_context);
  /* Deinitialize (same as in success case). */
  goto free_pc;
}
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

Boolean
ssh_engine_finish_trigger(SshEngine engine, SshEnginePacketContext pc)
{
  Boolean is_ok;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt32 forward_nh_index;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_INTERCEPTOR_STACK_MARK();

  /* If PC_HIT_TRIGGER is set, then engine_trigger() must be called! */
  SSH_ASSERT(pc->rule != NULL);
  SSH_ASSERT(pc->rule->type != SSH_ENGINE_RULE_TRIGGER);
  SSH_ASSERT(pc->flow_index != SSH_IPSEC_INVALID_INDEX);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (pc->u.rule.next_hop_index_src != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_decrement_next_hop_refcnt(engine,
                                         pc->u.rule.next_hop_index_src);
  pc->u.rule.next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  if (pc->u.rule.next_hop_index_appgw != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_decrement_next_hop_refcnt(engine,
                                         pc->u.rule.next_hop_index_appgw);
  pc->u.rule.next_hop_index_appgw = SSH_IPSEC_INVALID_INDEX;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  d_flow = FASTPATH_GET_FLOW(engine->fastpath, pc->flow_index);
  c_flow = SSH_ENGINE_GET_FLOW(engine, pc->flow_index);

  if (d_flow->generation != pc->flow_generation
      || (c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID) == 0
      || (c_flow->control_flags & SSH_ENGINE_FLOW_C_TRIGGER) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Flow disappeared during trigger processing!"));

      FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return FALSE;
    }

  /* Cache the forward nh index. */
  forward_nh_index = d_flow->forward_nh_index;

  d_flow->forward_nh_index = pc->u.rule.next_hop_index_dst;
  pc->u.rule.next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;

  /* Note that it is intentional that we do not change the
     reverse next hop node here, as it is related to the
     ifnum and local-stack selectors. */
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  d_flow = FASTPATH_GET_FLOW(engine->fastpath, pc->flow_index);
  c_flow = SSH_ENGINE_GET_FLOW(engine, pc->flow_index);

  d_flow->forward_ifnum = pc->u.rule.ifnum_dst;
  d_flow->forward_local = pc->u.rule.local_dst;
  d_flow->forward_mtu = pc->u.rule.mtu_dst;

  /* Update route selectors. */
  d_flow->forward_route_selector = pc->u.rule.route_selector_dst;
  d_flow->reverse_route_selector = pc->u.rule.route_selector_src;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* The reverse incoming ifnum might have been changed, as there
     might now be a tunnel available. */
  SSH_DEBUG(SSH_D_MIDOK, ("Updating flow incoming reverse ifnum %d -> %d",
			  d_flow->incoming_reverse_ifnum , 
			  pc->u.rule.ifnum_dst));
  d_flow->incoming_reverse_ifnum = pc->u.rule.ifnum_dst;

  is_ok = ssh_engine_flow_compute_flow_id_from_flow(engine, pc->flow_index,
						    d_flow,
						    FALSE,
						    d_flow->reverse_flow_id);
  if (is_ok)
    {
      c_flow->control_flags &= ~SSH_ENGINE_FLOW_C_TRIGGER;
      pc->flags &= ~SSH_ENGINE_PC_HIT_TRIGGER;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("flow forward next hop is now defined!"));
    }
  else
    SSH_DEBUG(SSH_D_NICETOKNOW, ("reverse flow id update failed!"));

  FASTPATH_COMMIT_FLOW(engine->fastpath, pc->flow_index, d_flow);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (forward_nh_index != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_decrement_next_hop_refcnt(engine, forward_nh_index);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  return is_ok;
}

void ssh_engine_execute_rule_no_flow(SshEnginePacketContext pc)
{
  SshEngine engine = pc->engine;
  SshEnginePolicyRule rule = pc->rule;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  size_t mtu;
  SshEngineIfnum ifnum;
  Boolean local;
  SshUInt16 route_selector;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  Boolean dst_is_nulladdr;
  SshUInt32 next_hop_index;
  SshEngineNextHopData d_nh;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_MIDOK, ("NO_FLOW rule"));
  SSH_ASSERT(rule->type == SSH_ENGINE_RULE_PASS
	     || rule->type == SSH_ENGINE_RULE_APPLY);

  /* Note: all needed data must be read out of pc->u.rule before
     anything is written to pc->u.flow because they are part of
     the same union. */
#ifdef SSHDIST_L2TP
  /* Set the ignore L2TP flag for L2TP control traffic flows.
     The control traffic is only encrypted with IPSec but the
     packets are not encapsulated in UDP/L2TP/PPP. */
  if (pc->ipproto == SSH_IPPROTO_UDP &&
      (pc->u.rule.src_port == SSH_IPSEC_L2TP_PORT ||
       pc->u.rule.dst_port == SSH_IPSEC_L2TP_PORT) &&
      (pc->pp->flags & (SSH_ENGINE_P_TOLOCAL |
			SSH_ENGINE_P_FROMLOCAL)))
    pc->flags |= SSH_ENGINE_FLOW_D_IGNORE_L2TP;
#endif /* SSHDIST_L2TP */

  if ((pc->pp->flags & SSH_ENGINE_P_FROMLOCAL) != 0
      || (pc->pp->flags & SSH_ENGINE_P_TOLOCAL) != 0)
    pc->flags |= SSH_ENGINE_FLOW_D_LOCAL_ENDPNT;

  pc->transform_index = rule->transform_index;
  pc->flow_index = SSH_IPSEC_INVALID_INDEX;
  /* Copy media processing information into pc. */
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  mtu = pc->u.rule.mtu_dst;
  ifnum = pc->u.rule.ifnum_dst;
  local = pc->u.rule.local_dst;
  route_selector = pc->u.rule.route_selector_dst;
  pc->u.flow.mtu = mtu;
  pc->u.flow.ifnum = ifnum;
  pc->u.flow.local = local;
  pc->route_selector = route_selector;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  dst_is_nulladdr = SSH_IP_IS_NULLADDR(&pc->dst);

  /* It is possible that we are executing here even if the
     state machine was traversed with a no-"no-flow" rule.
     So we must free any next_hop_indexes it has allocated */
  if (pc->u.rule.next_hop_index_src != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_engine_decrement_next_hop_refcnt(engine,
					   pc->u.rule.next_hop_index_src);
      pc->u.rule.next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
    }

  /* Use the next_hop_index_dst to prep the media header */
  next_hop_index = pc->u.rule.next_hop_index_dst;
  /* Mark the next hop node as invalid */
  pc->u.rule.next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;

  d_nh = FASTPATH_GET_NH(engine->fastpath, next_hop_index);
  pc->u.flow.mtu = (SshUInt16) d_nh->mtu;
  pc->u.flow.ifnum = d_nh->ifnum;
  pc->u.flow.local =  (d_nh->flags & SSH_ENGINE_NH_LOCAL) != 0;
  pc->u.flow.mediatype = d_nh->mediatype;
  pc->u.flow.media_hdr_len = d_nh->media_hdr_len;
  pc->u.flow.min_packet_len = d_nh->min_packet_len;
  pc->u.flow.media_protocol = d_nh->media_protocol;
  SSH_ASSERT(d_nh->media_hdr_len <= sizeof(pc->u.flow.mediahdr));
  memcpy(pc->u.flow.mediahdr, d_nh->mediahdr, d_nh->media_hdr_len);

  /* Update the source/destination media header for special
     inbound and outbound next-hop nodes. */
  if (d_nh->mediatype != SSH_INTERCEPTOR_MEDIA_PLAIN
      && d_nh->flags & (SSH_ENGINE_NH_INBOUND | SSH_ENGINE_NH_OUTBOUND))
    ssh_engine_update_media_header(pc, d_nh, dst_is_nulladdr);

  FASTPATH_RELEASE_NH(engine->fastpath, next_hop_index);

  /* Free the refcnt */
  ssh_engine_decrement_next_hop_refcnt(engine, next_hop_index);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* If we have a transform, copy data out of the transform. */
  if (!ssh_engine_copy_transform_data(engine, pc))
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_HIGHOK, ("returning EXECUTE"));

  /* It is true that the packet is not really corrupt at this
     point, but the _audit_packet_context() contains
     all required functionality for auditing this event. */
  if ((rule->flags & SSH_ENGINE_LOG_CONNECTIONS) != 0)
    {
      pc->audit.corruption = SSH_PACKET_CORRUPTION_POLICY_PASS;
      pc->audit.ip_option = 0;
      pc->audit.spi = 0;

      /* Queue the audit event to the PM, this is done now and not
	 at the end of the fastpath, since audit information from
	 the packet may change during transform execution. */
      ssh_engine_audit_packet_context(engine, pc);
      return;
    }

  engine_packet_continue(pc, SSH_ENGINE_RET_EXECUTE);
  return;
}

/* Steps rule execution forward.  This eventually calls
   engine_packet_continue when done with the rule.  If success is
   TRUE, this continues operating based on pc->u.rule.state.  If
   success if FALSE, this passes the error to
   engine_packet_continue and causes the packet to be dropped.  It
   is assumed that pc->pp is either valid or NULL if success is FALSE.
   If firewalling is enabled, this function is also used in appgw mapping
   creation. */

void ssh_engine_execute_rule_step_internal(SshEnginePacketContext pc, 
					   SshEngineRuleExecuteError error)
{
  SshEngine engine = pc->engine;
  SshUInt32 transform_index;
  SshEngineTransformData trd;
  SshEnginePolicyRule rule;
  SshIpAddrStruct src, dst;
  SshUInt16 src_port, dst_port;
  SshUInt32 spi;
  SshInterceptorPacket pp;
  SshEngineIfnum ifnum;
  SshUInt8 ipproto;
#ifdef SSHDIST_IPSEC_NAT
  SshUInt16 nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */
  SshInterceptorRouteKeyStruct key;
  Boolean outbound_ifnum, transform_applied;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_MIDOK, ("execute_rule_step: error=%d, state=%d",
                          (int) error, (int) pc->u.rule.state));

 restart_recursed:

  /* Check for failure. */
  if (error != SSH_ENGINE_RULE_EXECUTE_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("execute_rule_step reports failure (%d)",
			       (int) error));

      switch (error)
	{
	case SSH_ENGINE_RULE_EXECUTE_ERROR_SEND_ICMP:
#if defined (WITH_IPV6)
          if (pc->pp->protocol == SSH_PROTOCOL_IP6)
            ssh_engine_send_icmp_error(engine, pc, SSH_ICMP6_TYPE_UNREACH,
                                       SSH_ICMP6_CODE_UNREACH_NOROUTE, 0);
          else
#endif /* WITH_IPV6 */
            ssh_engine_send_icmp_error(engine, pc, SSH_ICMP_TYPE_UNREACH,
                                       SSH_ICMP_CODE_UNREACH_HOST, 0);
	  pc->pp = NULL;
	  break;

	default:
	  break;
	}

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      if (pc->u.rule.next_hop_index_dst != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_decrement_next_hop_refcnt(engine,
                                             pc->u.rule.next_hop_index_dst);
      if (pc->u.rule.next_hop_index_src != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_decrement_next_hop_refcnt(engine,
                                             pc->u.rule.next_hop_index_src);
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
      if (pc->u.rule.next_hop_index_appgw != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_decrement_next_hop_refcnt(engine,
                                             pc->u.rule.next_hop_index_appgw);
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
      /* Check if this is actually appgw mapping creation. */
      if (pc->rule == NULL)
        { /* Fail the appgw mapping creation by calling the callback. */
          (*pc->u.rule.appgw_callback)(engine->pm, NULL, 0, 0, 0, 0, NULL, 0,
                                       NULL, 0,
                                       pc->u.rule.appgw_context);

          /* Release the packet context. */
          ssh_engine_free_pc(engine, pc);
        }
      else
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
        if (pc->flags & SSH_ENGINE_PC_REROUTE_FLOW)
          {
            ssh_engine_route_change_final(pc, error);
            /* Release the packet context. */
            SSH_DEBUG(SSH_D_MY, ("placing pc=%p on freelist", pc));
          }
        else
          {
	    SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
            pc->transform = 0;
            if (pc->pp == NULL)
              engine_packet_continue(pc, SSH_ENGINE_RET_ERROR);
            else
              engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
          }
      return;
    }

  rule = pc->rule;
#ifdef SSHDIST_IPSEC_FIREWALL
  /* Rule is NULL if we are executing appgw request. */
#else /* SSHDIST_IPSEC_FIREWALL */
  SSH_ASSERT(rule != NULL);
#endif /* SSHDIST_IPSEC_FIREWALL */
  pp = pc->pp;
  SSH_ASSERT(pp != NULL);
  SSH_DEBUG(SSH_D_MIDOK, ("Execute rule state `%s'",
                          ssh_engine_rule_state_names[pc->u.rule.state]));;
  switch (pc->u.rule.state)
    {
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
    case SSH_ENGINE_ST_ROUTE_APPGW:




      SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);
      SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(&key,  &pc->u.rule.appgw_ip);
      pc->u.rule.route_selector = key.selector;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->u.rule.route_selector_appgw = key.selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ssh_interceptor_packet_detach(pc->pp);
      ssh_engine_route(engine, 0, &key, TRUE,
                       ssh_engine_execute_rule_route_cb, (void *)pc);
      goto return_unless_recursed;

    case SSH_ENGINE_ST_ROUTE_APPGW_REDIRECT:
      if (!(SSH_IP_EQUAL(&pc->u.rule.appgw_orig_dst, &pc->dst)))
        {



	  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);
	  SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(&key,  &pc->u.rule.appgw_orig_dst);
	  pc->u.rule.route_selector = key.selector;

          ssh_interceptor_packet_detach(pc->pp);
          ssh_engine_route(engine, 0, &key, TRUE,
                           ssh_engine_execute_rule_route_cb, (void*)pc);
          goto return_unless_recursed;
        }
      /*FALLTHROUGH*/
    case SSH_ENGINE_ST_ROUTE_APPGW_DONE:
      /* Route initiator and responder IP addresses. */
      pc->u.rule.state = SSH_ENGINE_ST_INIT;
      goto restart_recursed;
      break;

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

    case SSH_ENGINE_ST_INIT:
      SSH_DEBUG(SSH_D_MIDOK,
                ("Rule execute for %@->%@%s%s%s",
                 ssh_ipaddr_render, &pc->src,
                 ssh_ipaddr_render, &pc->dst,
                 pp->flags & SSH_ENGINE_P_TOLOCAL ? " to-local" : "",
                 pp->flags & SSH_ENGINE_P_FROMLOCAL ? " from-local" : "",
                 (pc->rule && pc->rule->flags & SSH_ENGINE_NO_FLOW
                  ? " no-flow" : " flow")));

      /* Determine the start state that is appropriate for this
         packet. */
      if ((pp->flags & SSH_ENGINE_P_TOLOCAL) == 0
          && (pp->flags & SSH_ENGINE_P_FROMLOCAL) == 0)
        {
          /* A forwarded packet.  Route tunnel destination (or
             destination if no tunneling is done in the forward
             direction) to resolve the next-hop node in the forward
             direction.  Route tunnel source to resolve the next-hop
             node in the reverse direction. */
          pc->u.rule.state = SSH_ENGINE_ST_FW_ROUTE_TN_DST;
        }
      else if ((pp->flags & SSH_ENGINE_P_TOLOCAL)
               && (pp->flags & SSH_ENGINE_P_FROMLOCAL) == 0)
        {
          /* A to-local (inbound) packet.  Route source address to
             resolve the next-hop node for the decapsulated packet
             in the forward case.  Route tunnel source to resolve
             the next-hop node in the reverse direction. */
          pc->u.rule.state = SSH_ENGINE_ST_TL_ROUTE_SRC;
#ifdef SSHDIST_IPSEC_NAT
          /* Check for forced NAT. */
          nat_dst_port = pc->u.rule.dst_port;
          dst = pc->dst;

          if (pc->ipproto == SSH_IPPROTO_ICMP ||
	      pc->ipproto == SSH_IPPROTO_IPV6ICMP ||
              pc->ipproto == SSH_IPPROTO_TCP ||
	      pc->ipproto == SSH_IPPROTO_UDP ||
	      pc->ipproto == SSH_IPPROTO_UDPLITE)
            {
              if (rule)
                {
                  if (rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST)
                    {
                      dst = rule->nat_dst_ip_low;
                      nat_dst_port = rule->nat_dst_port;
                      pc->u.rule.state = SSH_ENGINE_ST_FW_ROUTE_TN_DST;

                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Forced Destination NAT: %@.%d > %@.%d",
                                 ssh_ipaddr_render, &pc->dst,
                                 pc->u.rule.dst_port,
                                 ssh_ipaddr_render, &dst, nat_dst_port));
                    }
                }
            }
#endif /* SSHDIST_IPSEC_NAT */
        }
      else if ((pp->flags & SSH_ENGINE_P_TOLOCAL) == 0
               && pp->flags & SSH_ENGINE_P_FROMLOCAL)
        {
          /* A from-local (outbound) packet.  Route tunnel destination
             to resolve the next-hop node in the forward case.  Route
             destination address to resolve the next-hop node for the
             decapsulated packets in the reverse direction. */
          pc->u.rule.state = SSH_ENGINE_ST_FL_ROUTE_TN_DST;
        }
      else
        {
          SSH_ASSERT(pp->flags & SSH_ENGINE_P_TOLOCAL
                     && pp->flags & SSH_ENGINE_P_FROMLOCAL);
          /* A loopback packet. */
          pc->u.rule.state = SSH_ENGINE_ST_LOOPBACK;
        }
      /* Move to the next state. */
      goto restart_recursed;
      break;

    case SSH_ENGINE_ST_FW_ROUTE_TN_DST:
    case SSH_ENGINE_ST_FL_ROUTE_TN_DST:
      /* Select the IP addresses that we use for looking up routing
         information.  Normally these are the source and destination
	 addresses of the packet; however, if we are encapsulating it
	 in tunnel mode, then we use the local and remote gateway addresses
	 for routing instead. */
      dst = pc->dst;
      src = pc->src;
      ifnum = pc->pp->ifnum_in;
      ipproto = pc->ipproto;
      src_port = pc->u.rule.src_port;
      dst_port = pc->u.rule.dst_port;
      spi = pc->u.rule.spi;
      transform_applied = FALSE;

      if (pc->u.rule.state == SSH_ENGINE_ST_FL_ROUTE_TN_DST)
	outbound_ifnum = TRUE;
      else
	outbound_ifnum = FALSE;

      if (rule)
        transform_index = rule->transform_index; /* for normal rule exec */
      else
        transform_index = pc->transform_index; /* for appgw mapping create */
      if (transform_index != SSH_IPSEC_INVALID_INDEX)
        {
	  SshEngineTransformControl c_trd;
	  
	  transform_applied = TRUE;
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);
	  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
	  if (c_trd == NULL)
            {
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
              SSH_DEBUG(SSH_D_FAIL, ("Transform index is not valid anymore"));
	      error = SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
              goto restart_recursed;
            }

	  trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, transform_index);

#ifdef SSHDIST_L2TP
          if (trd->transform & (SSH_PM_IPSEC_L2TP | SSH_PM_IPSEC_TUNNEL))
#else /* SSHDIST_L2TP */
          if (trd->transform & SSH_PM_IPSEC_TUNNEL)
#endif /* SSHDIST_L2TP */
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("Routing dst to gw addr %@ ifnum %d",
                                       ssh_ipaddr_render, &trd->gw_addr,
                                       (int) trd->own_ifnum));
              dst = trd->gw_addr;
	      src = trd->own_addr;
	      if (c_trd->control_flags
		  & SSH_ENGINE_TR_C_IPSEC_FLOW_REROUTE_ONGOING)
		ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
	      else
		ifnum = trd->own_ifnum;
	      outbound_ifnum = TRUE;
            }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
	  if (trd->transform & SSH_PM_IPSEC_NATT)
	    {
	      ipproto = SSH_IPPROTO_UDP;
	      src_port = trd->local_port;
	      dst_port = trd->remote_port;
	    }
	  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
	  if (trd->transform & SSH_PM_IPSEC_ESP)
	    {
	      ipproto = SSH_IPPROTO_ESP;
	      spi = trd->spis[SSH_PME_SPI_ESP_OUT];
	    }
	  else if (trd->transform & SSH_PM_IPSEC_AH)
	    {
	      ipproto = SSH_IPPROTO_AH;
	      spi = trd->spis[SSH_PME_SPI_AH_OUT];
	    }
	  else if (trd->transform & SSH_PM_IPSEC_IPCOMP)
	    {
	      ipproto = SSH_IPPROTO_IPPCP;
	      spi = trd->spis[SSH_PME_SPI_IPCOMP_OUT];
	    }
	  FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
        }
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
      else if (rule &&
	       (rule->flags &
		(SSH_ENGINE_RULE_FORCE_NAT_DST | SSH_ENGINE_RULE_FORCE_NAT_SRC)
		))
	{
	  if (rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST)
	    dst = rule->nat_dst_ip_low;
	  if (rule->flags & SSH_ENGINE_RULE_FORCE_NAT_SRC)
	    src = rule->nat_src_ip_low;
	}
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

      /* Perform route lookup for the destination address. Store route
	 selector for later use in route callback. */
      ssh_engine_create_route_key(engine, &key, pc, &src, &dst, ipproto,
				  src_port, dst_port, spi,
				  ifnum, outbound_ifnum, transform_applied);
      pc->u.rule.route_selector = key.selector;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      /* Save route key selector and ifnum. */
      pc->u.rule.route_selector_dst = key.selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ssh_interceptor_packet_detach(pc->pp);
      ssh_engine_route(engine, 0, &key, TRUE,
                       ssh_engine_execute_rule_route_cb, (void *)pc);
      goto return_unless_recursed;
      break;

    case SSH_ENGINE_ST_FW_ROUTE_TN_SRC:
    case SSH_ENGINE_ST_TL_ROUTE_TN_SRC:
      /* Select the IP address that we use for looking up routing
         information.  Normally this is the source address of the
         packet; however, if we did decapsulate the packet from a
         tunnel, then we must use the from-tunnel's remote gateway
         address for routing instead. */
      src = pc->dst;
      dst = pc->src;
      ifnum = pc->pp->ifnum_in;
      outbound_ifnum = TRUE;
      ipproto = pc->ipproto;
      src_port = pc->u.rule.dst_port;
      dst_port = pc->u.rule.src_port;
      spi = pc->u.rule.spi;
      transform_applied = FALSE;

      if (pc->u.rule.state == SSH_ENGINE_ST_TL_ROUTE_TN_SRC)
	{
	  /* Use ifnum selector only if packet destination is 
	     broadcast / multicast or IPv6 link local address. */
	  if (!ssh_engine_ip_is_broadcast(engine, &pc->dst)
	      && !SSH_IP6_IS_LINK_LOCAL(&pc->dst))	    
	    ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
	}
      else
	{
	  /* Use outbound ifnum in forward direction
	     as the inbound ifnum in reverse direction. */
	  outbound_ifnum = FALSE;
	  ifnum = pc->u.rule.ifnum_dst;
	}
      transform_index = ((pc->flags & SSH_ENGINE_PC_RESTARTED_OUT) ? 
			 SSH_IPSEC_INVALID_INDEX: pc->prev_transform_index);
      if (transform_index != SSH_IPSEC_INVALID_INDEX)
        {
	  SshEngineTransformControl c_trd;
	  
	  transform_applied = TRUE;
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);
          c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
          if (c_trd == NULL)
            {
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
              SSH_DEBUG(SSH_D_FAIL, ("Transform index is not valid anymore"));
              error = SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
              goto restart_recursed;
            }

	  trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, transform_index);

#ifdef SSHDIST_L2TP
          if (trd->transform & (SSH_PM_IPSEC_L2TP | SSH_PM_IPSEC_TUNNEL))
#else /* SSHDIST_L2TP */
          if (trd->transform & SSH_PM_IPSEC_TUNNEL)
#endif /* SSHDIST_L2TP */
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("Routing src to gw addr %@",
                                       ssh_ipaddr_render, &trd->gw_addr));
              dst = trd->gw_addr;
	      src = trd->own_addr;
	      if (c_trd->control_flags
		  & SSH_ENGINE_TR_C_IPSEC_FLOW_REROUTE_ONGOING)
		ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
	      else
		ifnum = trd->own_ifnum;
	      outbound_ifnum = TRUE;
            }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
	  if (trd->transform & SSH_PM_IPSEC_NATT)
	    {
	      ipproto = SSH_IPPROTO_UDP;
	      src_port = trd->local_port;
	      dst_port = trd->remote_port;
	    }
	  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
	  if (trd->transform & SSH_PM_IPSEC_ESP)
	    {
	      ipproto = SSH_IPPROTO_ESP;
	      spi = trd->spis[SSH_PME_SPI_ESP_OUT];
	    }
	  else if (trd->transform & SSH_PM_IPSEC_AH)
	    {
	      ipproto = SSH_IPPROTO_AH;
	      spi = trd->spis[SSH_PME_SPI_AH_OUT];
	    }
	  else if (trd->transform & SSH_PM_IPSEC_IPCOMP)
	    {
	      ipproto = SSH_IPPROTO_IPPCP;
	      spi = trd->spis[SSH_PME_SPI_IPCOMP_OUT];
	    }
	  FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
        }

      /* Perform route lookup for the source address. Store route selector
	 for later use in route callback. */
      ssh_engine_create_route_key(engine, &key, pc, &src, &dst, ipproto,
				  src_port, dst_port, spi,
				  ifnum, outbound_ifnum, transform_applied);
      pc->u.rule.route_selector = key.selector;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->u.rule.route_selector_src = key.selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ssh_interceptor_packet_detach(pc->pp);
      ssh_engine_route(engine, 0, &key, TRUE,
                       ssh_engine_execute_rule_route_cb, (void *)pc);
      goto return_unless_recursed;
      break;

    case SSH_ENGINE_ST_TL_ROUTE_SRC:
      /* Perform route lookup for the source address, to produce
         a destination next hop node. Store route selector for later 
	 use in route callback. */

      /* Use ifnum selector if packet destination is broadcast / multicast
	 or IPv6 link local address. */
      if (ssh_engine_ip_is_broadcast(engine, &pc->dst)
	  || SSH_IP6_IS_LINK_LOCAL(&pc->dst))
	ifnum = pc->pp->ifnum_in;
      else
	ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

      ssh_engine_create_route_key(engine, &key, pc, &pc->dst, &pc->src,
				  pc->ipproto, pc->u.rule.dst_port,
				  pc->u.rule.src_port, pc->u.rule.spi,
				  ifnum, TRUE, FALSE);
      pc->u.rule.route_selector = key.selector;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->u.rule.route_selector_dst = key.selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ssh_interceptor_packet_detach(pc->pp);
      ssh_engine_route(engine, 0, &key, TRUE,
                       ssh_engine_execute_rule_route_cb, (void *)pc);
      goto return_unless_recursed;
      break;

    case SSH_ENGINE_ST_FL_ROUTE_DST:
      /* Perform route lookup for the destination address, to produce
       a source next hop node. Store route selector for later use in 
       route callback. */
      ssh_engine_create_route_key(engine, &key, pc, &pc->src, &pc->dst,
				  pc->ipproto, pc->u.rule.src_port,
				  pc->u.rule.dst_port, pc->u.rule.spi,
				  pc->pp->ifnum_in, TRUE, FALSE);
      pc->u.rule.route_selector = key.selector;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->u.rule.route_selector_src = key.selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ssh_interceptor_packet_detach(pc->pp);
      ssh_engine_route(engine, 0, &key, TRUE,
                       ssh_engine_execute_rule_route_cb, (void *)pc);
      goto return_unless_recursed;
      break;

    case SSH_ENGINE_ST_LOOPBACK:




      SSH_DEBUG(SSH_D_FAIL, ("Loopback packet found"));
      error = SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
      goto restart_recursed;
      break;

    case SSH_ENGINE_ST_FINAL:
      SSH_DEBUG(SSH_D_MIDOK, ("Moving to rule execution final step."));
      return;

    default:
      ssh_fatal("execute_rule_step: bad state %d", (int)pc->u.rule.state);
    }
  SSH_NOTREACHED;

 return_unless_recursed:
  /* Restart if recursed.  This is part of the tail recursion elimination
     logic. */
  SSH_ASSERT(pc->flags & SSH_ENGINE_PC_RE_INUSE);
  if (pc->flags & SSH_ENGINE_PC_RE_RECURSED)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("faking recursion"));
      error = pc->recursed_error;
      pc->flags &= ~SSH_ENGINE_PC_RE_RECURSED;
      goto restart_recursed;
    }
  pc->flags &= ~SSH_ENGINE_PC_RE_INUSE;
}

SshEngineRuleExecuteError
ssh_engine_execute_rule_step_final(SshEnginePacketContext pc)
{
  SshEngine engine = pc->engine;
  SshUInt16 flow_c_flags, flow_d_flags;
  SshUInt32 flow_index, rule_index;
  SshEngineTransformData trd;
  SshEnginePolicyRule rule;
  SshUInt32 reverse_tunnel_id;
  SshInterceptorPacket pp;
  SshUInt32 flow_idle_timeout, flow_max_lifetime;
#ifdef SSHDIST_IPSEC_NAT
  SshIpAddrStruct nat_dst, nat_src;
  SshUInt16 nat_dst_port, nat_src_port;
#endif /* SSHDIST_IPSEC_NAT */
  SshUInt16 flow_dst_port, flow_src_port;
  Boolean is_to_tunnel, is_to_tunnel_nat;
  SshUInt32 reverse_transform_index;
  
  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(pc->u.rule.state == SSH_ENGINE_ST_FINAL);

  SSH_DEBUG(SSH_D_MIDOK, ("Executing rule execution final state"));

  rule = pc->rule;
  pp = pc->pp;
  SSH_ASSERT(pp != NULL);
  
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  /* Check if we are performing the second or first phase in the creation
     of an APPGW mapping. */
  if (pc->rule == NULL)
    { /* Finish the creation of an appgw mapping. */
      ssh_engine_create_appgw_mapping_final(engine, pc);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_OK;
    }
  else if ((pc->rule->flags &
	    (SSH_PM_ENGINE_RULE_APPGW|SSH_ENGINE_RULE_DELETED))
	   == SSH_PM_ENGINE_RULE_APPGW
	   && pc->rule->type == SSH_ENGINE_RULE_TRIGGER)
    {
      /* Initiate the creation of an appgw mapping. */
      if (ssh_engine_create_appgw_mapping_initial(engine, pc) == TRUE)
	engine_packet_continue(pc, SSH_ENGINE_RET_RESTART_FLOW_LOOKUP);
      else
	engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);      
      return SSH_ENGINE_RULE_EXECUTE_ERROR_OK;
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
  if (pc->rule != NULL && (pc->rule->flags & SSH_ENGINE_RULE_DELETED))
    {
      /* Do not process packets if the rule has been deleted,
	 as the transform_index field may be meaningless. */
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_RULEDROP);
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_OK;
    }
  else if (pc->flags & SSH_ENGINE_PC_HIT_TRIGGER)
    {
      if (ssh_engine_finish_trigger(engine, pc) == TRUE)
	engine_packet_continue(pc, SSH_ENGINE_RET_RESTART_FLOW_LOOKUP);
      else
	engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_OK;
    }

  /* Drop all media level broadcast packets coming from the
     adapter and not directed to us.  In other words, we do not
     forward broadcast packets that are not directed to us. */
  if (pp->flags & SSH_PACKET_MEDIABCAST &&
      (pp->flags & SSH_ENGINE_P_FROMLOCAL) == 0 &&
      (pp->flags & SSH_ENGINE_P_TOLOCAL) == 0)
    {
      SSH_DEBUG(SSH_D_MIDOK,
		("Dropping media broadcast packet to non-local "
		 "destination %@",
		 ssh_ipaddr_render, &pc->dst));
      return SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
    }

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Make sure the rule is still valid (i.e., has not been deleted).
     Note that we must maintain consistency with this respect against
     any deletion that might occur while executing it here. */
  if (rule->flags & SSH_ENGINE_RULE_DELETED)
    { 
      /* Rule has been deleted, abort processing it. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
    }

  /* If we are not going to create a flow, then copy the relevant
     information to pc. */
  if ((rule->flags & SSH_ENGINE_NO_FLOW) != 0)
    { 
      /* No flow to be created; prepare for immediate execution. */
      ssh_engine_execute_rule_no_flow(pc);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_OK;
    }

  SSH_DEBUG(SSH_D_MIDOK,
	    ("Normal rule (flags 0x%08x), creating flow",
	     (unsigned int) rule->flags));

  /* Determine the tunnel id for the reverse flow.  We can do this without
     locking because the reference we hold on rule also protects the
     existence of the transform data and the tunnel fields do not change
     after the transform data has been created. */
  reverse_tunnel_id = 0;

  /* Extract defaults for TRIGGER rules from rule->flags */
  is_to_tunnel = (rule->flags & SSH_PM_ENGINE_RULE_TOTUNNEL
		  ? TRUE : FALSE);
  is_to_tunnel_nat = (rule->flags & SSH_PM_ENGINE_RULE_TT_NAT
		      ? TRUE : FALSE);

  flow_c_flags = SSH_ENGINE_FLOW_C_REROUTE_I | SSH_ENGINE_FLOW_C_REROUTE_R;
  flow_d_flags = 0;

  if (rule->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, 
				       rule->transform_index);
      SSH_ASSERT(trd != NULL);
      reverse_tunnel_id = trd->inbound_tunnel_id;
      is_to_tunnel = TRUE;
#ifdef SSHDIST_IPSEC_NAT
      if (trd->transform & SSH_PM_IPSEC_PORT_NAT)
	is_to_tunnel_nat = TRUE;
#endif /* SSHDIST_IPSEC_NAT */

      FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
    }

#ifdef SSHDIST_IPSEC_NAT
  flow_d_flags |= ssh_engine_nat_allocate(engine,
					  pc,
					  rule,
					  is_to_tunnel,
					  is_to_tunnel_nat,
					  FALSE,
					  &nat_src,
					  &nat_src_port,
					  &nat_dst,
					  &nat_dst_port);
  if (flow_d_flags == 0xffff)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("flow create failed due to NAT error"));
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
    }

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Adjust the route key selectors,
     as the src/dst addresses of the packet
     have changed due to NAT. */
  if (flow_d_flags & SSH_ENGINE_FLOW_D_NAT_SRC)
    {
      if (pc->u.rule.route_selector_dst & SSH_INTERCEPTOR_ROUTE_KEY_SRC)
	pc->u.rule.route_selector_dst &= ~SSH_INTERCEPTOR_ROUTE_KEY_SRC;

      if (ssh_engine_ip_is_local(engine, &nat_src))
	pc->u.rule.route_selector_dst &=
	  SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_SRC;
      else
	pc->u.rule.route_selector_dst &=
	  ~SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_SRC;
    }

  if (flow_d_flags & SSH_ENGINE_FLOW_D_NAT_DST)
    {
      if (ssh_engine_ip_is_local(engine, &nat_dst))
	pc->u.rule.route_selector_dst &=
	  SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_DST;
      else
	pc->u.rule.route_selector_dst &=
	  ~SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_DST;
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* SSHDIST_IPSEC_NAT */

  /* Determine the index of the rule. */
  rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, rule);
  SSH_ASSERT(rule_index < engine->rule_table_size);

  if (pc->ipproto == SSH_IPPROTO_TCP)
    flow_idle_timeout = rule->flow_idle_session_timeout;
  else
    flow_idle_timeout = rule->flow_idle_datagram_timeout;

  flow_max_lifetime = rule->flow_max_lifetime;

#ifdef SSHDIST_L2TP
  /* Set the ignore L2TP flag for L2TP control traffic flows.  The
     control traffic is only encrypted with IPSec but the packets
     are not encapsulated in UDP/L2TP/PPP. */
  if (pc->ipproto == SSH_IPPROTO_UDP &&
      (pc->u.rule.src_port == SSH_IPSEC_L2TP_PORT ||
       pc->u.rule.dst_port == SSH_IPSEC_L2TP_PORT) &&
      (pc->pp->flags & (SSH_ENGINE_P_TOLOCAL | SSH_ENGINE_P_FROMLOCAL)))
    {
      /* The L2TP control flows must not be timed out. They carry
	 control traffic infrequently so that one is not able to
	 rely on the idle timers. Trust them to be reaped
	 when the IPsec flow is removed or the LRU reaper hits them. */
      flow_d_flags |= SSH_ENGINE_FLOW_D_IGNORE_L2TP;
      flow_max_lifetime = 0;
      flow_idle_timeout = 0;
    }
#endif /* SSHDIST_L2TP */

  /* Check additional flow flags. */
  if ((rule->flags & SSH_ENGINE_LOG_CONNECTIONS) != 0)
    flow_c_flags |= SSH_ENGINE_FLOW_C_LOG_CONNECTIONS;

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  /* Check from protocol monitor whether this is an acceptable
     "session-creation" packet. */
  switch (ssh_engine_is_packet_valid_initial(engine, pc))
    {
    case SSH_ENGINE_MRET_PASS:
      break;

    case SSH_ENGINE_MRET_REJECT:
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_MONITORDROP);
      SSH_DEBUG(SSH_D_FAIL, 
		("flow creation rejected by protocol monitor"));
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      ssh_engine_send_tcp_rst(engine, pc);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
      break;

    case SSH_ENGINE_MRET_DROP:
    default:
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      SSH_DEBUG(SSH_D_FAIL, ("flow creation denied by protocol monitor"));
      return SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
    }
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
  /* Check rate limitation */
  if ((rule->flags & SSH_ENGINE_RATE_LIMIT)
      && ssh_engine_flow_rate_limit(engine, &pc->src, FALSE))
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      SSH_DEBUG(SSH_D_FAIL, ("flow creation prohibited by rate limit"));

      /* Audit flow rate limitation */
      pc->audit.corruption = SSH_PACKET_CORRUPTION_FLOW_RATE_LIMITED;
      pc->audit.ip_option = 0;
      pc->audit.spi = 0;

      return SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
    }
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

  /* The ICMP code/type field is stored in the u.rule.dst_port
     field in the case of ipproto == ICMP{,V6}. */
  flow_src_port = pc->u.rule.src_port;
  flow_dst_port = pc->u.rule.dst_port;

  /* Set from-local/to-local bit in flow */
  if ((pp->flags & SSH_ENGINE_P_FROMLOCAL) != 0
      || (pp->flags & SSH_ENGINE_P_TOLOCAL) != 0)
    flow_d_flags |= SSH_ENGINE_FLOW_D_LOCAL_ENDPNT;

  if ((rule->type == SSH_ENGINE_RULE_TRIGGER)
      && (rule->transform_index == SSH_IPSEC_INVALID_INDEX))
    {
      flow_d_flags |= SSH_ENGINE_FLOW_D_DANGLING;
      flow_c_flags |= SSH_ENGINE_FLOW_C_TRIGGER;
    }









  if ((rule->flags & SSH_PM_ENGINE_RULE_FLOW_REF)
      && (rule->flags
	  & (SSH_PM_ENGINE_RULE_APPGW|SSH_PM_ENGINE_RULE_SLAVE))
      && rule->type == SSH_ENGINE_RULE_APPLY)
    {
      rule_index = rule->depends_on;
      SSH_ASSERT(rule_index != SSH_IPSEC_INVALID_INDEX);
    }

  /* If a packet cannot create a flow, but otherwise it could
     be passed as a no-flow packet, then handle it as a no-flow
     packet.*/
  if (ssh_engine_flow_is_no_flow(pc->ipproto, flow_dst_port)
      && rule->type != SSH_ENGINE_RULE_TRIGGER
#ifdef SSHDIST_IPSEC_NAT
      && (flow_d_flags &
	  (SSH_ENGINE_FLOW_D_NAT_SRC|SSH_ENGINE_FLOW_D_NAT_DST)) == 0
#endif /* SSHDIST_IPSEC_NAT */
      )
    {
      ssh_engine_execute_rule_no_flow(pc);
      return SSH_ENGINE_RULE_EXECUTE_ERROR_OK;
    }

  /* Set reverse transform index to the transform used for 
     decapsulating the packet from a tunnel. */
  if ((pc->flags & SSH_ENGINE_PC_RESTARTED_OUT) == 0)
    reverse_transform_index = pc->prev_transform_index;
  else
    reverse_transform_index = SSH_IPSEC_INVALID_INDEX;

  /* Create a flow table entry for the new flow. */
  if (!ssh_engine_create_flow(engine,
			      rule_index,
			      pc->flow_id,
			      &pc->src, &pc->dst,
			      pc->ipproto,
			      flow_src_port,
			      flow_dst_port,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
			      pc->u.rule.ifnum_dst, pc->u.rule.ifnum_src,
			      pc->u.rule.local_dst, pc->u.rule.local_src,
			      pc->u.rule.mtu_dst, pc->u.rule.mtu_src,
			      pc->u.rule.route_selector_dst,
			      pc->u.rule.route_selector_src,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
			      pc->u.rule.next_hop_index_dst,
			      pc->u.rule.next_hop_index_src,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
			      pp->ifnum_in,
			      pc->u.rule.ifnum_dst,
#ifdef SSHDIST_IPSEC_NAT
			      &nat_src, &nat_dst,
			      nat_src_port, nat_dst_port,
#endif /* SSHDIST_IPSEC_NAT */
			      pc->protocol_xid,
			      flow_c_flags,
			      flow_d_flags,
			      rule->transform_index,
			      reverse_transform_index,
			      flow_idle_timeout,
			      flow_max_lifetime,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
			      pc->pp->extension,
#else
			      NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
			      &flow_index))
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      SSH_DEBUG(SSH_D_FAIL, ("creating flow table node failed"));
      /* Fail, the failure code there will handle freeing next hop nodes. */
      return SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE;
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Cause the flow lookup to be restarted. */
  SSH_DEBUG(SSH_D_MIDOK, ("flow created, restarting lookup, flow=%d",
			  (int) flow_index));
  engine_packet_continue(pc, SSH_ENGINE_RET_RESTART_FLOW_LOOKUP);
  return SSH_ENGINE_RULE_EXECUTE_ERROR_OK;
}

/* Breaks recursion and steps rule execution forward. */
void ssh_engine_execute_rule_step(SshEnginePacketContext pc, 
				  SshEngineRuleExecuteError error)
{
  SSH_INTERCEPTOR_STACK_MARK();

  /* Check for recursion (to eliminate tail recursion in this function). */
  if (pc->flags & SSH_ENGINE_PC_RE_INUSE)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("eliminating tail recursion"));
      pc->recursed_error = error;
      pc->flags |= SSH_ENGINE_PC_RE_RECURSED;
      return;
    }
  pc->flags |= SSH_ENGINE_PC_RE_INUSE;

  /* Execute rule step. The rule execution will finish either with 
     an error (in which case the packet has already been dropped) or
     with state SSH_ENGINE_ST_FINAL (which is handled below). */     
  ssh_engine_execute_rule_step_internal(pc, error);
  
  /* Process final step here where the stack usage is minimal. */
  if (pc->u.rule.state == SSH_ENGINE_ST_FINAL)
    {
      if (pc->flags & SSH_ENGINE_PC_REROUTE_FLOW)
	{
	  ssh_engine_route_change_final(pc, SSH_ENGINE_RULE_EXECUTE_ERROR_OK);
	}
      else
	{
	  error = ssh_engine_execute_rule_step_final(pc);
	  if (error != SSH_ENGINE_RULE_EXECUTE_ERROR_OK)
	    ssh_engine_execute_rule_step_internal(pc, error);
	}
    }
}

/* This functions is called during policy decisions when we have found
   a matching rule.  The found rule is stored in pc->rule.  This
   function excutes the rule - this either processes the packet
   immediately or creates a flow.  This may also start an asynchronous
   process (possibly involving the policy manager) e.g. to negotiate
   new security associations.  This returns SSH_ENGINE_RET_ASYNC if an
   asynchronous operation was started, SSH_ENGINE_RET_ERROR if an
   error caused pc->pp to become invalid, and can return other values
   of the type SshEngineActionRet.  The caller must have incremented
   the reference count of the rule before calling this.  This will eventually
   call engine_packet_continue when done, which will decrement the
   reference count of the rule when control returns to it. */

SshEngineActionRet
ssh_engine_execute_rule(SshEnginePacketContext pc)
{
  SshInterceptorPacket pp;
  SshEnginePolicyRule rule;
  SshEngine engine;

  SSH_INTERCEPTOR_STACK_MARK();

  engine = pc->engine;
  pp = pc->pp;
  rule = pc->rule;

  SSH_ASSERT(rule->refcnt > 0);
  SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4 ||
             pp->protocol == SSH_PROTOCOL_IP6);
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SSH_ASSERT(pc->protocol_offset == 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  pc->transform = 0;
  pc->flags &= ~(SSH_ENGINE_PC_RE_INUSE|SSH_ENGINE_PC_RE_RECURSED);

  /* Mark that this rule has been used. Trigger rules are marked as
     used only after a trigger has been succesfully handled by
     the policymanager and the corresponding add_rule() has been called. */
  if (rule->type != SSH_ENGINE_RULE_TRIGGER)
    rule->flags |= SSH_ENGINE_RULE_USED;

  switch (rule->type)
    {
    case SSH_ENGINE_RULE_DROP:
      SSH_DEBUG(SSH_D_HIGHOK, ("RULE_DROP"));
      /* We should silently drop the packet without creating a flow.
         Do it now. */
      if (rule->flags & SSH_ENGINE_LOG_CONNECTIONS)
        {
          pc->audit.corruption = SSH_PACKET_CORRUPTION_POLICY_DROP;
	  pc->audit.ip_option = 0;
	  pc->audit.spi = 0;

          /* Set pc audit corrupt flag, so we get audited even
             if "corrupt packets" are not normally audited by fastpath. */
          pc->flags |= SSH_ENGINE_PC_AUDIT_CORRUPT;
        }
      /* No need to `SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_DROP)',
         because the return value instructs the fastpath to do that in
         any case. */
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_RULEDROP);
      return SSH_ENGINE_RET_DROP;

    case SSH_ENGINE_RULE_REJECT:
      /* We should drop the packet without creating a flow, but send
         back a TCP RST and/or ICMP.  Do it now. */
      SSH_DEBUG(SSH_D_HIGHOK, ("RULE_REJECT"));

      /* Auditing of this rule match must be done here. This is
         not very clean, as this code is duplicated at the end of the
         fast path, but ssh_engine_send_icmp_error() steals the packet
         'pc->pp' and unless we want to increase memory use over the
         routing request, we do this here. ssh_engine_audit_packet_context
	 takes care of sending the appropiate reject message, send_tcp_rst()
	 or send_icmp_error(). */
      if (rule->flags & SSH_ENGINE_LOG_CONNECTIONS)
        {
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_POLICY_REJECT;
	  pc->audit.ip_option = 0;
	  pc->audit.spi = 0;

	  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_RULEREJECT);
	  ssh_engine_audit_packet_context(engine, pc);
	  return SSH_ENGINE_RET_DROP;
	}




      if (pc->ipproto == SSH_IPPROTO_TCP)
        {
	  ssh_engine_send_tcp_rst(engine, pc);
	}
      else
        {
#if defined (WITH_IPV6)
          if (pc->pp->protocol == SSH_PROTOCOL_IP6)
            ssh_engine_send_icmp_error(engine, pc,
                                       SSH_ICMP6_TYPE_UNREACH,
                                       SSH_ICMP6_CODE_UNREACH_PROHIBITED,
                                       0);
          else
#endif /* WITH_IPV6 */
            ssh_engine_send_icmp_error(engine, pc,
                                       SSH_ICMP_TYPE_UNREACH,
                                       SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT,
                                       0);
        }
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_RULEREJECT);
      return SSH_ENGINE_RET_DROP;

    case SSH_ENGINE_RULE_TRIGGER:
      if ((rule->flags & SSH_ENGINE_NO_FLOW)
          || (pc->flags & SSH_ENGINE_PC_HIT_TRIGGER))
        {
          /* We should pass the packet to the policy manager. */
          if (ssh_engine_trigger(pc, rule,
                                 (pc->flags & SSH_ENGINE_PC_HIT_TRIGGER)
				 ? pc->flow_index : SSH_IPSEC_INVALID_INDEX))
            return SSH_ENGINE_RET_DROP;
          return SSH_ENGINE_RET_ERROR;
        }
      /* Fall-through. Execute rule */
    case SSH_ENGINE_RULE_PASS:
    case SSH_ENGINE_RULE_APPLY:

      if (rule->type == SSH_ENGINE_RULE_PASS)
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("RULE_PASS index=%u flags=0x%08x prec=0x%08x",
		   (unsigned int)
                   SSH_ENGINE_GET_RULE_INDEX(engine, rule),
		   (unsigned int)
                   rule->flags,
		   (unsigned int)
		   rule->precedence));
      else if (rule->type == SSH_ENGINE_RULE_APPLY)
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("RULE_APPLY index=%u flags=0x%08x prec=%08x",
		   (unsigned int)
                   SSH_ENGINE_GET_RULE_INDEX(engine, rule),
		   (unsigned int)
                   rule->flags,
		   (unsigned int)
		   rule->precedence));
      else if (rule->type == SSH_ENGINE_RULE_TRIGGER)
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("RULE_TRIGGER index=%u flags=0x%08x prec=%08x",
		   (unsigned int)
                   SSH_ENGINE_GET_RULE_INDEX(engine, rule),
		   (unsigned int)
                   rule->flags,
		   (unsigned int)
		   rule->precedence));
      else
        SSH_NOTREACHED;

      /* A memory-saving kludge: In case of ICMP and ICMPV6, store the
         type and code into the dst_port, from where they will be
         copied to the flow record. */



      if (pc->ipproto == SSH_IPPROTO_ICMP)
        {
          pc->u.rule.dst_port = (pc->icmp_type << 8) | pc->u.rule.icmp_code;
          if (pc->u.rule.dst_port == (SSH_ICMP_TYPE_ECHO << 8))
            {
              const unsigned char *ucp;
              ucp = ssh_interceptor_packet_pullup_read(pp,
                             (pc->hdrlen + 8 > pc->packet_len
                              ? pc->packet_len
                              : pc->hdrlen + 8));
              if (!ucp)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("execute_rule pullup failed"));
#if defined (WITH_IPV6)
		error:
#endif /* WITH_IPV6 */
                  pc->transform = 0;
		  pc->pp = NULL;
                  return SSH_ENGINE_RET_ERROR; /* pp has been freed */
                }
              pc->u.rule.src_port = SSH_GET_16BIT(ucp + pc->hdrlen + 4);
            }
        }
#if defined (WITH_IPV6)
      else if (pc->ipproto == SSH_IPPROTO_IPV6ICMP)
        {
          pc->u.rule.dst_port = (pc->icmp_type << 8) | pc->u.rule.icmp_code;
          if (pc->u.rule.dst_port == (SSH_ICMP6_TYPE_ECHOREQUEST << 8))
            {
              unsigned char buf[2];

              if (pc->hdrlen + 6 > pc->packet_len)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("execute_rule too short packet"));
		  ssh_interceptor_packet_free(pc->pp);
                  goto error;
                }
              ssh_interceptor_packet_copyout(pp, pc->hdrlen + 4, buf, 2);
              pc->u.rule.src_port = SSH_GET_16BIT(buf);
            }
        }
#endif /* WITH_IPV6 */

      /* Start from the init state. */
      pc->u.rule.state = SSH_ENGINE_ST_INIT;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->u.rule.next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;
      pc->u.rule.next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
      pc->u.rule.next_hop_index_appgw = SSH_IPSEC_INVALID_INDEX;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */



      ssh_engine_execute_rule_step(pc, SSH_ENGINE_RULE_EXECUTE_ERROR_OK);
      return SSH_ENGINE_RET_ASYNC;

#ifndef SSH_IPSEC_SMALL
    case SSH_ENGINE_RULE_DORMANT_APPLY:
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_RULEDROP);
      return SSH_ENGINE_RET_FAIL;
#endif /* SSH_IPSEC_SMALL */

    default:
      ssh_fatal("ssh_engine_execute_rule: unsupported rule type %d",
                (int)rule->type);
      return SSH_ENGINE_RET_FAIL;
    }
}

/* Schedule a route_change_next via a timeout */
static void
ssh_engine_route_change_schedule(SshEngine engine)
{
  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_MY, ("scheduling another re-route operation"));
  /* Schedule a timeout for the next iteration */
  ssh_kernel_timeout_register(0L, 100000L,

                              ssh_engine_route_change_next, engine);
}

/* Complete the route change of a flow */
void ssh_engine_route_change_final(SshEnginePacketContext pc,
				   SshEngineRuleExecuteError error)
{
  SshEngine engine = pc->engine;
  SshEngineFlowData d_flow = NULL;
  SshEngineFlowControl c_flow;
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;
  SshEngineFlowStatus flow_status;
  SshEnginePolicyRule old_rule;
  Boolean ok;
  SshUInt32 idx;
  SshEngineTransformControl old_fwd_trd, old_rev_trd;
  SshUInt32 old_fwd_trd_idx, old_rev_trd_idx;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt32 next_hop_index_src, next_hop_index_dst, nh_tmp;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  idx = engine->flow_reroute_idx;
  old_rev_trd_idx = SSH_IPSEC_INVALID_INDEX;
  old_fwd_trd_idx = SSH_IPSEC_INVALID_INDEX;
  old_fwd_trd = old_rev_trd = NULL;
  old_rule = NULL;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

  next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
  next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("route change rule execution completed: idx=%d error=%s (%d) "
             "nh: forward=%d reverse=%d",
             (int) idx, 
	     (error == SSH_ENGINE_RULE_EXECUTE_ERROR_OK ? "ok" : "failure"),
	     (int) error,
             (int) pc->u.rule.next_hop_index_dst,
             (int) pc->u.rule.next_hop_index_src));
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ok = TRUE;

  SSH_ASSERT(idx != SSH_IPSEC_INVALID_INDEX);
  c_flow = SSH_ENGINE_GET_FLOW(engine, idx);

  if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID))
    goto done;

  /* Flow still wants itself rerouted? */
  if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_PENDING)
    {
      ok = FALSE;

      if (error == SSH_ENGINE_RULE_EXECUTE_ERROR_OK)
        {
          c_flow->control_flags &= ~SSH_ENGINE_FLOW_C_REROUTE_PENDING;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          /* Cache routing information for tuning next hop nodes.
	     This also ensures that if we abort the operation
	     below, the refcnts get freed. */
          next_hop_index_src = pc->u.rule.next_hop_index_src;
          next_hop_index_dst = pc->u.rule.next_hop_index_dst;
          pc->u.rule.next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
          pc->u.rule.next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

          if (c_flow->rule_index == SSH_IPSEC_INVALID_INDEX)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("flow not associated with a rule. "
                         "Failing operation.\n"));
              goto done;
            }

	  d_flow = FASTPATH_GET_FLOW(engine->fastpath, idx);
	  SSH_ASSERT(d_flow != NULL);
	  SSH_ASSERT(d_flow->data_flags & SSH_ENGINE_FLOW_D_VALID);

	  /* Existing flow information is more correct than the
	     one cached into the packet context. */
	  if (d_flow->generation != pc->flow_generation)
	    {
	      FASTPATH_RELEASE_FLOW(engine->fastpath, idx);
	      ok = TRUE;
	      goto done;
	    }

	  if (!(d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING))
	    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
	      /* Install the new routing information. */
	      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R)
		{
		  nh_tmp = d_flow->forward_nh_index;
		  d_flow->forward_nh_index = next_hop_index_dst;
		  next_hop_index_dst = nh_tmp;
		}
	      
	      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I)
		{
		  /* Decrement refcnt of previous next hop node and patch
		     in replacement */
		  nh_tmp = d_flow->reverse_nh_index;
		  d_flow->reverse_nh_index = next_hop_index_src;
		  next_hop_index_src = nh_tmp;
		}
	      
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
	      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R)
		{
		  d_flow->forward_ifnum = pc->u.rule.ifnum_dst;
		  d_flow->forward_local = pc->u.rule.local_dst;
		  d_flow->forward_mtu = pc->u.rule.mtu_dst;
		}
	      
	      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I)
		{
		  d_flow->reverse_ifnum = pc->u.rule.ifnum_src;
		  d_flow->reverse_local = pc->u.rule.local_src;
		  d_flow->reverse_mtu = pc->u.rule.mtu_src;
		}
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
	    }	      

          /* Modify flow parameters according to routing information. */
          if (d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
            {
              if (d_flow->forward_transform_index != SSH_IPSEC_INVALID_INDEX)
                {
		  c_trd = SSH_ENGINE_GET_TRD(engine,
					     d_flow->forward_transform_index);

                  if (c_trd != NULL &&
		      (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R))
                    {
		      d_trd = 
			FASTPATH_GET_TRD(engine->fastpath,
					 d_flow->forward_transform_index);
		      d_trd->own_ifnum = pc->u.rule.ifnum_dst;

		      c_trd->control_flags &=
			~SSH_ENGINE_TR_C_IPSEC_FLOW_REROUTE_ONGOING;

		      SSH_DEBUG(SSH_D_MIDOK, 
				("Updating IPsec flow's (%d) incoming "
				 "forward and reverse ifnum %d -> %d",
				 idx, d_flow->incoming_forward_ifnum, 
				 d_trd->own_ifnum));
		      d_flow->incoming_forward_ifnum = d_trd->own_ifnum;
		      d_flow->incoming_reverse_ifnum = d_trd->own_ifnum;
		      		      
		      FASTPATH_COMMIT_TRD(engine->fastpath,
					  d_flow->forward_transform_index,
					  d_trd);
		    }
		}
            }
          else
            {
              if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I)
		{
		  SSH_DEBUG(SSH_D_MIDOK, 
			    ("Updating normal flow's (%d) incoming forward "
			     "ifnum %d -> %d",
			     idx, d_flow->incoming_forward_ifnum, 
			     pc->u.rule.ifnum_src));
		  d_flow->incoming_forward_ifnum = pc->u.rule.ifnum_src;
		}
              if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R)
		{
		  SSH_DEBUG(SSH_D_MIDOK,
			 ("Updating normal flow's (%d) incoming reverse "
			  "ifnum %d -> %d",
			  idx, d_flow->incoming_reverse_ifnum, 
			  pc->u.rule.ifnum_dst));
		  d_flow->incoming_reverse_ifnum = pc->u.rule.ifnum_dst;
		}
            }

          /* Re-attach flows. */
          if (!(d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING))
            {
              /* The purpose of the exercise below is to
                 evaluate the flow against the existing policy
                 by dangling/undangling it. The transforms/rules
                 have temporary refcounts on them, so they do not
                 disappear during the operation. */

              SSH_ASSERT(old_rule == NULL && old_rev_trd == NULL
                         && old_fwd_trd == NULL);

              if ((d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING) == 0)
                {
                  /* Grab tmp refcnt on rule */
                  SSH_ASSERT(c_flow->rule_index != SSH_IPSEC_INVALID_INDEX);
                  old_rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
                  old_rule->refcnt++;

                  /* Grab tmp refcounts to these transforms. */
                  if (d_flow->forward_transform_index
		      != SSH_IPSEC_INVALID_INDEX)
                    {
                      old_fwd_trd =
                        SSH_ENGINE_GET_TRD(engine,
                                           d_flow->forward_transform_index);
                      if (old_fwd_trd == NULL)
			{
			  FASTPATH_RELEASE_FLOW(engine->fastpath, idx);
			  goto done;
			}

                      old_fwd_trd_idx = d_flow->forward_transform_index;
                      SSH_ENGINE_INCREMENT_TRD_REFCNT(old_fwd_trd);
                    }
                  if (d_flow->reverse_transform_index
		      != SSH_IPSEC_INVALID_INDEX)
                    {
                      old_rev_trd =
                        SSH_ENGINE_GET_TRD(engine,
                                           d_flow->reverse_transform_index);
                      if (old_rev_trd == NULL)
			{
			  FASTPATH_RELEASE_FLOW(engine->fastpath, idx);
			  goto done;
			}

                      old_rev_trd_idx = d_flow->reverse_transform_index;
                      SSH_ENGINE_INCREMENT_TRD_REFCNT(old_rev_trd);
                    }

		  /* Commit the changes we have done so far and relase the
		     fastpath lock for the dangle/undangle */
		  FASTPATH_COMMIT_FLOW(engine->fastpath, idx, d_flow);

                  /* Dangle flow.. for the undangle operation coming up. */
                  if (ssh_engine_flow_dangle(engine, idx) == FALSE)
                    {
                      SSH_DEBUG(SSH_D_FAIL, ("Unable to dangle flow=%d",
					     (int) idx));
                      goto done;
                    }
                }
	      else
		{
		  /* Commit the changes we have done so far and relase the
		     fastpath lock for the undangle operation. */
		  FASTPATH_COMMIT_FLOW(engine->fastpath, idx, d_flow);
		}
              flow_status = ssh_engine_flow_undangle(engine, idx);

              /* Remove placeholder refcounts. */
              if (old_fwd_trd != NULL)
                {
                  ssh_engine_decrement_transform_refcnt(engine,
                                                        old_fwd_trd_idx);
                  old_fwd_trd = NULL;
                }

              if (old_rev_trd != NULL)
                {
                  ssh_engine_decrement_transform_refcnt(engine,
                                                        old_rev_trd_idx);
                  old_rev_trd = NULL;
                }

              if (old_rule != NULL)
                {
                  ssh_engine_decrement_rule_refcnt(engine, old_rule);
                  old_rule = NULL;
                }

              SSH_ASSERT(old_rule == NULL && old_rev_trd == NULL
                         && old_fwd_trd == NULL);

              switch (flow_status)
                {
                case SSH_ENGINE_FLOW_STATUS_ERROR:
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Error in undangling flow %d. Freeing flow.",
                             (int) idx));
                  goto done;

                case SSH_ENGINE_FLOW_STATUS_WELL_DEFINED:
                  SSH_DEBUG(SSH_D_NICETOKNOW, ("Flow %d re-routed.",
					       (int) idx));
                  ok = TRUE;
                  break;

                case SSH_ENGINE_FLOW_STATUS_REVERSE_TRIGGER:
                case SSH_ENGINE_FLOW_STATUS_DANGLING:
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Flow %d pending after re-route.",
			     (int) idx));
                  ok = TRUE;
                  break;

                default:
                  SSH_NOTREACHED;
                }
	    }
          else
            {
              /* Try to recompute flow ids */
              if ((ssh_engine_flow_compute_flow_id_from_flow(engine, idx,
							     d_flow,
							     FALSE,
							     d_flow->
							     reverse_flow_id)
                   == FALSE)
                  ||
                  (ssh_engine_flow_compute_flow_id_from_flow(engine, idx,
							     d_flow,
							     TRUE,
							     d_flow->
							     forward_flow_id)
                   == FALSE))
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Error recomputing flow id for flow %d.",
			     (int) idx));

		  FASTPATH_RELEASE_FLOW(engine->fastpath, idx);
                  goto done;
                }

              ok = TRUE;
	      FASTPATH_COMMIT_FLOW(engine->fastpath, idx, d_flow);
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Rule execution failed. Destroying flow."));
          goto done;
        }
      ok = TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Flow re-route results discarded."));
    }

 done:
#ifdef SSHDIST_IPSEC_FIREWALL
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SSH_ASSERT(pc->u.rule.next_hop_index_appgw == SSH_IPSEC_INVALID_INDEX);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* SSHDIST_IPSEC_FIREWALL */

  /* Remove placeholder refcounts. */
  if (old_fwd_trd != NULL)
    ssh_engine_decrement_transform_refcnt(engine,
                                          old_fwd_trd_idx);

  if (old_rev_trd != NULL)
    ssh_engine_decrement_transform_refcnt(engine,
                                          old_rev_trd_idx);

  if (old_rule != NULL)
    ssh_engine_decrement_rule_refcnt(engine, old_rule);


  /* Do not leave any refcnts dangling */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (next_hop_index_src != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_decrement_next_hop_refcnt(engine,
					 next_hop_index_src);

  if (next_hop_index_dst != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_decrement_next_hop_refcnt(engine,
					 next_hop_index_dst);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (ok == FALSE)
    {	        
      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING)
	{
	  SSH_DEBUG(SSH_D_FAIL,
		    ("Re-routing operation failed for incoming ipsec flow. "
		     "Marking transform for deletion."));

	  c_flow->hard_expire_time = engine->run_time;
	  c_flow->rekey_attempts = SSH_ENGINE_MAX_REKEY_ATTEMPTS;
	  c_flow->control_flags |= SSH_ENGINE_FLOW_C_IPSECSOFTSENT;	 
	}
      else
	{
	  SSH_DEBUG(SSH_D_FAIL,
		    ("Re-routing operation failed. Freeing flow %u.",
		     (unsigned int) idx));
	  
	  ssh_engine_free_flow(engine, idx);
	}
    }
  
  /* Return refcnt on rule taken in route_change_next() */
  ssh_engine_decrement_rule_refcnt(engine, pc->rule);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Reschedule for next operation */
  ssh_engine_route_change_schedule(engine);

  /* Return dummy packet */
  SSH_ASSERT(pc->pp != NULL);
  ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;

  /* Return packet context */

  ssh_engine_free_pc(engine, pc);

  return;
}

/* Handle next flow in line */
void ssh_engine_route_change_next(void *context)
{
  SshEngine engine = (SshEngine) context;
  SshUInt32 idx;
  SshEnginePolicyRule rule;
  Boolean src_local = FALSE, dst_local = FALSE;
  SshEngineFlowControl ic_flow, rc_flow, c_flow;
  SshEngineFlowData d_flow; 
#ifdef SSHDIST_IPSEC_FIREWALL
  SshEngineFlowData tmp_flow;
#endif /* SSHDIST_IPSEC_FIREWALL */
  SshIpAddrStruct src, dst;
  SshUInt16 src_port, dst_port;
  SshEnginePacketContext pc;
  SshInterceptorPacket pp;
  
  SSH_INTERCEPTOR_STACK_MARK();

  /* Allocate a dummy packet for rule execution */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    SSH_PACKET_FROMPROTOCOL, /* Set later */
                                    SSH_PROTOCOL_IP4, /* Set later */
                                    SSH_INTERCEPTOR_INVALID_IFNUM, /* Set   */
				    SSH_INTERCEPTOR_INVALID_IFNUM, /* later */
                                    20);

  if (pp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate dummy packet"));
      ssh_engine_route_change_schedule(engine);
      return;
    }

  /* Allocate a packet context for the new packet. */
  if ((pc = ssh_engine_alloc_pc(engine)) == NULL)
    {
      ssh_interceptor_packet_free(pp);
      ssh_engine_route_change_schedule(engine);
      return;
    }
  pc->rule = NULL;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  idx = engine->flow_reroute_idx;

  do {
    c_flow = SSH_ENGINE_GET_FLOW(engine, idx);

    if (c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID &&
	c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_PENDING)
      {
        /* We cannot reroute dangling flows currently, as rerouting
           requires that forward and reverse transform indices be
           meaingful, otherwise we might end up doing routing
           for the actual flow src/dst address instead of tunnel
           end points. */

#ifdef SSHDIST_IPSEC_FIREWALL
        if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID)
	    && c_flow->pair_flow_idx != idx
	    && c_flow->pair_flow_idx != SSH_IPSEC_INVALID_INDEX)
	  {

	    if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I)
	      {
		ic_flow = c_flow;
		rc_flow = SSH_ENGINE_GET_FLOW(engine, idx);

		tmp_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath,
                                                       c_flow->pair_flow_idx);

		SSH_ASSERT(tmp_flow->data_flags & SSH_ENGINE_FLOW_D_VALID);

#ifdef SSHDIST_IPSEC_NAT
                dst = tmp_flow->nat_dst_ip;
                dst_port = tmp_flow->nat_dst_port;
#else /* SSHDIST_IPSEC_NAT */
                dst = tmp_flow->dst_ip;
                dst_port = tmp_flow->dst_port;
#endif /* SSHDIST_IPSEC_NAT */

		FASTPATH_RELEASE_FLOW(engine->fastpath, c_flow->pair_flow_idx);
		d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, idx);
		
                src = d_flow->src_ip;
                src_port = d_flow->src_port;
	      }
	    else
	      {
		SSH_ASSERT(c_flow->control_flags&SSH_ENGINE_FLOW_C_REROUTE_R);

		ic_flow = SSH_ENGINE_GET_FLOW(engine, c_flow->pair_flow_idx);
		rc_flow = c_flow;

		tmp_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath,
						      c_flow->pair_flow_idx);

		SSH_ASSERT(tmp_flow->data_flags & SSH_ENGINE_FLOW_D_VALID);

                src = tmp_flow->src_ip;
                src_port = tmp_flow->src_port;

		FASTPATH_RELEASE_FLOW(engine->fastpath, c_flow->pair_flow_idx);

		d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, idx);

#ifdef SSHDIST_IPSEC_NAT
                dst = d_flow->nat_dst_ip;
                dst_port = d_flow->nat_dst_port;
#else /* SSHDIST_IPSEC_NAT */
                dst = d_flow->dst_ip;
                dst_port = d_flow->dst_port;
#endif /* SSHDIST_IPSEC_NAT */
	      }
	  }
	else
#endif /* SSHDIST_IPSEC_FIREWALL */
	  {
	    d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, idx);

	    SSH_ASSERT(d_flow->data_flags & SSH_ENGINE_FLOW_D_VALID);

	    ic_flow = rc_flow = c_flow;

            src = d_flow->src_ip;
            src_port = d_flow->src_port;

#ifdef SSHDIST_IPSEC_NAT
            dst = d_flow->nat_dst_ip;
            dst_port = d_flow->nat_dst_port;
#else /* SSHDIST_IPSEC_NAT */
            dst = d_flow->dst_ip;
            dst_port = d_flow->dst_port;
#endif /* SSHDIST_IPSEC_NAT */
	  }

	/* Now we have id_flow and rd_flow, which point to copies
	   cached on our stack OR the fetched copy. Then we have a
	   valid d_flow on which we have a lock in the fastpath. */

	if (((ic_flow->control_flags & rc_flow->control_flags)
	     & SSH_ENGINE_FLOW_C_VALID)
            && ((d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING) == 0)
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
            && ((d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
                || ((d_flow->reverse_nh_index != SSH_IPSEC_INVALID_INDEX)
                    && (d_flow->forward_nh_index != SSH_IPSEC_INVALID_INDEX)))
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
            && (c_flow->rule_index != SSH_IPSEC_INVALID_INDEX))
          {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
            SSH_DEBUG(SSH_D_LOWSTART,
                      ("preparing to reroute flow %d "
                       "(nh forward %d reverse %d)",
                       (int) idx, (int) d_flow->forward_nh_index,
		       (int) d_flow->reverse_nh_index));
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

            rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
            SSH_ASSERT(rule != NULL);

            /* Ok. bootstrap re-route operation. */
            pp->flags = SSH_PACKET_FROMADAPTER;
            ssh_engine_init_pc(pc, engine, pp, rule->tunnel_id, NULL);
            pc->flags = SSH_ENGINE_PC_REROUTE_FLOW | SSH_ENGINE_PC_INUSE;
            pc->transform_index = SSH_IPSEC_INVALID_INDEX;
            pc->prev_transform_index = d_flow->reverse_transform_index;
            pc->next = NULL;
            pc->engine = engine;
            pc->rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
	    pc->rule->refcnt++;

	    pc->flow_generation = d_flow->generation;
	  
	    if (d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
	      pc->flags |= SSH_ENGINE_FLOW_D_IPSECINCOMING;
	    
            pc->src = src;
            pc->u.rule.src_port = src_port;

            /* We are interested in the routing information for
               the destination address, as the packet goes out. Otherwise
               things will break later on, as the ST_FINAL NAT phase
               is skipped. */
            pc->dst = dst;
            pc->u.rule.dst_port = dst_port;

            pc->ipproto = d_flow->ipproto;
            if (pc->ipproto == SSH_IPPROTO_ICMP
              || pc->ipproto == SSH_IPPROTO_IPV6ICMP)
              {
                pc->icmp_type = (d_flow->dst_port >> 8);
                pc->u.rule.icmp_code = (d_flow->dst_port & 0xff);
              }

	    /* These fields are used by ssh_engine_create_route_key */



	    pc->u.rule.spi = 0; 
	    pc->u.rule.tos = 0;
	    pc->u.rule.priority = 0;
	    pc->audit.flowlabel = 0;

            pc->u.rule.state = SSH_ENGINE_ST_INIT;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
            pc->u.rule.next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;
            pc->u.rule.next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
#ifdef SSHDIST_IPSEC_FIREWALL
            pc->u.rule.next_hop_index_appgw = SSH_IPSEC_INVALID_INDEX;
#endif /* SSHDIST_IPSEC_FIREWALL */
	    if (!(d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING))
	      {
		SshEngineNextHopData d_nh;
		
		d_nh = FASTPATH_GET_NH(engine->fastpath,
				       d_flow->reverse_nh_index);
		
		SSH_ASSERT(d_nh != NULL);
		src_local = (d_nh->flags & SSH_ENGINE_NH_LOCAL ? TRUE : FALSE);
		
		FASTPATH_RELEASE_NH(engine->fastpath, 
				    d_flow->reverse_nh_index);
		
		d_nh = FASTPATH_GET_NH(engine->fastpath,
				       d_flow->forward_nh_index);
		
		SSH_ASSERT(d_nh != NULL);
		dst_local = (d_nh->flags & SSH_ENGINE_NH_LOCAL ? TRUE : FALSE);
		FASTPATH_RELEASE_NH(engine->fastpath, 
				    d_flow->forward_nh_index);
	      }
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
            src_local = d_flow->reverse_local;
            dst_local = d_flow->forward_local;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

	    /* If we are re-routing an IPSec incoming flow, we are in
	       effect actually re-routing also the trd->own_ifnum. So
	       grab the parameters as they are in the actual encapsulation. */
	    if (d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
	      {
		SshEngineTransformControl c_trd;
		SshEngineTransformData d_trd;
		
		c_trd = SSH_ENGINE_GET_TRD(engine,
					   d_flow->forward_transform_index);
		d_trd = 
		  FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
					     d_flow->forward_transform_index);
		if (c_trd != NULL)
		  {
		    src_local = FALSE;
		    dst_local = TRUE;
		    pc->src = d_trd->gw_addr;
		    pc->dst = d_trd->own_addr;
		  }
		FASTPATH_RELEASE_TRD(engine->fastpath,
				     d_flow->forward_transform_index);
	      }

            /* Keep _P_FROMLOCAL _P_TOLOCAL flags still, because they
               might have been required by the rule which instantiated
               this flow, even if the new routing might not set them. */

            if (dst_local
		&& (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R) != 0)
              {
                pc->pp->flags |= SSH_ENGINE_P_TOLOCAL;
		if (src_local)
		  {
		    pc->pp->flags &= ~(SSH_PACKET_FROMADAPTER);
		    pc->pp->flags |= SSH_PACKET_FROMPROTOCOL;
		  }
		else
		  {
		    pc->pp->flags &= ~(SSH_PACKET_FROMPROTOCOL);
		    pc->pp->flags |= SSH_PACKET_FROMADAPTER;
		  }
              }

            if (src_local
		&& (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I) != 0)
              {
                pc->pp->flags |= SSH_ENGINE_P_FROMLOCAL;
                pc->pp->flags &= ~(SSH_PACKET_FROMADAPTER);
                pc->pp->flags |= SSH_PACKET_FROMPROTOCOL;
              }

            if (SSH_IP_IS6(&d_flow->src_ip))
              pc->pp->protocol = SSH_PROTOCOL_IP6;

	    FASTPATH_RELEASE_FLOW(engine->fastpath, idx);
            engine->flow_reroute_idx = idx;
            ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

            ssh_engine_execute_rule_step(pc, SSH_ENGINE_RULE_EXECUTE_ERROR_OK);
            return;
          }
	FASTPATH_RELEASE_FLOW(engine->fastpath, idx);
      }
    idx++;
    idx %= engine->flow_table_size;
  } while (idx != engine->flow_reroute_last);
  SSH_DEBUG(SSH_D_MIDOK, ("reroute of all flows complete."));

  /* No valid nodes left to reroute. */
  engine->flow_reroute_idx = SSH_IPSEC_INVALID_INDEX;
  engine->flow_reroute_last = SSH_IPSEC_INVALID_INDEX;

  if (pc->rule)
    ssh_engine_decrement_rule_refcnt(engine, pc->rule);
  
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Return dummy packet */
  pc->pp = NULL;
  SSH_ASSERT(pp != NULL);
  ssh_interceptor_packet_free(pp);

  /* Return packet context */
  ssh_engine_free_pc(engine, pc);
}

/* Signal the engine to cycle through all flows and consider
   any pending reroute flags for those flows. */
void
ssh_engine_route_change_cycle(SshEngine engine)
{
  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Start iterating over the first flow */
  if (engine->flow_reroute_idx == SSH_IPSEC_INVALID_INDEX)
    {
      engine->flow_reroute_idx = 0;
      engine->flow_reroute_last = 0;

      ssh_engine_route_change_schedule((void *)engine);
    }
  else
    {
      engine->flow_reroute_last = engine->flow_reroute_idx;
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("route change already in progress. extending ringbuffer."));
    }
}

/* This callback may get called by the interceptor whenever routing
   information changes or from the ssh_pme_redo_flows() API. However,
   sending these callbacks is optional, and the engine will also
   otherwise periodically update cached information.  This function can
   get called concurrently with other functions. It expects to receive
   the engine pointer as context.
   The function initiates an asynchronous iteration over all flows,
   that updates the routing information in each flow, re-evaluates
   the policy rule for the flow, sets/clears any tunneling as required
   by new rule, and finally re-computes flow-ids. The flow may be left
   dangling. */
void
ssh_engine_route_change_callback(void *context)
{
  SshEngine engine = (SshEngine) context;
  SshUInt32 idx;
  SshEngineFlowControl c_flow;
#ifdef DEBUG_LIGHT
  SshUInt32 cnt = 0;
#endif /* DEBUG_LIGHT */

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_MIDSTART, ("route change callback called"));

  /* Mark all valid flows for re-routing ASAP. The flows will
     keep operating normally, untill they have been re-routed
     and re-policed. */

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Mark flows for rerouting */
  for (idx = 0; idx < engine->flow_table_size; idx++)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, idx);
      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID)
        {
          c_flow->control_flags |= SSH_ENGINE_FLOW_C_REROUTE_PENDING;
#ifdef DEBUG_LIGHT
          cnt++;
#endif /* DEBUG_LIGHT */
	}
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("scheduled %d flows for re-routing",
			       (int) cnt));

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Mark cached media addresses for update. */




  for (idx = 0; idx < engine->next_hop_hash_size; idx++)
    {
      SshEngineNextHopControl c_nh;
      SshEngineNextHopData d_nh;

      c_nh = SSH_ENGINE_GET_NH(engine, idx);
      d_nh = FASTPATH_GET_NH(engine->fastpath, idx);
      if (c_nh->refcnt > 0)
        d_nh->flags |= SSH_ENGINE_NH_REROUTE;
      FASTPATH_COMMIT_NH(engine->fastpath, idx, d_nh);
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ssh_engine_route_change_cycle(engine);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  return;
}

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/* Creates the initiator and responder mappings for an application
   gateway. */
void ssh_engine_pme_create_appgw_mappings(SshEngine engine,
					  SshUInt32 rule_index,
					  SshUInt32 flow_index,
					  SshUInt32 flags,
					  SshUInt32 tunnel_id,
					  SshInterceptorProtocol protocol,
					  SshUInt8 ipproto,
					  const SshIpAddr initiator_ip,
					  SshUInt16 initiator_port,
					  const SshIpAddr responder_orig_ip,
					  SshUInt16 responder_orig_port,
					  const SshIpAddr responder_ip,
					  SshUInt16 responder_port,
					  const SshIpAddr appgw_ip,
					  SshUInt16 appgw_initiator_port,
					  SshUInt16 appgw_responder_port,
					  SshUInt32 trigger_rule_index,
					  SshUInt32 transform_index,
					  SshUInt32 prev_transform_index,
					  SshUInt32 flow_idle_timeout,
					  SshPmeAppgwCB callback,
					  void *context)
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp = NULL;
  Boolean initiator_local;
  Boolean responder_local;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(SSH_IP_DEFINED(initiator_ip));
  SSH_ASSERT(SSH_IP_DEFINED(responder_orig_ip));
  SSH_ASSERT(SSH_IP_DEFINED(responder_ip));
  SSH_ASSERT(SSH_IP_DEFINED(appgw_ip));

  SSH_DEBUG(SSH_D_MY,
            ("creating appgw mappings for session %@:%u -> %@:%u "
             "for trigger rule %u prev_transform=0x%08x transform=0x%08x",
             ssh_ipaddr_render,initiator_ip,
             initiator_port,
             ssh_ipaddr_render, responder_orig_ip,
             responder_orig_port,
             (unsigned int) trigger_rule_index,
             (unsigned int) prev_transform_index,
	     (unsigned int) transform_index));

  SSH_ASSERT(rule_index != SSH_IPSEC_INVALID_INDEX);

  /* Do all operations requiring flow_table_lock. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);


  /* Check whether initiator or responder addresses are local IP
     addresses. */
  initiator_local = ssh_engine_ip_is_local(engine, initiator_ip);
  if (ssh_engine_ip_is_local(engine, responder_ip)
      || ssh_engine_ip_is_broadcast(engine, responder_ip))
    responder_local = TRUE;
  else
    responder_local = FALSE;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Allocate a dummy packet object.  We do not care about the
     interface numbers. */




  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    (initiator_local
                                     ? SSH_PACKET_FROMPROTOCOL
                                     : SSH_PACKET_FROMADAPTER),
                                    protocol,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
				    20);
  if (pp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate interceptor packet"));
    error:
      if (pp)
        ssh_interceptor_packet_free(pp);
      /* Call the callback indicating failure. */
      (*callback)(engine->pm, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, context);
      return;
    }

  /* Update engine's local stack selectors. */
  if (pp->flags & SSH_PACKET_FROMPROTOCOL)
    {
      /* An outgoing packet. */
      pp->flags |= SSH_ENGINE_P_FROMLOCAL;
    }
  else
    {
      /* An incoming packet.  Check local IP addresses and broadcast
         addresses. */
      if (responder_local)
        pp->flags |= SSH_ENGINE_P_TOLOCAL;
      /* Check null-address. */
      else if (SSH_IP_IS_NULLADDR(responder_ip))
        pp->flags |= SSH_ENGINE_P_TOLOCAL;
      /* Check multicast addresses. */
      else if (SSH_IP_IS_MULTICAST(responder_ip))
        pp->flags |= SSH_ENGINE_P_TOLOCAL;
    }

  /* Allocate a packet context from the freelist.  Note that we reuse
     the packet context structure here as they are a data structure we
     already have in reasonable quantities, and here as well as in
     receiving a packet we can simply fail if they are not
     available. */
  if ((pc = ssh_engine_alloc_pc(engine)) == NULL)
    goto error;

  ssh_engine_init_pc(pc, engine, pp, tunnel_id, NULL);
  pc->flags = 0;
  if (flags & SSH_PME_APPGW_KEEP_INITIATOR_PORT)
    pc->flags |= SSH_ENGINE_PC_NAT_KEEP_PORT;
  if (flags & SSH_PME_APPGW_ACCEPT_SHARED_PORT)
    pc->flags |= SSH_ENGINE_PC_NAT_SHARE_PORT;
  pc->transform_index = transform_index;
  pc->prev_transform_index = prev_transform_index;
  pc->rule = NULL;  /* This indicates appgw request. */
  pc->hdrlen = 0;
  pc->ipproto = ipproto;
  pc->u.rule.spi = 0;
  pc->protocol_xid = 0;
  pc->src = *initiator_ip;
  pc->u.rule.src_port = initiator_port;
  pc->dst = *responder_ip;
  pc->u.rule.dst_port = responder_port;

  /* These fields are used by ssh_engine_create_route_key */
  pc->u.rule.tos = 0;
  pc->u.rule.priority = 0;
  pc->audit.flowlabel = 0;

  pc->u.rule.appgw_ip = *appgw_ip;
  pc->u.rule.appgw_initiator_port = appgw_initiator_port;
  pc->u.rule.appgw_responder_port = appgw_responder_port;
  pc->u.rule.appgw_orig_dst = *responder_orig_ip;
  pc->u.rule.appgw_orig_dst_port = responder_orig_port;
  pc->u.rule.appgw_protocol = protocol;
  pc->u.rule.appgw_rule_index = trigger_rule_index;
  pc->u.rule.appgw_callback = callback;
  pc->u.rule.appgw_context = context;
  pc->u.rule.appgw_flow_idle_timeout = flow_idle_timeout;
  pc->u.rule.appgw_current_rule = rule_index;
  pc->u.rule.appgw_flow_index = flow_index;
  pc->u.rule.state = SSH_ENGINE_ST_ROUTE_APPGW;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  pc->u.rule.next_hop_index_dst = SSH_IPSEC_INVALID_INDEX;
  pc->u.rule.next_hop_index_src = SSH_IPSEC_INVALID_INDEX;
  pc->u.rule.next_hop_index_appgw = SSH_IPSEC_INVALID_INDEX;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ssh_engine_execute_rule_step(pc, SSH_ENGINE_RULE_EXECUTE_ERROR_OK);
}

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
