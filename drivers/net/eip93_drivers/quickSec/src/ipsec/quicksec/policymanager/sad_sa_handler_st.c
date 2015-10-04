/*
 * sad_sa_handler_st.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2004, 2005, 2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * IPSec SA handler thread.
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStSaHandler"

/********************************** States **********************************/

SSH_FSM_STEP(ssh_pm_st_sa_handler_start)
{  
  SshPmQm qm = (SshPmQm) thread_context;
  SshUInt32 num_items;
#ifdef SSHDIST_IKEV1
  SshPm pm = (SshPm) fsm_context;
  SshEngineTransformControl trc = &qm->sa_handler_data.trd.control;
#endif /* SSHDIST_IKEV1 */

  SSH_DEBUG(SSH_D_MIDSTART, ("SA handler sub thread entered for qm=%p", qm));

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  qm->local_ts_item_index = 0;
  qm->remote_ts_item_index = 0;

  num_items = qm->local_ts->number_of_items_used *
    qm->remote_ts->number_of_items_used;

  if (num_items > sizeof(qm->sa_handler_data.sa_indices) / sizeof(SshUInt32))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Too many traffic selector items, failing "
			     "negotiation."));
      qm->error = SSH_IKEV2_ERROR_TS_UNACCEPTABLE;

      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }
  
#ifdef SSH_IPSEC_TCPENCAP
  /* Set TCP encapsulation connection ID. */
  if (qm->p1 &&
      qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    memcpy(qm->tcp_encaps_conn_spi, qm->p1->ike_sa->ike_spi_i, 
	   SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH);
#endif /* SSH_IPSEC_TCPENCAP */
  
  /* Was this a rekey? This will be set, if we are initiator or this
     is IKEv2 rekey. It is not set for IKEv1 responder side, that
     we'll detect next. */

#ifdef SSHDIST_IKEV1    
  /* Need to recheck initiator IKEv1 rekeys. It may be that the responder
     has sent a delete notification for the old SPI after we started this
     rekey operation. In such case we install the SA as if it was a new SA. */
  if (qm->p1 
      && qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1
      && qm->rekey
      && ssh_pm_check_spi_delete_received(pm, qm->old_inbound_spi))
    qm->rekey = 0;
#endif /* SSHDIST_IKEV1 */

  if (qm->rekey)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("This is a rekey"));
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_rekey);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_IKEV1
  /* Need to check for IKEv1 responder rekeys. We do not perform this
     check for resurrected SA's. */
  if (qm->p1
      && qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1
      && !qm->initiator
      && (trc->control_flags & SSH_ENGINE_TR_C_RECOVERED_SA) == 0)
    {
      /** Check responder rekey. */
      SSH_DEBUG(SSH_D_MIDSTART, ("Check for IKEv1 responder rekey"));
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_check_v1_responder_rekey);
      return SSH_FSM_CONTINUE;
    }
  else
#endif /* SSHDIST_IKEV1 */
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Not a rekey"));

      if (qm->trd_index != SSH_IPSEC_INVALID_INDEX)
	SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_create_trd_result);
      else
	SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_route);
      
      return SSH_FSM_CONTINUE;
    }
}

#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(ssh_pm_st_sa_handler_check_v1_responder_rekey)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  const unsigned char *peer_id = NULL;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  SSH_DEBUG(SSH_D_LOWOK, ("Checking for IKEv1 responder rekey"));

  /* Create outbound rule for the SA. */
  if (!ssh_pm_make_sa_outbound_rule(pm, qm,
                                    qm->forward, qm->rule,
                                    qm->local_ts, qm->local_ts_item_index,
				    qm->remote_ts, qm->remote_ts_item_index,
				    &qm->sa_outbound_rule))
    {
      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_ERROR, ("Could not create outbound SA rule"));

      qm->trd_index = SSH_IPSEC_INVALID_INDEX;
      qm->error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(qm->sa_outbound_rule.policy_context == NULL);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  peer_id = qm->sa_handler_data.trd.control.peer_id;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Consult the rule database in the engine to check if this is */
  /* a responder rekey. */
  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_check_v1_responder_rekey_result);
  SSH_FSM_ASYNC_CALL({
    ssh_pme_find_matching_transform_rule(
				pm->engine,
				&qm->sa_outbound_rule,
				qm->sa_handler_data.trd.data.transform,
				qm->sa_handler_data.trd.data.cipher_key_size,
				&qm->sa_handler_data.trd.data.gw_addr,
				&qm->sa_handler_data.trd.data.own_addr,
				qm->sa_handler_data.trd.data.local_port,
				qm->sa_handler_data.trd.data.remote_port,
				peer_id,
				SSH_PME_RULE_MATCH_ANY_IFNUM
				| SSH_PME_RULE_MATCH_IKEV1,
				ssh_pm_sa_index_cb,
				thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_check_v1_responder_rekey_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  if (qm->trd_index != SSH_IPSEC_INVALID_INDEX)
    {
      /** Rekey the existing rule. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Found a matching rule for responder rekey: trd_index=0x%x "
		 "old outbound SPI 0x%08lx",
                 (unsigned int) qm->trd_index,
		 (unsigned long) qm->old_outbound_spi));
      qm->rekey = 1;

      /** Fetch peer handle for rekeyed IPsec SA. */
      qm->peer_handle = 
	ssh_pm_peer_handle_by_spi_out(pm, qm->old_outbound_spi, qm->trd_index);
      qm->sa_handler_data.trd.control.peer_handle = qm->peer_handle;

      /** Fetch old inbound SPI value for rekeyed SA. */
      qm->old_inbound_spi =
	ssh_pm_spi_in_by_trd(pm, qm->old_outbound_spi, qm->trd_index);
      
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_rekey);
      return SSH_FSM_CONTINUE;
    }

  /** Not a rekey. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("No old rule found for responder: this is not a rekey"));

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_route);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKEV1 */

static void
pm_st_sa_handler_rekey_cb(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);

  if (status == FALSE)
    qm->error = SSH_PM_QM_ERROR_INTERNAL_PM;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_rekey)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshEngineTransformData trd = &qm->sa_handler_data.trd.data;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  /* For rekeys, update p1 to peer. Assert that p1 is valid because rekeys 
     never happen for manually keyed IPsec SAs. */
  SSH_PM_ASSERT_P1(qm->p1);
  if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
    {
      if (!ssh_pm_peer_update_p1(pm, 
				 ssh_pm_peer_by_handle(pm, qm->peer_handle),
				 qm->p1))
	{
	  qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
	  return SSH_FSM_CONTINUE;
	}
    }

  SSH_ASSERT(qm->trd_index != SSH_IPSEC_INVALID_INDEX);

  /* Rekey inbound. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Rekeying inbound SAs of transform 0x%x",
                               (unsigned int) qm->trd_index));

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_rekey_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_rekey_transform_inbound(pm->engine,
						     qm->trd_index,
						     trd->spis,
						     trd->keymat,
						     qm->trd_life_seconds,
						     qm->trd_life_kilobytes,
						     pm_st_sa_handler_rekey_cb,
						     thread));
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_rekey_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;
  
  /* Reinstall the rules to the engine. */
  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_add_rule);

#ifdef SSHDIST_IKEV1
  /* If we are the initiator of an IKEv1 IPsec SA negotiation then delay 
     the rekey of outbound SPI so that the peer can rekey the inbound SPI
     before we start sending packets with the new outbound SPI. Otherwise
     continue immediately. */
  if (qm->initiator
      && (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
    {
      SSH_FSM_ASYNC_CALL({
	/* This uses the same timeout structure as initiator triggering
	   packet reprocess. This is safe, as we are now rekeying. */
	ssh_register_timeout(qm->timeout,
			     0, SSH_PM_REKEY_OUTBOUND_DELAY,
			     ssh_pm_timeout_cb, thread);
      });
      SSH_NOTREACHED;
    }
#endif /* SSHDIST_IKEV1 */

  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_st_sa_handler_route_cb(SshPm pm, SshUInt32 flags, SshUInt32 ifnum,
			      const SshIpAddr next_hop, size_t mtu,
			      void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
  SshIpAddr addr;

  if (flags & SSH_PME_ROUTE_REACHABLE)
    {
      if (qm->sa_handler_data.trd.data.own_ifnum != ifnum)
	{
	  SSH_DEBUG(SSH_D_MIDOK,
		    ("Changing local interface from %d to %d",
		     (int) qm->sa_handler_data.trd.data.own_ifnum,
		     (int) ifnum));
	  qm->sa_handler_data.trd.data.own_ifnum = ifnum;
	}
      else
	{
	  SSH_DEBUG(SSH_D_MIDOK, 
		    ("Using local interface %d",
		     (int) qm->sa_handler_data.trd.data.own_ifnum));
	}
      
      /* Set local address for manual key SAs that did not specify local IP. */
      if ((qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_MANUAL) 
	  && !SSH_IP_DEFINED(&qm->sa_handler_data.trd.data.own_addr))
	{
	  addr = ssh_pm_find_interface_address(pm, ifnum, 
			     SSH_IP_IS6(&qm->sa_handler_data.trd.data.gw_addr),
			     &qm->sa_handler_data.trd.data.gw_addr);
	  if (addr == NULL)
	    goto fail;
	  
	  qm->sa_handler_data.trd.data.own_addr = *addr;
	  SSH_DEBUG(SSH_D_MIDOK,
		    ("Setting manual key SA local address to %@",
		     ssh_ipaddr_render, 
		     &qm->sa_handler_data.trd.data.own_addr));
	}
    }
  
  else
    {
    fail:
      SSH_DEBUG(SSH_D_ERROR, ("Tunnel endpoint is unreachable!"));
      qm->error = SSH_PM_QM_ERROR_INTERNAL_PM;
    }
  
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_route)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshInterceptorRouteKeyStruct key;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;




  ssh_pm_create_route_key(pm, &key,
			  &qm->sa_handler_data.trd.data.own_addr,
                          &qm->sa_handler_data.trd.data.gw_addr,
                          0, 0, 0, SSH_INVALID_IFNUM);

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_create_trd);

  /* Route gw address to get the correct if_num for trd */
  SSH_FSM_ASYNC_CALL(ssh_pme_route(pm->engine,
				   0,      /* flags */
				   &key, 
				   ssh_pm_st_sa_handler_route_cb,
				   thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_create_trd)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmTunnel tunnel;
  SshUInt16 gw_port = 0, own_port = 0;
  Boolean manual_key = FALSE;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  /* Bind this IPsec SA to a peer handle. */
  if (qm->p1)
    {
      gw_port = qm->p1->ike_sa->remote_port;
      own_port = SSH_PM_IKE_SA_LOCAL_PORT(qm->p1->ike_sa);
      manual_key = FALSE;

      if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
          /* Check if there is a known peer for p1. */
          qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, qm->p1);
        }
      else
        {
	  /* This is an IPsec SA rekey that has created a new IKEv1 SA.
	     Update the IKE SA to the existing peer. */
          if (ssh_pm_peer_update_p1(pm, 
				    ssh_pm_peer_by_handle(pm, qm->peer_handle),
				    qm->p1) == FALSE)
            {
              qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
              SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
              return SSH_FSM_CONTINUE;
            }
        }
    }
  else if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      /* For manually keyed SAs lookup peer using addresses. */
      gw_port = 0;
      own_port = 0;
      manual_key = TRUE;

      /* For recovered IKEv1 keyed IPsec SAs the qm->peer_handle has already
	 been set by the import/export code. */
      SSH_ASSERT((qm->sa_handler_data.trd.control.control_flags & 
		  SSH_ENGINE_TR_C_RECOVERED_SA) == 0);

      /* For SA's with no IKE SA, lookup peer handle by addresses. */
      qm->peer_handle = 
	ssh_pm_peer_handle_by_address(pm,
				      &qm->sa_handler_data.trd.data.gw_addr, 
				      gw_port,
				      &qm->sa_handler_data.trd.data.own_addr, 
				      own_port, FALSE, TRUE);
    }

  /* No suitable peer handle found, create new. */
  if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      qm->peer_handle = 
	ssh_pm_peer_create(pm, 
			   &qm->sa_handler_data.trd.data.gw_addr, gw_port,
			   &qm->sa_handler_data.trd.data.own_addr, own_port,
			   qm->p1, manual_key);
      if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
	{
	  qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
	  return SSH_FSM_CONTINUE;
	}

      /* Take one reference for IPsec SA. If this is manually keyed SA, then
	 use the reference from ssh_pm_peer_create(). */
      if (!manual_key)
	ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
    }

  /* Suitable peer handle found, take one reference for this IPsec SA. */
  else
    ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
  
  /* Set transform ike_sa_handle point to peer. */ 
  qm->sa_handler_data.trd.control.peer_handle = qm->peer_handle;
  qm->delete_peer_ref_on_error = 1;
      
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if (qm->tunnel->flags & SSH_PM_T_SET_EXTENSION_SELECTOR)
    {
      memcpy(qm->sa_handler_data.trd.data.extension, qm->tunnel->extension,
	     sizeof(qm->sa_handler_data.trd.data.extension));
      qm->sa_handler_data.trd.data.decapsulate_extension = 1;
    }
  else
    qm->sa_handler_data.trd.data.decapsulate_extension = 0;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

#ifdef SSH_IPSEC_TCPENCAP
  /* Set the TCP encaps connection ID. */
  if (qm->p1 &&
      (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP) &&
      (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) == 0 &&
      (qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_NATT) == 0)
    memcpy(qm->sa_handler_data.trd.control.tcp_encaps_conn_spi,
	   qm->p1->ike_sa->ike_spi_i, SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH);
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  if (qm->tunnel->vip != NULL && qm->tunnel == qm->rule->side_to.tunnel)
    {
      /* Take a reference to the vip object for this transform. */
      ssh_pm_virtual_ip_take_ref((SshPm) fsm_context, qm->tunnel);
      
      /* Set IKE peer handle to vip object. */
      ssh_pm_virtual_ip_set_peer(pm, qm->tunnel, qm->peer_handle);
      
      /* Mark that VIP reference should be deleted on installation error. */
      qm->delete_vip_ref_on_error = 1;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* There is little point in trying to dangle a manually-keyed transform */
  if (qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_MANUAL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("installing MANUAL SA transform"));
      qm->sa_outbound_rule.flags |= SSH_PM_ENGINE_RULE_FLOW_REF;
    }

  /** Calculate nesting level for transform. */
  for (tunnel = qm->tunnel; tunnel != NULL; tunnel = tunnel->outer_tunnel)
    qm->sa_handler_data.trd.data.nesting_level++;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Nesting level %d", 
			       qm->sa_handler_data.trd.data.nesting_level));

  /** Assert that the transform addresses are valid. */
  SSH_ASSERT(!(qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_TUNNEL) ||
	     (SSH_IP_DEFINED(&qm->sa_handler_data.trd.data.own_addr) &&
	      !SSH_IP_IS_NULLADDR(&qm->sa_handler_data.trd.data.own_addr)));
  SSH_ASSERT(!(qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_TUNNEL) ||
	     (SSH_IP_DEFINED(&qm->sa_handler_data.trd.data.gw_addr) &&
	      !SSH_IP_IS_NULLADDR(&qm->sa_handler_data.trd.data.gw_addr)));

  /** Create transform. */
  qm->trd_index = SSH_IPSEC_INVALID_INDEX;
  SSH_DEBUG(SSH_D_LOWSTART, ("Creating transform"));
  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_create_trd_result);
  
  SSH_FSM_ASYNC_CALL(ssh_pme_create_transform(pm->engine,
                                              &qm->sa_handler_data.trd,
                                              qm->trd_life_seconds,
                                              qm->trd_life_kilobytes,
                                              ssh_pm_transform_index_cb,
                                              thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_create_trd_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  /* Was the transform creation successful? */
  if (qm->trd_index == SSH_IPSEC_INVALID_INDEX)
    {
      /** Failed. Do not clear qm->spis here, as failed state will use
	  them and remove the allocated SPI's from pm->inbound_spis. */
      SSH_DEBUG(SSH_D_FAIL, ("Transform creation failed"));
      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }
  
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  if (qm->tunnel->vip != NULL && qm->tunnel == qm->rule->side_to.tunnel)
    {
      SshUInt32 i;
      
      /* Create virtual IP routes to negotiatiated remote traffic selectors. 
	 This call only creates the route entries to the vip object.  
	 The actual routes will be configured to the system after the 
	 virtual adapter is configured. */
#ifdef SSHDIST_L2TP
      /* Do not create route entries for L2TP/IPSec peer, since L2TP uses
	 transport mode. */
      if (!(qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_L2TP))
	{
#endif /* SSHDIST_L2TP */
	  for (i = 0; i < qm->remote_ts->number_of_items_used; i++)
	    ssh_pm_vip_create_transform_route(qm->tunnel->vip,
                                              &qm->remote_ts->items[i],
                                              qm->trd_index);
#ifdef SSHDIST_L2TP
	}
#endif /* SSHDIST_L2TP */
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* It was successful.  Let's create the outbound rules. */
  SSH_DEBUG(SSH_D_LOWOK, ("Transform created: index=0x%x",
			  (unsigned int) qm->trd_index));

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_add_rule);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_sa_handler_add_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  /* Create outbound rule for the SA. */
  if (!ssh_pm_make_sa_outbound_rule(pm, qm,
                                    qm->forward, qm->rule,
                                    qm->local_ts, qm->local_ts_item_index,
				    qm->remote_ts, qm->remote_ts_item_index,
				    &qm->sa_outbound_rule))
    {
      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_ERROR, ("Could not create outbound SA rule"));

      qm->error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(qm->sa_outbound_rule.policy_context == NULL);

  /* The rules, created by the SA handler thread, are the ones from
     which we want to receive transform events.  Let's notify that by
     setting the `policy_context' for these rules. */
  qm->sa_outbound_rule.policy_context = qm->rule;

  /* Set the forward flag so future transform events will find the
     correct tunnel. */
  if (qm->tunnel == qm->rule->side_to.tunnel)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Setting forward flag in the SA rule"));
      qm->sa_outbound_rule.flags |= SSH_PM_ENGINE_RULE_FORWARD;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Clearing forward flag in the SA rule"));
      qm->sa_outbound_rule.flags &= ~SSH_PM_ENGINE_RULE_FORWARD;
    }

  /* If this rule is the result of an appgw to-tunnel pm rule
     or a NAT is being performed, then we need a placeholder rule for
     owning the transform and that is this rule. Set this rule to
     be inactive untill it is activated. */
  
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  if ((qm->rule != NULL
       && qm->rule->service && qm->rule->service->appgw_ident)
      || ((SSH_IP_DEFINED(&qm->sel_src) 
	   && !SSH_IP_EQUAL(&qm->packet_orig_src_ip, &qm->sel_src))
          || (qm->sel_src_port != 0 && 
	      qm->packet_orig_src_port != qm->sel_src_port)))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Appgw related rule or NAT in effect, making it inactive!"));
      qm->sa_outbound_rule.flags |= SSH_ENGINE_RULE_INACTIVE;
      qm->is_sa_rule_modified = 1;
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  if (!qm->forward)
    {
      if (qm->tunnel->flags & SSH_PM_TR_ENABLE_OUT_SA_SEL)
        {
          /* The SA was negotiated using the reverse direction but the
             policy request creating the outbound rule anyway. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Installing active outbound rule for reverse mode "
                     "negotiation because of tunnel flag "
                     "SSH_PM_TR_ENABLE_OUT_SA_SEL"));
        }
      else
        {
          /* The SA was negotiated using the reverse direction.
             Create the outbound rule as inactive to avoid opening
             unconfigured flows. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("SA negotiated in reverse mode: making rule inactive"));
          qm->sa_outbound_rule.flags |= SSH_ENGINE_RULE_INACTIVE;
        }
    }
  qm->sa_outbound_rule.transform_index = qm->trd_index;
  qm->sa_outbound_rule.flags |= SSH_PM_ENGINE_RULE_SA_OUTBOUND;

  /* Do not create an IPSec flow for rekeys */
  if (qm->rekey)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No IPsec flow created for rekeyed QM"));
      qm->sa_outbound_rule.flags |= SSH_ENGINE_RULE_NO_IPSEC_FLOW;
    }

  /* Only create an IPSec flow for the the first pair of traffic selector
     items unless this is an multihomed SCTP association. */
  if ((qm->local_ts_item_index || qm->remote_ts_item_index)
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
      && ((qm->rule->flags & SSH_PM_RULE_MULTIHOME) == 0)
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
      )
    qm->sa_outbound_rule.flags |= SSH_ENGINE_RULE_NO_IPSEC_FLOW;

  /** Add SA outbound rule. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Adding SA outbound rule"));
  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_add_rule_result);

  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, qm->rekey,
				      &qm->sa_outbound_rule,
                                      ssh_pm_add_sa_handler_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_add_rule_result)
{
  SshPmQm qm = (SshPmQm) thread_context;
  SshUInt32 i;

  /* Check for errors before continuing. */
  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  if (qm->sa_index == SSH_IPSEC_INVALID_INDEX)
    {
      /** Failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Could not create outbound SA rule"));

      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Rule added successfully. If there are more rules to be created from 
     the traffic selectors, then continue with adding SA rules. Otherwise
     we proceed to handling inner tunnel IKE rules. */

  if (++qm->remote_ts_item_index == qm->remote_ts->number_of_items_used)
    {
      if (++qm->local_ts_item_index == qm->local_ts->number_of_items_used)
	{
	  SSH_DEBUG(SSH_D_HIGHOK, ("SA outbound rules created"));

	  /* Check if need to create high level rules for inner 
	     tunnel IKE. */
	  if (qm->rule->flags & SSH_PM_RULE_MATCH_LOCAL_IKE)
	    {
	      for (i = 0; i < SSH_PM_MAX_INNER_TUNNELS; i++)
		{
		  qm->sa_handler_data.inner_local_ike_ports[i] = 0;
		  qm->sa_handler_data.inner_local_ike_natt_ports[i] = 0;
		  qm->sa_handler_data.inner_remote_ike_ports[i] = 0;
		  qm->sa_handler_data.inner_remote_ike_natt_ports[i] = 0;
		}
	      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_create_ike_apply_rule);
	      return SSH_FSM_CONTINUE;
	    }

	  /* Done with rules. */	  
	  if (qm->rekey)
	    {
	      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_rekey_outbound);
	    }
	  else
	    {
	      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_register_outbound_spi);
	    }
	  return SSH_FSM_CONTINUE;
	}
      qm->remote_ts_item_index = 0;
    }

  /* More SA rules to be added. */
  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_add_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_create_ike_apply_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmRule inner_rule = NULL;
  SshADTHandle h;
  SshUInt32 i;
  SshUInt16 local_ike_port = 0, local_ike_natt_port = 0;
  SshUInt16 remote_ike_port = 0, remote_ike_natt_port = 0;
  SshPmTunnel outer_tunnel, inner_tunnel;
  Boolean inner_forward;

  if (qm->forward)
    outer_tunnel = qm->rule->side_to.tunnel;
  else
    outer_tunnel = qm->rule->side_from.tunnel;
  SSH_ASSERT(outer_tunnel != NULL);

  /* Check if there is an inner tunnel that uses this tunnel for IKE. */
  for (h = ssh_adt_enumerate_start(pm->rule_by_precedence);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->rule_by_precedence, h))
    {
      inner_rule = ssh_adt_get(pm->rule_by_precedence, h);
      SSH_ASSERT(inner_rule != NULL);

      /* Check inner rule in both directions. */
      if (inner_rule->side_to.tunnel &&
	  inner_rule->side_to.tunnel->ike_tn &&
	  inner_rule->side_to.tunnel->outer_tunnel &&
	  inner_rule->side_to.tunnel->outer_tunnel == outer_tunnel
	  && inner_rule->side_to.tunnel->outer_tunnel_ike_sa == 0)
	{
	  inner_forward = TRUE;
	  inner_tunnel = inner_rule->side_to.tunnel;
	}
      else if (inner_rule->side_from.tunnel &&
	       inner_rule->side_from.tunnel->ike_tn &&
	       inner_rule->side_from.tunnel->outer_tunnel &&
	       inner_rule->side_from.tunnel->outer_tunnel == outer_tunnel
	       && inner_rule->side_from.tunnel->outer_tunnel_ike_sa == 0)
	{
	  inner_forward = FALSE;
	  inner_tunnel = inner_rule->side_from.tunnel;
	}
      else
	continue;

      /* Take IKE ports from tunnel. */
      if (inner_tunnel->local_port)
	local_ike_port = inner_tunnel->local_port;
      else
	local_ike_port = SSH_IPSEC_IKE_PORT;
      for (i = 0; i < pm->params.num_ike_ports; i++)
	{
	  if (local_ike_port == pm->params.local_ike_ports[i])
	    {
              local_ike_natt_port = pm->params.local_ike_natt_ports[i];
              remote_ike_port = pm->params.remote_ike_ports[i];
              remote_ike_natt_port = pm->params.remote_ike_natt_ports[i];
	      break;
	    }
	}
      
      /* Check is this IKE port pair is already processed. */
      for (i = 0; i < SSH_PM_MAX_INNER_TUNNELS; i++)
	{
	  if (qm->sa_handler_data.inner_local_ike_ports[i] == 0)
	    break;
	  
	  else if (inner_forward == qm->sa_handler_data.inner_ike_forward[i]
		   && local_ike_port
                   == qm->sa_handler_data.inner_local_ike_ports[i] 
		   && local_ike_natt_port 
		   == qm->sa_handler_data.inner_local_ike_natt_ports[i])
	    break;
	}
      if (qm->sa_handler_data.inner_local_ike_ports[i] != 0)
	continue;

      /* Mark this IKE port pair processed and continue with rule creation. */
      SSH_ASSERT(i < SSH_PM_MAX_INNER_TUNNELS);
      SSH_ASSERT(qm->sa_handler_data.inner_local_ike_ports[i] == 0);
      qm->sa_handler_data.inner_local_ike_ports[i] = local_ike_port;
      qm->sa_handler_data.inner_local_ike_natt_ports[i] =
        local_ike_natt_port;
      SSH_ASSERT(qm->sa_handler_data.inner_remote_ike_ports[i] == 0);
      qm->sa_handler_data.inner_remote_ike_ports[i] = remote_ike_port;
      qm->sa_handler_data.inner_remote_ike_natt_ports[i] =
        remote_ike_natt_port;
      qm->sa_handler_data.inner_ike_forward[i] = inner_forward;
      break;
    }
  if (h == SSH_ADT_INVALID)
    {
      /* Done with all inner tunnels. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No more inner tunnel IKE rules needed"));
            
      if (qm->rekey)
	{
	  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_rekey_outbound);
	}
      else
	{
	  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_register_outbound_spi);
	}
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating inner tunnel IKE apply rule for rule `%@', "
	     "%s IKE ports %d:%d, %d:%d",
             ssh_pm_rule_render, qm->rule,
	     (inner_forward ? "forward" : "reverse"),
	     local_ike_port, local_ike_natt_port,
	     remote_ike_port, remote_ike_natt_port));

  SSH_ASSERT(local_ike_port != 0);
  SSH_ASSERT(local_ike_natt_port != 0);
  SSH_ASSERT(remote_ike_port != 0);
  SSH_ASSERT(remote_ike_natt_port != 0);

  /* Create traffic selectors for IKE. */
  SSH_ASSERT(qm->sa_handler_data.ike_remote_ts == NULL);
  SSH_ASSERT(qm->sa_handler_data.ike_local_ts == NULL);
  if (inner_forward)
    {
      qm->sa_handler_data.ike_remote_ts = 
	ssh_pm_calculate_inner_ike_ts(pm, qm->remote_ts, 
				      remote_ike_port, remote_ike_natt_port);
      qm->sa_handler_data.ike_local_ts = 
	ssh_pm_calculate_inner_ike_ts(pm, qm->local_ts, 0, 0);
    }
  else
    {
      qm->sa_handler_data.ike_remote_ts = 
	ssh_pm_calculate_inner_ike_ts(pm, qm->remote_ts, 0, 0);
      qm->sa_handler_data.ike_local_ts = 
	ssh_pm_calculate_inner_ike_ts(pm, qm->local_ts,
				      local_ike_port, local_ike_natt_port);
    }

  if (qm->sa_handler_data.ike_remote_ts == NULL 
      || qm->sa_handler_data.ike_local_ts == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Inner tunnel IKE tunneling is not allowed by rule `%@'",
                 ssh_pm_rule_render, qm->rule));
      qm->error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
    }
  else
    {
      qm->sa_handler_data.remote_ts_index = 0;
      qm->sa_handler_data.local_ts_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_add_ike_apply_rule);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_add_ike_apply_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshIkev2PayloadTSItem item;
  Boolean check_natt = FALSE, local_is_natt = FALSE, remote_is_natt = FALSE;
  SshUInt32 i;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  /* Skip unnecessary traffic selector pairs (i.e. 500->4500, 4500->500) */
  
  item = &qm->sa_handler_data.ike_local_ts->
    items[qm->sa_handler_data.local_ts_index];
  if (item->proto == SSH_IPPROTO_UDP
      && item->start_port == item->end_port)
    {
      check_natt = TRUE;
      for (i = 0; local_is_natt == FALSE && i < SSH_PM_MAX_INNER_TUNNELS; i++)
	if (item->start_port 
	    == qm->sa_handler_data.inner_local_ike_natt_ports[i])
	  local_is_natt = TRUE;
    }

  item = &qm->sa_handler_data.ike_remote_ts->
    items[qm->sa_handler_data.remote_ts_index];
  if (item->proto == SSH_IPPROTO_UDP
      && item->start_port == item->end_port)
    {
      for (i = 0; remote_is_natt == FALSE && i < SSH_PM_MAX_INNER_TUNNELS; i++)
	if (item->start_port
            == qm->sa_handler_data.inner_remote_ike_natt_ports[i])
	  remote_is_natt = TRUE;
    }
  else
    check_natt = FALSE;
  
  if (check_natt
      && ((local_is_natt && !remote_is_natt) 
	  || (!local_is_natt && remote_is_natt)))
    {
      /* This traffic selector pair is not needed, move on to next pair. */
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_next_ike_apply_rule);
      return SSH_FSM_CONTINUE;
    }

  /* Create outbound apply rule for inner tunnel IKE. */
  if (!ssh_pm_make_inner_ike_outbound_apply_rule(pm, &engine_rule,
     				 qm->sa_handler_data.ike_local_ts,
     				 qm->sa_handler_data.local_ts_index,
     				 qm->sa_handler_data.ike_remote_ts,
     				 qm->sa_handler_data.remote_ts_index,
				 qm->trd_index,
				 qm->rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT],
	       			 SSH_PM_RULE_PRI_USER_HIGH + 1,
       				 TRUE,
			     	 qm->forward,
			       	 qm->rule))
    {
      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_ERROR, ("Could not create inner tunnel IKE apply rule"));
      
      qm->error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }
  
  /** Add inner tunnel IKE outbound apply rule. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Adding inner tunnel IKE apply rule"));
  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_add_ike_apply_rule_result);
  
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, qm->rekey,
				      &engine_rule,
                                      ssh_pm_add_sa_handler_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_add_ike_apply_rule_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  if (qm->sa_index == SSH_IPSEC_INVALID_INDEX)
    {
      /** Failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Could not add inner tunnel IKE apply rule"));

      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_next_ike_apply_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_next_ike_apply_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  /* Advance to next traffic selector item pair. */
  if (++qm->sa_handler_data.local_ts_index 
      == qm->sa_handler_data.ike_local_ts->number_of_items_used)
    {
      if (++qm->sa_handler_data.remote_ts_index 
	  == qm->sa_handler_data.ike_remote_ts->number_of_items_used)
	{
	  /* Done with the IKE apply rule. */
	  ssh_ikev2_ts_free(pm->sad_handle, qm->sa_handler_data.ike_remote_ts);
	  qm->sa_handler_data.ike_remote_ts = NULL;
	  ssh_ikev2_ts_free(pm->sad_handle, qm->sa_handler_data.ike_local_ts);
	  qm->sa_handler_data.ike_local_ts = NULL;

          SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_create_ike_apply_rule);
          return SSH_FSM_CONTINUE;
	}
      qm->sa_handler_data.local_ts_index = 0;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_add_ike_apply_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_rekey_outbound)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  SSH_DEBUG(SSH_D_LOWOK,
	    ("Mark the old outbound SPI value 0x%08lx as rekeyed",
	     (unsigned long) qm->old_outbound_spi));
  
  /* Get the SPI entry and mark it as rekeyed. */
  if (!ssh_pm_mark_outbound_spi_rekeyed(pm, qm->old_outbound_spi,
					qm->old_inbound_spi))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Old outbound SPI entry not found"));
      qm->error = SSH_PM_QM_ERROR_INTERNAL_PM;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSH_IPSEC_TCPENCAP
  /* Clear the TCP encaps connection ID if p1 has moved to NAT-T. */
  if ((qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_NATT)
      || (qm->p1 &&
	  (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)))
    memset(qm->tcp_encaps_conn_spi, 0, SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH);
#endif /* SSH_IPSEC_TCPENCAP */

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Rekeying outbound SAs of transform 0x%x",
	     (unsigned int) qm->trd_index));

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_register_outbound_spi);

#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_ASYNC_CALL({
    ssh_pme_rekey_transform_outbound(pm->engine,
				     qm->trd_index,
				     &qm->sa_handler_data.trd.data.spis[3],
				     (qm->sa_handler_data.trd.data.keymat
                                    + SSH_IPSEC_MAX_KEYMAT_LEN / 2),
				     qm->tcp_encaps_conn_spi,
				     qm->initiator,
				     pm_st_sa_handler_rekey_cb, thread);
  });
#else /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_ASYNC_CALL({
    ssh_pme_rekey_transform_outbound(pm->engine,
				     qm->trd_index,
				     &qm->sa_handler_data.trd.data.spis[3],
				     (qm->sa_handler_data.trd.data.keymat
				      + SSH_IPSEC_MAX_KEYMAT_LEN / 2),
				     qm->initiator,
				     pm_st_sa_handler_rekey_cb, thread);
  });
#endif /* SSH_IPSEC_TCPENCAP */
}

/* A callback function that is called to notify the status of engine
   rule deletion. */
static void
pm_delete_rule_cb(SshPm pm, Boolean done,
		  SshUInt32 rule_index, SshUInt32 peer_handle,
		  SshUInt8 ipproto, SshUInt32 outbound_spi, 
		  SshUInt32 inbound_spi, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm )ssh_fsm_get_tdata(thread);

  if (done)
    qm->sa_handler_data.delete_index++;

  /* Continue.  The next state is already set by our caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}


SSH_FSM_STEP(ssh_pm_st_sa_handler_failed)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshUInt32 delete_index, rule_index;

  SSH_DEBUG(SSH_D_FAIL, ("In SA handler failed state, error %d", qm->error));

  SSH_ASSERT(qm->error != 0);

  delete_index = qm->sa_handler_data.delete_index;
  rule_index = qm->sa_handler_data.sa_indices[delete_index];

  /* Free rules installed at this time, so there will be no references
     to the transform later. */
  if (rule_index != SSH_IPSEC_INVALID_INDEX &&
      delete_index < qm->sa_handler_data.added_index)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Deleting rule index %d",
			       (int) rule_index));

      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine,
					     rule_index,
					     pm_delete_rule_cb, thread));
      SSH_NOTREACHED;
    }

#ifdef WITH_IKE
  /* Notify peer (if possible) in a delayed manner. The delete notification 
     will be sent after the IKE SA done notification is received from the
     IKE library. */

  if (qm->p1 != NULL && qm->ed != NULL)
    {
      SSH_PM_ASSERT_ED(qm->ed);
      if (qm->ed->ipsec_ed->ipsec_sa_protocol == SSH_IKEV2_PROTOCOL_ID_ESP
	  && qm->spis[SSH_PME_SPI_ESP_IN] != 0)
	{
	  SSH_DEBUG(SSH_D_HIGHOK,
		    ("Requesting delete notification for SPI 0x%08lx",
		     (unsigned long) qm->spis[SSH_PME_SPI_ESP_IN]));
	  ssh_pm_request_ipsec_delete_notification(pm, qm->p1, SSH_IPPROTO_ESP,
						   qm->spis[SSH_PME_SPI_ESP_IN]
						   );
	}
      else if (qm->ed->ipsec_ed->ipsec_sa_protocol == SSH_IKEV2_PROTOCOL_ID_AH
	       && qm->spis[SSH_PME_SPI_AH_IN] != 0)
	{
	  SSH_DEBUG(SSH_D_HIGHOK,
		    ("Requesting delete notification for SPI 0x%08lx",
		     (unsigned long) qm->spis[SSH_PME_SPI_AH_IN]));
	  ssh_pm_request_ipsec_delete_notification(pm, qm->p1, SSH_IPPROTO_AH,
						   qm->spis[SSH_PME_SPI_AH_IN]
						   );
	}
    }
#endif /* WITH_IKE */

  /* Delete the transform if it was created but no engine rules were
     added to that transform (if engine rules have been added, the
     transform will be deleted after all the rules are deleted above). */
  if (qm->delete_trd_on_error)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Deleting transform index %x",
			       (unsigned int) qm->trd_index));

      qm->delete_trd_on_error = 0;
      ssh_pme_delete_transform(pm->engine, qm->trd_index);
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Release VIP object reference taken for the IPsec SA that was never
     properly installed. */
  if (qm->delete_vip_ref_on_error)
    {
      SSH_ASSERT(qm->tunnel->vip != NULL);
      ssh_pm_virtual_ip_free(pm, SSH_IPSEC_INVALID_INDEX, qm->tunnel);
      
      /* Clear peer handle from VIP object, as the peer reference is released
	 next. */
      ssh_pm_virtual_ip_set_peer(pm, qm->tunnel, SSH_IPSEC_INVALID_INDEX);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Release peer reference taken for the IPsec SA that was never installed. */
  if (qm->delete_peer_ref_on_error)
    {
      qm->delete_peer_ref_on_error = 0;
      if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
	ssh_pm_peer_handle_destroy(pm, qm->peer_handle);
    }

  /* XXX: Handle ipsec_sa_event_deleted() correctly for failed rekeyes. */

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_register_outbound_spi)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_initiator_set_access_groups);

  if (qm->tunnel->manual_tn)
    return SSH_FSM_CONTINUE;

  if (!ssh_pm_register_outbound_spi(pm, qm))
    {
      /** Failed. Do not clear qm->spis here, as failed state will use
	  them */
      SSH_DEBUG(SSH_D_FAIL, ("Out of SPI data structures"));
      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
      return SSH_FSM_CONTINUE;
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_initiator_set_access_groups)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_initiator_check_access_groups);
  
  /* Perform authorization for the P1 at the initiator here. */
  if (qm->p1 && !qm->p1->auth_group_ids_set &&
      qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Resolving authorization group ID"));
      SSH_FSM_ASYNC_CALL(ssh_pm_authorization_p1(pm, qm->p1,
						 ssh_pm_authorization_cb,
						 thread));
      SSH_NOTREACHED;
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_initiator_check_access_groups)
{
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_success);
  
  if (qm->p1 && (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      SSH_ASSERT(qm->p1->auth_group_ids_set == 1);
      if (!ssh_pm_check_rule_authorization(qm->p1, qm->rule))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("The rule's authorization does not match"));
	  qm->error = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
	  qm->failure_mask |= SSH_PM_E_ACCESS_GROUP_MISMATCH;
	  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_failed);
	}
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_sa_handler_success)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IKEV1
  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_sa_handler_failed))
    return SSH_FSM_CONTINUE;

  /* Add a reference to the CFGMode client. This is only done for IKEv1 SA's.
     For IKEv2 no extra references are required because IPsec SA's (i.e. 
     all objects using the CFG mode addresses) are tied to the IKE SA. */
  if (qm->p1 && 
      (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
      qm->p1->cfgmode_client && !qm->rekey)
    ssh_pm_cfgmode_client_store_take_reference(pm,
					       qm->p1->cfgmode_client);

#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  if (qm->tunnel->manual_tn)
    ssh_pm_log_manual_sa_event(pm, qm, TRUE, "completed");
  
  SSH_FSM_SET_NEXT(ssh_pm_st_sa_handler_terminate);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_sa_handler_terminate)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshInetIPProtocolID firstproto = SSH_IPPROTO_ANY;
  SshUInt32 firstspi = 0;
  SshEngineTransformData trd;
  const char *msg;
  unsigned char ipproto_buf[3][4], spi_buf[3][4];
  int n;

  /* Check the outermost protocol. */
  trd = &qm->sa_handler_data.trd.data;

  n = 0;
  if (trd->transform & SSH_PM_IPSEC_ESP)
    {
      SSH_PUT_32BIT(spi_buf[n], trd->spis[SSH_PME_SPI_ESP_IN]);
      SSH_PUT_32BIT(ipproto_buf[n], SSH_IPPROTO_ESP);

      firstproto = SSH_IPPROTO_ESP;
      firstspi = trd->spis[SSH_PME_SPI_ESP_IN];

      n++;
    }
  if (trd->transform & SSH_PM_IPSEC_AH)
    {
      SSH_PUT_32BIT(spi_buf[n], trd->spis[SSH_PME_SPI_AH_IN]);
      SSH_PUT_32BIT(ipproto_buf[n], SSH_IPPROTO_AH);

      /* For AH+ESP, AH is upper, thus rewrite for CR */
      firstproto = SSH_IPPROTO_AH;
      firstspi = trd->spis[SSH_PME_SPI_AH_IN];

      n++;
    }
  if (trd->transform & SSH_PM_IPSEC_IPCOMP)
    {
      SSH_PUT_32BIT(spi_buf[n], trd->spis[SSH_PME_SPI_IPCOMP_IN]);
      SSH_PUT_32BIT(ipproto_buf[n], SSH_IPPROTO_IPPCP);

      n++;
    }

  /* If we have initiated the rekey, we have stored information in the SPI 
     table that this rekey is already in progress. We are done now, so we
     can clear the information from the SPI entry. */
  if (qm->spi_neg_started)
    {
      if (!ssh_pm_mark_outbound_spi_neg_finished(pm, qm->old_outbound_spi,
						 qm->old_inbound_spi))
	SSH_DEBUG(SSH_D_FAIL, ("Old outbound SPI entry not found."));
      qm->spi_neg_started = 0;
    }

  if (qm->error)
    {
      n = 0;
      msg = qm->rekey
	? "Rekeyed IPsec SA installation failed"
	: "IPsec SA installation failed";
    }
  else
    msg = qm->rekey
      ? "Rekeyed IPsec SA installed" : "IPsec SA installed";

  switch (n)
    {
    case 0:
      ssh_pm_audit_event(pm, SSH_PM_AUDIT_POLICY,
			 SSH_AUDIT_NOTICE,
			 SSH_AUDIT_TXT, "IPsec SA not installed",
			 SSH_AUDIT_ARGUMENT_END);
      break;
    case 1:
      ssh_pm_audit_event(pm, SSH_PM_AUDIT_POLICY,
			 SSH_AUDIT_NOTICE,
			 SSH_AUDIT_TXT, msg,
			 SSH_AUDIT_IPPROTO,
			 ipproto_buf[0], sizeof(ipproto_buf[0]),
			 SSH_AUDIT_SPI, spi_buf[0], sizeof(spi_buf[0]),
			 SSH_AUDIT_ARGUMENT_END);
      break;
    case 2:
      ssh_pm_audit_event(pm, SSH_PM_AUDIT_POLICY,
			 SSH_AUDIT_NOTICE,
			 SSH_AUDIT_TXT, msg,
			 SSH_AUDIT_IPPROTO,
			 ipproto_buf[0], sizeof(ipproto_buf[0]),
			 SSH_AUDIT_SPI, spi_buf[0], sizeof(spi_buf[0]),
			 SSH_AUDIT_IPPROTO,
			 ipproto_buf[1], sizeof(ipproto_buf[1]),
			 SSH_AUDIT_SPI, spi_buf[1], sizeof(spi_buf[1]),
			 SSH_AUDIT_ARGUMENT_END);
      break;
    case 3:
      ssh_pm_audit_event(pm, SSH_PM_AUDIT_POLICY,
			 SSH_AUDIT_NOTICE,
			 SSH_AUDIT_TXT, msg,
			 SSH_AUDIT_IPPROTO,
			 ipproto_buf[0], sizeof(ipproto_buf[0]),
			 SSH_AUDIT_SPI, spi_buf[0], sizeof(spi_buf[0]),
			 SSH_AUDIT_IPPROTO,
			 ipproto_buf[1], sizeof(ipproto_buf[1]),
			 SSH_AUDIT_SPI, spi_buf[1], sizeof(spi_buf[1]),
			 SSH_AUDIT_IPPROTO,
			 ipproto_buf[2], sizeof(ipproto_buf[2]),
			 SSH_AUDIT_SPI, spi_buf[2], sizeof(spi_buf[2]),
			 SSH_AUDIT_ARGUMENT_END);
      break;
    }

#ifdef WITH_IKE
  if (qm->error == SSH_IKEV2_ERROR_OK &&
      (firstproto == SSH_IPPROTO_ESP ||
       firstproto == SSH_IPPROTO_AH))
    {
      /* Notify unknown SPI handler about a new inbound SA. */
      ssh_pm_new_inbound_spi(pm,
			     &qm->sa_handler_data.trd.data.own_addr,
			     &qm->sa_handler_data.trd.data.gw_addr,
			     firstproto,
			     firstspi);
    }
#endif /* WITH_IKE */

  /* We are finished.  Let's signal our Quick-Mode negotiation thread
     and we are done. */
  SSH_DEBUG(SSH_D_LOWOK,
	    ("Waking Quick-Mode thread: error code=%d", qm->error));

  qm->sa_handler_done = 1;
  if (qm->initiator)
    ssh_fsm_continue(&qm->thread);

  if (!qm->tunnel->manual_tn)
    {
      if (!qm->callbacks.aborted)
	{
	  /* SA handler does not fail towards IKE. If we have failed, the
	     delayed IPsec SA deletion is always initiated from the
	     failure state. */
	  if (qm->callbacks.u.ipsec_sa_install_cb)
	    (*qm->callbacks.u.ipsec_sa_install_cb)(qm->error,
					       qm->callbacks.callback_context);

	  ssh_operation_unregister(qm->callbacks.operation);
	}
    }

  return SSH_FSM_FINISH;
}
