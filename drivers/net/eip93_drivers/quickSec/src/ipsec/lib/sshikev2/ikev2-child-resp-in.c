/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004, 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 16:09 Dec 10 2004 kivinen
 *        Last Modification : 11:27 Apr 13 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.111
 *        
 *
 *        Description       : IKEv2 state machine for CREATE CHILD
 *			      responder in.
 *
 *
 *        $Log: ikev2-child-resp-in.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:04  treychen_hc
 *        add eip93 drivers
 * *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateChildRespIn"

/* Responder side CREATE CHILD packet in. */
SSH_FSM_STEP(ikev2_state_child_responder_in)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_check_rekey);

  if (packet->ed->sa == NULL ||
      packet->ed->nonce == NULL ||
      packet->ed->ipsec_ed->ts_i == NULL ||
      packet->ed->ipsec_ed->ts_r == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
		      ("Error: Mandatory payloads (SAi,Ni,TSi,TSr) missing"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Mandatory payloads (SAr,Ni,TSi,TSr) missing");
      
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = CREATE_CHILD"));
  packet->ed->state = SSH_IKEV2_STATE_CREATE_CHILD;
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Responder side CREATE CHILD packet, check if we have
   REKEY notify payload. */
SSH_FSM_STEP(ikev2_state_child_responder_in_check_rekey)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotify notify;
  int i;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_alloc_sa);
  for(i = 0, notify = packet->ed->notify;
      i < packet->ed->notify_count && notify != NULL;
      i++, notify = notify->next_notify)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_REKEY_SA &&
	  notify->spi_size == 4 &&
	  notify->spi_data != NULL &&
	  notify->notification_size == 0)
	{
	  /* Found REKEY. */
	  packet->ed->ipsec_ed->rekeyed_spi = SSH_GET_32BIT(notify->spi_data);
	  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("N(REKEY_SA) found spi = %08lx",
					   (unsigned long)
					   packet->ed->ipsec_ed->rekeyed_spi));
	  break;
	}
    }
  return SSH_FSM_CONTINUE;
}

void ikev2_reply_cb_child_resp_ipsec_spi_allocate(SshIkev2Error error_code,
						  SshUInt32 spi,
						  void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IPsec SA allocated successfully"));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IPsec SA allocate failed: %d",
				 error_code));
  packet->ed->ipsec_ed->spi_inbound = spi;
}

/* Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_child_responder_in_alloc_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_sa);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_spi_allocate)
		     (ike_sa->server->sad_handle, packet->ed,
		      ikev2_reply_cb_child_resp_ipsec_spi_allocate, packet));
}

void
ikev2_reply_cb_child_responder_select_ipsec_sa(SshIkev2Error error_code,
					       int proposal_index,
					       SshIkev2PayloadTransform
					       selected_transforms
					       [SSH_IKEV2_TRANSFORM_TYPE_MAX],
					       void *context)
{
  SshIkev2Packet packet = context;

  if (!ikev2_select_sa_reply(packet, error_code,
			     selected_transforms,
			     packet->ed->ipsec_ed->ipsec_sa_transforms))
    return;
  packet->ed->ipsec_ed->spi_outbound =
    packet->ed->sa->spis.ipsec_spis[proposal_index];
  packet->ed->ipsec_ed->sa = packet->ed->sa;
  packet->ed->ipsec_ed->sa->proposal_number = proposal_index + 1;
  packet->ed->ipsec_ed->ipsec_sa_protocol =
    packet->ed->ipsec_ed->sa->protocol_id[proposal_index];
  packet->ed->sa = NULL;
}

/* Do the SA payload processing, i.e. call to the policy
   manager spd select ike SA function. */
SSH_FSM_STEP(ikev2_state_child_responder_in_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_nonce);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, select_ipsec_sa)
		     (ike_sa->server->sad_handle, packet->ed,
		      packet->ed->sa,
		      ikev2_reply_cb_child_responder_select_ipsec_sa,
		      packet));
}

/* Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_child_responder_in_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_ke);
  ikev2_check_nonce(packet, &(packet->ed->ipsec_ed->ni));
  return SSH_FSM_CONTINUE;
}

/* Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_child_responder_in_ke)
{
  SshIkev2Packet packet = thread_context;
  SshUInt16 ke_group, selected_group;

  ke_group = 0;
  selected_group = 0;

  if (packet->ed->ke != NULL)
    ke_group = packet->ed->ke->dh_group;

  if (packet->ed->ipsec_ed->
      ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H] != NULL)
    selected_group = packet->ed->ipsec_ed->
      ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id;

  if (ke_group != selected_group)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
		      ("KE payload does not match selected group send "
		       "N(INVALID_KE_PAYLOAD)"));
      /** Send INVALID_KE_PAYLOAD error. */
      SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_invalid_ke);
    }
  else
    {
      /** Valid group, continue. */
      SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_ts);
    }
  packet->ed->ipsec_ed->group_number = ke_group;
  return SSH_FSM_CONTINUE;
}

void ikev2_reply_cb_child_responder_narrow(SshIkev2Error error_code,
					   SshIkev2PayloadTS return_ts_local,
					   SshIkev2PayloadTS return_ts_remote,
					   void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Traffic selectors narrowed successfully"));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Traffic selectors narrow failed: %d",
				 error_code));
  if (return_ts_local)
    packet->ed->ipsec_ed->ts_local = return_ts_local;
  else
    packet->ed->ipsec_ed->ts_local = packet->ed->ipsec_ed->ts_r;

  ssh_ikev2_ts_take_ref(packet->ike_sa->server->sad_handle,
			packet->ed->ipsec_ed->ts_local);
  if (return_ts_remote)
    packet->ed->ipsec_ed->ts_remote = return_ts_remote;
  else
    packet->ed->ipsec_ed->ts_remote = packet->ed->ipsec_ed->ts_i;

  ssh_ikev2_ts_take_ref(packet->ike_sa->server->sad_handle,
			packet->ed->ipsec_ed->ts_remote);
}

/* Narrow the traffic selector. */
SSH_FSM_STEP(ikev2_state_child_responder_in_ts)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_in_end);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, narrow)
		     (ike_sa->server->sad_handle, packet->ed,
		      packet->ed->ipsec_ed->ts_r,
		      packet->ed->ipsec_ed->ts_i,
		      ikev2_reply_cb_child_responder_narrow,
		      packet));
}

/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_child_responder_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  /** Send reply CREATE_CHILD_SA packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_child_responder_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_child_responder_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;
  ikev2_udp_window_update(reply_packet);
  return SSH_FSM_FINISH;
}

/* Send INVALID_KE_PAYLOAD error with proper group. */
SSH_FSM_STEP(ikev2_state_child_responder_in_invalid_ke)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  /** Send N(INVALID_KE). */
  /* SSH_FSM_SET_NEXT(ikev2_state_reply_ke_error_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_reply_ke_error_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  ikev2_udp_window_update(reply_packet);
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Send N(INVALID_KE_PAYLOAD)"));
  return SSH_FSM_FINISH;
}
