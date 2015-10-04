/*
  File: pad_ike.c

  Copyright:
        Copyright 2005 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Policy manager PAD module.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIkePAD"

/****************** IKE New Connection Rate Limiting **********************/


#ifndef SSH_IPSEC_SMALL
/* Increment new connection rate by `value'. */
static void pm_ike_connection_rate_add(SshPm pm, SshUInt32 value)
{
  pm->ike_connection_rate.current_value += value;
}

/* Return the maximum of current new connection rate and
   averaged new connection rate. */
static SshUInt32 pm_ike_connection_rate_get(SshPm pm)
{
  if (pm->ike_connection_rate.current_value >
      pm->ike_connection_rate.average_value)
    return pm->ike_connection_rate.current_value;

  return pm->ike_connection_rate.average_value;
}
#endif /* SSH_IPSEC_SMALL */

/* Check whether the IKE responder should request a cookie from the IKE
   initiator when a new connection request is received, or whether the
   IKE responder should drop the connection attempt.

   We request a cookie if the policy enforces it, the number of available
   Phase-I negotiation structures reaches a soft limit, or the average
   incoming new connection rate exceeds a limit.

   The connection attempt is dropped if we run out of available Phase-I
   negotiation structures, or if the average incoming new connection rate
   exceeds a hard limit and we have reached the soft limit of available
   Phase-I negotiation structures. */
static SshIkev2Error pm_ike_rate_limit(SshPm pm, SshIkev2Server server,
				       SshUInt8 major_version,
				       SshIpAddr remote_address,
				       SshUInt16 port)
{
  SshIkev2Error error = SSH_IKEV2_ERROR_OK;

#ifndef SSH_IPSEC_SMALL
  SshUInt32 connection_rate;

  /* Cookie request forced by configuration.
     Request cookie even though we might not have resources to process
     the new IKE negotiation right now. */
  if (major_version == 2 && pm->flags & SSH_PM_FLAG_REQUIRE_COOKIE)
    {
      error = SSH_IKEV2_ERROR_COOKIE_REQUIRED;
      goto out;
    }

  SSH_ASSERT(pm->num_active_p1_negotiations <= SSH_PM_MAX_IKE_SA_NEGOTIATIONS);

  /* Hard limit reached on number of connections; deny new connection. */
  if (pm->num_active_p1_negotiations >= SSH_PM_MAX_IKE_NEW_CONNECTION)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
		    "Out of IKE SAs. Dropping new IKE SA request from %@:%d",
		    ssh_ipaddr_render, remote_address, port);
      error = SSH_IKEV2_ERROR_DISCARD_PACKET;
      goto out;
    }
  /* Soft limit reached on number of connections;
     request cookie and check new connection rate. */
  else if (pm->num_active_p1_negotiations >=
	   SSH_PM_IKE_NEW_CONNECTION_SOFT_LIMIT)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("New IKE connections soft limit reached, "
			       "requesting cookie"));
      error = SSH_IKEV2_ERROR_COOKIE_REQUIRED;
      goto out;
    }

  /* Get average new connection rate from the decaying counter. */
  connection_rate = pm_ike_connection_rate_get(pm);
  
  /* Hard limit reached on new connection rate */
  if (connection_rate >= SSH_PM_MAX_IKE_NEW_CONNECTION_RATE)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
		    "New IKE connection rate limit reached. "
		    "Dropping new IKE SA request from %@:%d",
		    ssh_ipaddr_render, remote_address, port);
      SSH_DEBUG(SSH_D_HIGHSTART,
		("Connection rate %d (conn/s)", 
		 (int) connection_rate));
      error = SSH_IKEV2_ERROR_DISCARD_PACKET;
      goto out;
    }
  /* Soft limit reached on new connection rate; request cookie. */
  else if (connection_rate >= SSH_PM_IKE_NEW_CONNECTION_RATE_SOFT_LIMIT)
    {
      error = SSH_IKEV2_ERROR_COOKIE_REQUIRED;
      goto out;
    }
  
 out:
  if (major_version == 1 && error == SSH_IKEV2_ERROR_COOKIE_REQUIRED)
    error = SSH_IKEV2_ERROR_DISCARD_PACKET;

  /* Update decaying counter. */
  pm_ike_connection_rate_add(pm, 1);

#else /* SSH_IPSEC_SMALL */
  if (pm->params.flags & SSH_PM_FLAG_REQUIRE_COOKIE)
    {
      error = SSH_IKEV2_ERROR_COOKIE_REQUIRED;
    }
#endif /* SSH_IPSEC_SMALL */

  if (error == SSH_IKEV2_ERROR_OK)
    {
      /* New connection accepted. */
      SSH_DEBUG(SSH_D_HIGHSTART, ("New connection from %@:%d allowed",
                                  ssh_ipaddr_render, remote_address, port));
    }
  else
    {
      /* New connection rejected. */
      SSH_DEBUG(SSH_D_FAIL, ("New connection from %@:%d forbidden",
			     ssh_ipaddr_render, remote_address, port));
    }

  return error;
}


/****************** PAD Interface functions *******************************/


/*************************** New Connection *******************************/

SshOperationHandle
ssh_pm_ike_new_connection(SshSADHandle sad_handle,
			  SshIkev2Server server,
			  SshUInt8 major, SshUInt8 minor,
			  SshIpAddr remote_address,
			  SshUInt16 port,
			  SshIkev2PadNewConnectionCB reply_callback,
			  void *reply_callback_context)

{
  SshPm pm = sad_handle->pm;
  SshIkev2Error decision;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("New connection from %@:%d rejected - pm not active",
		 ssh_ipaddr_render, remote_address, port));

      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
			reply_callback_context);
      return NULL;
    }


  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("New connection from %@:%d rejected - shutting down",
		 ssh_ipaddr_render, remote_address, port));

      (*reply_callback)(SSH_IKEV2_ERROR_DISCARD_PACKET,
			reply_callback_context);
      return NULL;
    }

  decision = pm_ike_rate_limit(pm, server, major, remote_address, port);

  (*reply_callback)(decision, reply_callback_context);
  return NULL;
}


/***************************** Get IKE ID ***********************************/

SshOperationHandle
ssh_pm_ike_id(SshSADHandle sad_handle,
	      SshIkev2ExchangeData ed,
	      Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
              SshUInt32 authentication_round,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
	      SshIkev2PadIDCB reply_callback,
	      void *reply_callback_context)
{
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshIkev2PayloadID id;
  SshPmTunnel tunnel;
  Boolean initiator;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  Boolean another_auth_follows;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  SSH_PM_ASSERT_P1(p1);
  SSH_PM_ASSERT_P1N(p1);

  if (ssh_pm_get_status(sad_handle->pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
			local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                        FALSE, 
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                        0, 
                        reply_callback_context);
      return NULL;
    }


  initiator = p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;

  /* Select a tunnel for the reponder if not already done */
  if (!initiator &&
      !ssh_pm_select_ike_responder_tunnel(sad_handle->pm, p1, ed))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
			local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                        FALSE, 
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                        0, 
                        reply_callback_context);
      return NULL;
    }

  SSH_ASSERT(p1->n->tunnel != NULL);
  tunnel = p1->n->tunnel;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* Second authentication is set if second identity
     exists for the initiator or if second auth domain 
     is set for the responder */
  if (initiator && authentication_round == 1 &&
      tunnel->second_local_identity)
    another_auth_follows = TRUE;
  else if (!initiator && authentication_round == 1 
           && tunnel->second_auth_domain_name)
    another_auth_follows = TRUE;
  else
    another_auth_follows = FALSE;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


  /* Select our identity based on that configured for the tunnel. */
  if (local)
    {
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (authentication_round > 1)
        {
          /* Currently we support only one extra identity */
          SSH_ASSERT(tunnel->second_local_identity != NULL);
          id = ssh_pm_ikev2_payload_id_dup(tunnel->second_local_identity);
        }
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        {
          id = ssh_pm_ike_get_identity(sad_handle->pm, p1, tunnel, TRUE);
        }
      if (id != NULL)
	{
	  SSH_ASSERT(id->id_type != 0);
	  
	  SSH_DEBUG(SSH_D_MIDOK, 
		    ("Using %@ as local Phase-1 identity (%s)",
		     ssh_pm_ike_id_render, id,
		     initiator ? 
		     "initiator" : "responder"));

	  (*reply_callback)(SSH_IKEV2_ERROR_OK, TRUE, 
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                            another_auth_follows, 
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                            id,
			    reply_callback_context);
	  ssh_pm_ikev2_payload_id_free(id);	  
	}
      else
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Could not allocate IKE identity"));
	  (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, TRUE, 
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                            FALSE, 
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                            NULL,
			    reply_callback_context);
	}
      return NULL;
    }
  else
    {
      SSH_ASSERT(initiator);

      /* Use the tunnel's configured remote identity. */
      (*reply_callback)(SSH_IKEV2_ERROR_OK, FALSE,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                        FALSE, 
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
			tunnel->remote_identity,
			reply_callback_context);
      return NULL;
    }
}


/************************ Preshared key lookup ***************************/

static void pm_ike_psk_abort(void *context)
{
  SshPmP1 p1 = (SshPmP1)context;

  p1->callbacks.aborted = TRUE;
  p1->callbacks.u.pre_shared_key_cb = NULL_FNPTR;
  p1->callbacks.callback_context = NULL;
}

static void ssh_pm_find_pre_shared_key_cb(const unsigned char *key,
					  size_t key_len,
					  void *context)
{
 SshFSMThread thread = (SshFSMThread) context;
 SshPmP1 p1 = (SshPmP1) ssh_fsm_get_tdata(thread);

 if (!p1->callbacks.aborted)
   {
     if (p1->callbacks.u.pre_shared_key_cb)
       (*p1->callbacks.u.pre_shared_key_cb)(key ? SSH_IKEV2_ERROR_OK :
					 SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
					 key, key_len,
					 p1->callbacks.callback_context);
     ssh_operation_unregister(p1->callbacks.operation);
   }
 SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(pm_ike_id_psk_lookup_start)
{
  SshPm pm = fsm_context;
  SshPmP1 p1 = thread_context;
  unsigned char *key = NULL;
  size_t key_len = 0;

  /* Check if the operation has been aborted already and if so bail out. 
     This check is necessary since in certain cases the IKE exchange 
     data ed may already have been freed as this stage and ed is used 
     below. */
  if (p1->callbacks.aborted)
    {
      SSH_FSM_SET_NEXT(pm_ike_id_psk_lookup_finish);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(p1->n->ed != NULL);

  /* If a callback has been registered for retrieving preshared
     keys, call it here. */
  if (pm->ike_preshared_keys_cb)
    {
      SSH_FSM_SET_NEXT(pm_ike_id_psk_lookup_finish);
      SSH_DEBUG(SSH_D_LOWSTART, ("Calling Preshared key callback"));

      SSH_FSM_ASYNC_CALL((*pm->ike_preshared_keys_cb)(p1->n->ed,
					   ssh_pm_find_pre_shared_key_cb,
					   thread,
					   pm->ike_preshared_keys_cb_context));
      SSH_NOTREACHED;
    }

  /* Lookup the preshared key based on the remote identity. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      key = ssh_pm_ike_preshared_keys_get_secret(p1->auth_domain, 
                                                 p1->n->ed->ike_ed->id_r,
						 &key_len);
    }
  else
    {
      key = ssh_pm_ike_preshared_keys_get_secret(p1->auth_domain, 
                                                 p1->n->ed->ike_ed->id_i,
						 &key_len);
    }

  /* If we do not know a preshared key for this remote identity then,
     we must fail this operation. */
  if (key == NULL)
    {
      p1->n->failure_mask |= SSH_PM_E_REMOTE_ID_MISMATCH;
      goto error;
    }

  if (!p1->callbacks.aborted)
    {
      (*p1->callbacks.u.pre_shared_key_cb)(SSH_IKEV2_ERROR_OK, key, key_len,
					   p1->callbacks.callback_context);
      ssh_operation_unregister(p1->callbacks.operation);
    }

  SSH_FSM_SET_NEXT(pm_ike_id_psk_lookup_finish);
  return SSH_FSM_CONTINUE;

 error:

  if (!p1->callbacks.aborted)
    {
      (*p1->callbacks.u.pre_shared_key_cb)(
					 SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
					 NULL, 0,
					 p1->callbacks.callback_context);
      ssh_operation_unregister(p1->callbacks.operation);
    }
  SSH_FSM_SET_NEXT(pm_ike_id_psk_lookup_finish);
  return SSH_FSM_CONTINUE;

}

SSH_FSM_STEP(pm_ike_id_psk_lookup_finish)
{
  return SSH_FSM_FINISH;
}

/* Find pre shared secret for local or remote host. When 'local' is FALSE
   the primary selector is the remote id field. Call reply_callback when
   the data is available (it can also be called immediately).

   If `local' is true then we search for the local pre-shared key. */
SshOperationHandle
ssh_pm_ike_pre_shared_key(SshSADHandle sad_handle,
			  SshIkev2ExchangeData ed,
			  Boolean local,
			  SshIkev2PadSharedKeyCB reply_callback,
			  void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  unsigned char *key = NULL;
  size_t key_len = 0;

  SSH_PM_ASSERT_P1(p1);
  SSH_PM_ASSERT_P1N(p1);

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
			NULL, 0, reply_callback_context);
      return NULL;
    }

  if (!SSH_PM_P1_USABLE(p1))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE,
			NULL, 0, reply_callback_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("Enter SA %p ED %p Asking for %s preshared key",
			     ed->ike_sa, ed, local ? "local" : "remote"));

  /* Select a tunnel for the reponder if not already done */
  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
      !ssh_pm_select_ike_responder_tunnel(pm, p1, ed))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
			NULL, 0, reply_callback_context);
      return NULL;
    }

  /* If the IKE initiator has used the "me Tarzan, you Jane" option, then
     check here that that responder has replied with an acceptable identity. */
  if (!local && !ssh_pm_ike_check_requested_identity(pm, p1, ed->ike_ed->id_r))
    {
      p1->n->failure_mask |= SSH_PM_E_REMOTE_ID_MISMATCH;
      (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED, NULL, 0,
			reply_callback_context);
      return NULL;
    }

  if (p1->n->ed == NULL)
    p1->n->ed = ed;

  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED, NULL, 0,
			reply_callback_context);
      return NULL;
    }

#ifdef SSHDIST_IKE_EAP_AUTH
  /* Check if EAP is configured for the tunnels authentication domain
     and this is an IKEv2 SA */
  if (p1->auth_domain->num_eap_protocols
#ifdef SSHDIST_IKEV1
      && ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0)
#endif /* SSHDIST_IKEV1 */
      )
    {
      /* To use EAP, the initiator omits the AUTH payload by returning
	 a NULL Pre Shared Key. */
      if (local && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
	{
	  (*reply_callback)(SSH_IKEV2_ERROR_OK, NULL, 0,
			    reply_callback_context);
	  return NULL;
	}
      
      /* RFC 4306 forbids EAP with pre shared key responder authentication.
	 Fail authentication here, as we end up here only if configuration
	 for certicate based responder authentication was missing. */
      if (!local && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
	{
	  SSH_DEBUG(SSH_D_FAIL,
		    ("EAP authentication cannot be used with pre shared key "
		     "based responder authentication."));
	  p1->n->failure_mask |= SSH_PM_E_AUTH_METHOD_MISMATCH;
	  (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED, NULL, 0,
			    reply_callback_context);
	  return NULL;
	}
    }
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKEV1
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1 &&
      ed->ike_ed->exchange_type == SSH_IKE_XCHG_TYPE_AGGR)
    p1->ike_sa->flags |= SSH_IKEV2_FB_IKE_AGGRESSIVE_MODE;
#endif /* SSHDIST_IKEV1 */

  /* Take local secret from tunnel for IKEv2 and IKEv1 main mode. */
  if (local
#ifdef SSHDIST_IKEV1
      /* In IKEv1 aggressive mode responder, we'll use the remote
	 secret by requestor ID, and for initiator the one from tunnel
	 local identity. */
      && ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
	  || !(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	  || (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1
	      && ed->ike_ed->exchange_type != SSH_IKE_XCHG_TYPE_AGGR))
#endif /* SSHDIST_IKEV1 */
      )
    {
      /* Always use the first available secret. */
      if (p1->n->tunnel->u.ike.num_secrets)
	{
	  key = p1->n->tunnel->u.ike.secrets->secret;
	  key_len = p1->n->tunnel->u.ike.secrets->secret_len;
          
	  /* Save the copy of the local secret to the Phase-1 object. */
	  p1->local_secret_len = key_len;
	  p1->local_secret = ssh_memdup(key, key_len);
          
	  if (!p1->local_secret)
	    {
              p1->local_secret_len = 0;
	      key = NULL;
	      key_len = 0;
	    }
	}
      
      /* If we have key, or if we are using IKEv1 (main mode
	 return key or error). */ 
      if (key != NULL
#ifdef SSHDIST_IKEV1
	  || (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
#endif /* SSHDIST_IKEV1 */
	  )
	{
          /* Record the local authentication method */
          p1->local_auth_method = SSH_PM_AUTH_PSK;
#ifdef SSHDIST_IKEV1
          /* For IKEv1 negotiations this policy call is not called for 'local'
             equal to FALSE, so we set 'p1->remote_auth_method' here. */
          if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
            p1->remote_auth_method = SSH_PM_AUTH_PSK;
#endif /* SSHDIST_IKEV1 */
          
          (*reply_callback)((key != NULL) ? SSH_IKEV2_ERROR_OK :
                            SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                            key, key_len,
                            reply_callback_context);
          return NULL;
        }
    }

  /* Store the reply callback and context */
  p1->callbacks.aborted = FALSE;
  p1->callbacks.u.pre_shared_key_cb = reply_callback;
  p1->callbacks.callback_context = reply_callback_context;
  
  /* Record the remote authentication method */
  p1->remote_auth_method = SSH_PM_AUTH_PSK;
  
#ifdef SSHDIST_IKEV1
  /* Set the local auth method for IKEv1 agressive mode responders */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    p1->local_auth_method = SSH_PM_AUTH_PSK;
#endif /* SSHDIST_IKEV1 */
  
  ssh_operation_register_no_alloc(p1->callbacks.operation,
                                  pm_ike_psk_abort, p1);
  
  ssh_fsm_thread_init(&pm->fsm, &p1->n->sub_thread,
                      pm_ike_id_psk_lookup_start,
                      NULL_FNPTR, NULL_FNPTR, p1);
  
  ssh_fsm_set_thread_name(&p1->n->sub_thread, "IKE PSK");
  return p1->callbacks.operation;
}

/****************** Configuration payload processing ************************/

void
ssh_pm_ike_conf_received(SshSADHandle sad_handle,
			 SshIkev2ExchangeData ed,
			 SshIkev2PayloadConf conf_payload_in)
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Received configuration payload %@ from the "
			       "IKE library", ssh_ikev2_payload_conf_render,
			       conf_payload_in));





  if (!SSH_PM_P1_USABLE(p1))
    return;

  /* Informational and Child SA exchanges not supported */
  if (ed->state != SSH_IKEV2_STATE_IKE_AUTH_1ST &&
#ifdef SSHDIST_IKE_EAP_AUTH
      ed->state != SSH_IKEV2_STATE_IKE_AUTH_EAP &&
#endif /* SSHDIST_IKE_EAP_AUTH */
      ed->state != SSH_IKEV2_STATE_IKE_AUTH_LAST)
    return;

  if (p1->remote_access_attrs)
    ssh_pm_free_remote_access_attrs(p1->remote_access_attrs);

  p1->remote_access_attrs = ssh_calloc(1, sizeof(*p1->remote_access_attrs));

  /* Decode the configuration payload. */
  if (p1->remote_access_attrs == NULL ||
      !ssh_pm_decode_conf_payload_request(conf_payload_in,
					  p1->remote_access_attrs))
    {
      if (p1->n)
	p1->n->conf_received_failed = 1;
    }

#endif /* SSHDIST_ISAKMP_CFG_MODE */
  return;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

static void
ssh_pm_cfgmode_alloc(SshPmRemoteAccessAttrs attributes, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmIkev2ConfQuery query = (SshPmIkev2ConfQuery) ssh_fsm_get_tdata(thread);
  SshPmRemoteAccessAttrsFreeCB free_cb;
  void *free_cb_context;
  SshPmP1 p1 = query->p1;
  SshIkev2Error error;
  SshPmRemoteAccessAttrs checked_attributes = NULL;
  SshUInt32 i, j, k;

  /* Mark the alloc operation completed. */
  query->sub_operation = NULL;

  /* The most common failure case */
  error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  free_cb = query->tunnel->u.ike.remote_access_free_cb;
  free_cb_context = query->tunnel->u.ike.remote_access_cb_context;
  
  /* Free any attributes that the client specified.
     Skip this if this is an imported IKE SA. */
  if (!query->ike_sa_import)
    {
      if (query->client_attributes)
	{
	  ssh_pm_free_remote_access_attrs(query->client_attributes);
	  query->client_attributes = NULL;
	}
    }

  /* Free old remote_access_attrs. */
  if (p1->remote_access_attrs)
    ssh_pm_free_remote_access_attrs(p1->remote_access_attrs);
  p1->remote_access_attrs = NULL;

  if (attributes)
    {
      /* Check the attributes. */
      checked_attributes = ssh_pm_dup_remote_access_attrs(attributes);
      if (checked_attributes == NULL)
	goto error;
      
      /* Check that for each additional subnet there is 
	 an address of the same address family. */
      for (i = 0, j = 0; i < attributes->num_subnets; i++)
	{
	  for (k = 0; k < attributes->num_addresses; k++)	    
	    if ((SSH_IP_IS4(&attributes->subnets[i])
		 && SSH_IP_IS4(&attributes->addresses[k]))
		|| (SSH_IP_IS6(&attributes->subnets[i])
		    && SSH_IP_IS6(&attributes->addresses[k])))
	      break;

	  /* No suitable address found, skip this subnet. */
	  if (k == attributes->num_addresses)
	    continue;

	  /* Valid address found, copy this subnet. */
	  checked_attributes->subnets[j++] = attributes->subnets[i];	  
	}
      checked_attributes->num_subnets = j;

      /* Skip encoding if this is an imported IKE SA. */
      if (!query->ike_sa_import)
	{
	  SshIkev2ConfType conf_type;
	  
	  if (query->ed->conf == NULL)
	    conf_type = SSH_IKEV2_CFG_SET;
	  else
	    conf_type = SSH_IKEV2_CFG_REPLY;
	  
	  /* Encode remote access attributes. */
	  if ((query->conf_payload =
	       ssh_ikev2_conf_allocate(pm->sad_handle, conf_type)) == NULL)
	    goto error;

	  if (!ssh_pm_encode_remote_access_attrs(query->conf_payload,
						 checked_attributes))
	    {
	      error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
	      goto error;
	    }
	}

      /* The attributes are successfully encoded. Now, allocate a cfgmode 
	 client store object if we have a free callback for the remote access
	 addresses. */
      if (free_cb)
        {
	  /* Release old client IP addresses from client store. */
	  if (p1->cfgmode_client)
	    ssh_pm_cfgmode_client_store_unreference(pm, p1->cfgmode_client);
	  
	  /* Register new client IP address. */
	  p1->cfgmode_client = ssh_pm_cfgmode_client_store_alloc(pm, p1);
	  if (p1->cfgmode_client == NULL)
	    goto error;
	}

      /* Set new remote access attributes to p1. */
      p1->remote_access_attrs = checked_attributes;
      checked_attributes = NULL;
    }
  else
    {
      error = SSH_IKEV2_ERROR_INTERNAL_ADDRESS_FAILURE;
      goto error;
    }

  query->error = SSH_IKEV2_ERROR_OK;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;

  /* Error handling. */
 error:

  SSH_ASSERT(error != SSH_IKEV2_ERROR_OK);
  query->error = error;

  if (checked_attributes)
    ssh_pm_free_remote_access_attrs(checked_attributes);
  
  if (p1->cfgmode_client)
    {
      ssh_pm_cfgmode_client_store_unreference(pm, p1->cfgmode_client);
      p1->cfgmode_client = NULL;
    }

  if (query->conf_payload)
    {
      ssh_ikev2_conf_free(pm->sad_handle, query->conf_payload);
      query->conf_payload = NULL;
    }

  /* Free the allocated remote access addresses. */
  if (attributes != NULL && free_cb != NULL_FNPTR)
    {
      for (i = 0; i < attributes->num_addresses; i++)
	(*free_cb)(pm, &attributes->addresses[i], attributes->address_context,
		   free_cb_context);
    }
  
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function completing the client store register. */
static void
pm_ras_attrs_register_client_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmIkev2ConfQuery query = (SshPmIkev2ConfQuery) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_LOWOK, ("Remote access address registration %s",
			  (success ? "succeeded" : "failed")));

  /* Mark the sub operation completed. */
  query->sub_operation = NULL;

  /* Move to next address. */
  query->index++;

  if (!success)
    query->error = SSH_IKEV2_ERROR_INTERNAL_ADDRESS_FAILURE;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Allocate client remote access attributes */

SSH_FSM_STEP(pm_ras_attrs_alloc)
{
  SshPm pm = fsm_context;
  SshPmIkev2ConfQuery query = (SshPmIkev2ConfQuery)thread_context;
  SshPmRemoteAccessAttrsAllocCB alloc_cb;
  void *alloc_cb_context;

  SSH_FSM_SET_NEXT(pm_ras_attrs_register_clients);

  if ((query->tunnel->flags & SSH_PM_TR_ALLOW_CFGMODE) == 0
      || (query->tunnel->u.ike.remote_access_alloc_cb == NULL_FNPTR))
    {
      query->error = SSH_IKEV2_ERROR_INTERNAL_ADDRESS_FAILURE;
      SSH_DEBUG(SSH_D_MIDOK, ("Policy does not allow configuration mode"));
      return SSH_FSM_CONTINUE;
    }
  
  SSH_DEBUG(SSH_D_MIDOK, ("Getting configuration attributes"));

  /* Query remote access attributes from the callback. */
  alloc_cb = query->tunnel->u.ike.remote_access_alloc_cb;
  alloc_cb_context = query->tunnel->u.ike.remote_access_cb_context; 
  SSH_ASSERT(alloc_cb != NULL_FNPTR);

  /* Check if the client request specifies attributes.
     Imported IKE SAs specify the attributes in client_attributes. */
  if (query->ed->conf != NULL)
    {
      query->client_attributes = ssh_malloc(sizeof(*query->client_attributes));
      
      if (query->client_attributes == NULL
	  || !ssh_pm_decode_conf_payload_request(query->ed->conf,
						 query->client_attributes))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Could not parse the client's conf payload"));
	  if (query->client_attributes == NULL)
	    {
	      query->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	    }
	  else
	    {
	      ssh_pm_free_remote_access_attrs(query->client_attributes);
	      query->client_attributes = NULL;
	      query->error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
	    }
	  return SSH_FSM_CONTINUE;
	}
    }

  SSH_ASSERT(query->sub_operation == NULL);
  SSH_FSM_ASYNC_CALL({
    query->sub_operation = (*alloc_cb)(pm, query->ed,
				       query->client_attributes,
				       ssh_pm_cfgmode_alloc, thread,
				       alloc_cb_context);
  });
  SSH_NOTREACHED;
}


SSH_FSM_STEP(pm_ras_attrs_register_clients)
{
  SshPm pm = fsm_context;
  SshPmIkev2ConfQuery query = (SshPmIkev2ConfQuery)thread_context;
  SshPmP1 p1 = query->p1;
  SshPmRemoteAccessAttrsFreeCB free_cb;
  void *free_cb_context;

  /* Resolve the free callback. */
  free_cb = query->tunnel->u.ike.remote_access_free_cb;
  free_cb_context = query->tunnel->u.ike.remote_access_cb_context;

  /* Check for previous errors */
  if (query->error != SSH_IKEV2_ERROR_OK)
    {
      /* Release client store object. This will free the allocated remote
	 access addresses that have been successfully registered. */
      if (p1->cfgmode_client)
	{
	  ssh_pm_cfgmode_client_store_unreference(pm, p1->cfgmode_client);
	  p1->cfgmode_client = NULL;
	}

      /* Free the remote access addresses that have not yet been registered
	 to client store.*/
      if (p1->remote_access_attrs != NULL)
	{
	  while (query->index < p1->remote_access_attrs->num_addresses)
	    {
	      if (free_cb)
		(*free_cb)(pm,
			   &p1->remote_access_attrs->addresses[query->index],
			   p1->remote_access_attrs->address_context,
			   free_cb_context);
	      query->index++;
	    }
	}

      if (query->conf_payload)
	{
	  ssh_ikev2_conf_free(pm->sad_handle, query->conf_payload);
	  query->conf_payload = NULL;
	}
      goto done;
    }
  
  /* Assert that in the successful case the remote access attributes are
     properly set to p1. */
  SSH_ASSERT(p1->remote_access_attrs != NULL);

  if (query->index == p1->remote_access_attrs->num_addresses)
    goto done;

  if (free_cb == NULL_FNPTR)
    goto done;

  /* Register the IP address as allocated. */
  SSH_ASSERT(query->sub_operation == NULL);
  SSH_FSM_ASYNC_CALL({
    query->sub_operation = 
      ssh_pm_cfgmode_client_store_register(
			     pm, query->tunnel,
			     p1->cfgmode_client,
			     &p1->remote_access_attrs->addresses[query->index],
			     p1->remote_access_attrs->address_context,
			     free_cb, free_cb_context,
			     pm_ras_attrs_register_client_cb, thread);
  });
  SSH_NOTREACHED;
  
 done:
  SSH_FSM_SET_NEXT(query->fsm_st_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_ras_attrs_done)
{
  SshPm pm = fsm_context;
  SshPmIkev2ConfQuery query = (SshPmIkev2ConfQuery)thread_context;
  int i;

  if (query->p1->callbacks.aborted)
    return SSH_FSM_FINISH;

  if (query->p1->callbacks.u.conf_cb)
    (*query->p1->callbacks.u.conf_cb)(query->error,
				      query->conf_payload,
				      query->p1->callbacks.callback_context);

  if (query->conf_payload && (query->error == SSH_IKEV2_ERROR_OK))
    {
      Boolean ikev2 = TRUE;
#ifdef SSHDIST_IKEV1
      if (query->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	ikev2 = FALSE;
#endif /* SSHDIST_IKEV1 */
      
      ssh_pm_log_cfgmode_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
			       query->p1,
			       query->conf_payload->conf_type,
			       ikev2 ? "completed" : "");
      
      for (i = 0; i < query->p1->remote_access_attrs->num_addresses; i++)
	ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
		      "  Address %@ sent to client",
		      ssh_ipaddr_render,
		      &query->p1->remote_access_attrs->addresses[i]);

      /* The IKE SA was modified.
	 Call the SA notification callback, if the IKE SA has been
	 exported earlier. */
      ssh_pm_ike_sa_event_updated(pm, query->p1);
    }

  ssh_operation_unregister(query->p1->callbacks.operation);
  return SSH_FSM_FINISH;
}

static void pm_ras_attrs_thread_destructor(SshFSM fsm, void *context)
{
  SshPmIkev2ConfQuery query = context;
  SshPm pm = ssh_fsm_get_gdata_fsm(fsm);

  SSH_PM_TUNNEL_DESTROY(pm, query->tunnel);

  /* Free ed reference.
     This might free the obstack this query was allocated from. */
  ssh_ikev2_exchange_data_free(query->ed);
}

static void pm_ras_attrs_abort(void *context)
{
  SshPmIkev2ConfQuery query = context;
  
  SSH_DEBUG(SSH_D_LOWOK, ("IKE RAS abort"));

  if (query->sub_operation)
    ssh_operation_abort(query->sub_operation);

  query->p1->callbacks.aborted = TRUE;

  ssh_fsm_set_next(&query->p1->thread, query->fsm_st_done);
  if (ssh_fsm_get_callback_flag(&query->p1->thread))
    SSH_FSM_CONTINUE_AFTER_CALLBACK(&query->p1->thread);
  else
    ssh_fsm_continue(&query->p1->thread);
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */


SshOperationHandle
ssh_pm_ike_conf_request(SshSADHandle sad_handle,
			SshIkev2ExchangeData ed,
			SshIkev2PadConfCB callback,
			void *context)
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshPmTunnel tunnel;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*callback)(SSH_IKEV2_ERROR_SUSPENDED, NULL, context);
      return NULL;
    }

  if (!SSH_PM_P1_USABLE(p1))
    {
      (*callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, NULL, context);
      return NULL;
    }

  /* Informational and Child SA exchanges not supported */
  if (ed->state != SSH_IKEV2_STATE_IKE_AUTH_1ST
      && ed->state != SSH_IKEV2_STATE_IKE_INIT_SA
#ifdef SSHDIST_IKE_EAP_AUTH
      && ed->state != SSH_IKEV2_STATE_IKE_AUTH_EAP
#endif /* SSHDIST_IKE_EAP_AUTH */
      && ed->state != SSH_IKEV2_STATE_IKE_AUTH_LAST
      && (ed->state != SSH_IKEV2_STATE_INFORMATIONAL
#ifdef SSHDIST_IKEV1
	  && !(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
#endif /* SSHDIST_IKEV1 */
	  ))
    {
      (*callback)(SSH_IKEV2_ERROR_OK, NULL, context);
      return NULL;
    }

  SSH_PM_ASSERT_P1(p1);

  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel == NULL)
    {
      (*callback)(SSH_IKEV2_ERROR_OK, NULL, context);
      return NULL;
    }

  /* Check whether we are interested in configuration payloads. */
  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      SshIkev2PayloadConf conf_payload;

      /* Check configuration mode for the initiator. */
      if ((tunnel->flags & SSH_PM_TI_CFGMODE) == 0)
	{
	  SSH_DEBUG(SSH_D_LOWSTART, ("Ignoring Conf Request payload"));
	  (*callback)(SSH_IKEV2_ERROR_OK, NULL, context);
	  return NULL;
	}

#ifdef SSHDIST_IKEV1
      /* Check if we have already received remote access attributes from
	 RAS. This may happen if this negotiation creates a new IKEv1 SA
	 after the original IKEv1 SA has expired but we still have IPsec
	 SAs using those remote access attributes. In such case we have
	 the original attributes stored in the vip object. */
      if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	  && tunnel->vip && tunnel->vip->attrs.num_addresses > 0)
	{
	  SSH_DEBUG(SSH_D_LOWSTART,
		    ("No need to request new config attributes for IKEv1 "
		     "SA %p", p1->ike_sa));
	  (*callback)(SSH_IKEV2_ERROR_OK, NULL, context);
	  return NULL;
	}
#endif /* SSHDIST_IKEV1 */

      conf_payload = ssh_pm_construct_conf_request_payload(sad_handle->pm, p1);

      if (conf_payload == NULL)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Cannot construct configuration payload"));

	  (*callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT, NULL, context);
	  return NULL;
	}

      SSH_DEBUG(SSH_D_MIDSTART, ("Returning configuration payload %@ to "
				 "the IKE library",
				 ssh_ikev2_payload_conf_render,
				 conf_payload));

      (*callback)(SSH_IKEV2_ERROR_OK, conf_payload, context);
      return NULL;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    }
  else
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      SshPmIkev2ConfQuery query;

      /* Check configuration mode for the responder. */
      if ((tunnel->flags & SSH_PM_TR_ALLOW_CFGMODE) == 0)
	{
	  SSH_DEBUG(SSH_D_LOWSTART, ("Ignoring Conf Request payload"));
	  (*callback)(SSH_IKEV2_ERROR_OK, NULL, context);
	  return NULL;
	}

      /* Only do SET/ACK if the compatibility flags indicate that the peer 
	 expects SET/ACK. If ed->conf is non-null the peer has sent a Conf 
	 payload request. */
      if (ed->conf == NULL
	  && (p1->compat_flags & SSH_PM_COMPAT_SET_ACK_CFG) == 0)
	{
	  SSH_DEBUG(SSH_D_LOWSTART, ("Ignoring Conf Request payload"));
	  (*callback)(SSH_IKEV2_ERROR_OK, NULL, context);
	  return NULL;
	}







      query = ssh_obstack_calloc(ed->obstack, sizeof(*query));
      if (query == NULL)
	{
	  (*callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, NULL, context);
	  return NULL;
	}

      query->p1 = p1;
      ssh_ikev2_exchange_data_take_ref(ed);
      query->ed = ed;
      query->p1->callbacks.aborted = FALSE;
      query->p1->callbacks.u.conf_cb = callback;
      query->p1->callbacks.callback_context = context;
      query->fsm_st_done = pm_ras_attrs_done;
      query->tunnel = tunnel;
      SSH_PM_TUNNEL_TAKE_REF(query->tunnel);

      ssh_operation_register_no_alloc(query->p1->callbacks.operation,
				      pm_ras_attrs_abort, query);

      ssh_fsm_thread_init(&pm->fsm, &query->thread,
			  pm_ras_attrs_alloc,
			  NULL_FNPTR,
			  pm_ras_attrs_thread_destructor,
			  query);

      ssh_fsm_set_thread_name(&query->p1->thread, "IKE RAS");
      return query->p1->callbacks.operation;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  (*callback)(SSH_IKEV2_ERROR_OK, NULL, context);
  return NULL;
}

#ifdef SSHDIST_IPSEC_MOBIKE
/*************************** Get Address Pair *******************************/












SshOperationHandle
ssh_pm_ike_get_address_pair(SshSADHandle sad_handle,
			    SshIkev2ExchangeData ed,
			    SshUInt32 address_index, 
			    SshIkev2PadGetAddressPairCB reply_callback,
			    void *reply_callback_context)
{
  SshIkev2Error status;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshIpAddrStruct remote_ip;
  SshIkev2Server server = NULL;  
  
  SSH_DEBUG(SSH_D_LOWSTART, ("Get address pair IKE SA %p index %d",
			     p1->ike_sa, (int) address_index));
  
  SSH_ASSERT(ed != NULL);
  SSH_ASSERT(reply_callback != NULL);  




  
  status = ssh_pm_mobike_get_address_pair(sad_handle->pm, p1, address_index,
					  &server, &remote_ip);
  if (status != SSH_IKEV2_ERROR_OK)
    goto error;
  
  SSH_DEBUG(SSH_D_MIDOK, ("Returning address pair %@ - %@",
			  ssh_ipaddr_render, server->ip_address,
			  ssh_ipaddr_render, &remote_ip));
  
  SSH_ASSERT(status == SSH_IKEV2_ERROR_OK);  
  (*reply_callback)(SSH_IKEV2_ERROR_OK, server, &remote_ip, 
		    reply_callback_context);
  
  return NULL;
  
  /* Error handling. */
 error:
  SSH_DEBUG(SSH_D_FAIL, ("Could not get address pair %d IKE SA %p: %s (%d)",
			 address_index, p1->ike_sa,
			 ssh_ikev2_error_to_string(status), (int) status));
  SSH_ASSERT(status != SSH_IKEV2_ERROR_OK);
  (*reply_callback)(status, NULL, NULL, reply_callback_context);
  return NULL;
}

SshOperationHandle
ssh_pm_ike_get_additional_address_list(SshSADHandle sad_handle,
				       SshIkev2ExchangeData ed,
				       SshIkev2PadGetAdditionalAddressListCB
				       reply_callback,
				       void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshPmTunnel tunnel;
  SshPmTunnelLocalIp local_ip;
  SshIpAddrStruct additional_addrs[SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES];
  SshUInt32 num_additional_addrs = 0;

  SSH_ASSERT(p1 != NULL);
  SSH_DEBUG(SSH_D_LOWSTART, 
	    ("Get additional address list IKE SA %p ED %p", p1, ed));





  /* Lookup tunnel. */
  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
		("Could not find tunnel for IKE SA %p, tunnel_id %d",
		 p1->ike_sa, p1->tunnel_id));
      goto error;      
    }

  for (local_ip = tunnel->local_ip;
       local_ip != NULL;
       local_ip = local_ip->next)
    {
      SSH_ASSERT(ssh_pm_mobike_valid_address(&local_ip->ip));

      /* Skip the currently used address. */
      if (!SSH_IP_CMP(p1->ike_sa->server->ip_address, &local_ip->ip))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Skipping currently used address %@",
                                  ssh_ipaddr_render, 
                                  p1->ike_sa->server->ip_address));
          continue;
        }

      if (num_additional_addrs >= SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES)
	{
	  SSH_DEBUG(SSH_D_FAIL, 
		    ("Maximum number of additional addresses reached"));
	  break;
	}

      /* Skip nonexisting statically configured local IPs. */
      if (local_ip->unavailable)
	{
	  SSH_DEBUG(SSH_D_MIDOK, ("Skipping unavailable local ip"));
	  continue;
	}
      
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Adding additional addresses %@",
				   ssh_ipaddr_render, &local_ip->ip));

      additional_addrs[num_additional_addrs++] = local_ip->ip;
    }
  SSH_ASSERT(num_additional_addrs <= SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES);
  
  SSH_DEBUG(SSH_D_MIDOK, ("Returning %d additional addresses", 
			  (int) num_additional_addrs));

  (*reply_callback)(SSH_IKEV2_ERROR_OK,
		    num_additional_addrs, additional_addrs, 
		    reply_callback_context);
  return NULL;

  /* Error handling. */
 error:
    (*reply_callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT,
		      0, NULL, reply_callback_context);
  return NULL;
}
#endif /* SSHDIST_IPSEC_MOBIKE */



