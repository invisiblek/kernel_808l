/*
 * spd_ike.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * IKE SPD policy calls.
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIke"












/*--------------------------------------------------------------------*/
/*       Static helper functions      	                 	      */
/*--------------------------------------------------------------------*/


/* Notify callback for ssh_ikev2_ike_sa_rekey(). */
void
pm_ike_sa_rekey_done_callback(SshSADHandle sad_handle,
			      SshIkev2Sa sa,
			      SshIkev2ExchangeData ed,
			      SshIkev2Error error)
{
  SshPmP1 old_p1 = (SshPmP1)sa;
  SshPmP1 new_p1;

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA rekey done, ike error code %s",
			  ssh_ikev2_error_to_string(error)));

  if (old_p1 != NULL)
    old_p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] = NULL;
  
  /* Update old rekeyed IKE SA since it state has changed to rekeyed. */
  ssh_pm_ike_sa_event_updated(sad_handle->pm, old_p1);
  
  /* Send any delayed delete notifications. */
  if (error == SSH_IKEV2_ERROR_OK)
    {
      /* Send notifications with the new initiated IKE SA. */
      new_p1 = PM_IKE_SA_REKEY_NEW_P1(old_p1, TRUE);
      if (new_p1 != NULL)
	ssh_pm_send_ipsec_delete_notification_requests(sad_handle->pm, new_p1);

      /* Send notifications with the new responded IKE SA. The responded new
	 IKE SA is non-NULL and has delayed delete notification requests only 
	 in the case we are the loser of a simultaneous IKE SA rekey. */
      new_p1 = PM_IKE_SA_REKEY_NEW_P1(old_p1, FALSE);
      if (new_p1 != NULL)
	ssh_pm_send_ipsec_delete_notification_requests(sad_handle->pm, new_p1);
    }
}

static SshIkev2Error
pm_build_ike_sa_from_p1(SshPm pm, SshPmP1 p1,
			SshIkev2PayloadSA *sa_payload_return)
{
  SshIkev2TransformID encr_transform_id, prf_transform_id, auth_transform_id;
  SshIkev2PayloadSA ike_sa_payload = NULL;
  SshIkev2Error ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
  SshUInt32 key_size;

  *sa_payload_return = NULL;

  if ((ike_sa_payload = ssh_ikev2_sa_allocate(pm->sad_handle)) == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  SSH_DEBUG(SSH_D_LOWSTART, ("IKE algorithms encrypt/prf/mac %s/%s/%s",
			     p1->ike_sa->encrypt_algorithm,
			     p1->ike_sa->prf_algorithm,
			     p1->ike_sa->mac_algorithm));

  encr_transform_id = ssh_find_keyword_number(ssh_ikev2_encr_algorithms,
					      p1->ike_sa->encrypt_algorithm);
  if (encr_transform_id == -1)
    goto error;
  key_size = (encr_transform_id >> 16);

  ike_error = ssh_ikev2_sa_add(ike_sa_payload,
			       0,
			       SSH_IKEV2_TRANSFORM_TYPE_ENCR,
			       (encr_transform_id & 0xffff),
			       SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));

  if (ike_error != SSH_IKEV2_ERROR_OK)
    goto error;

  prf_transform_id = ssh_find_keyword_number(ssh_ikev2_prf_algorithms,
					     p1->ike_sa->prf_algorithm);
  if (prf_transform_id == -1)
    goto error;
  key_size = (prf_transform_id >> 16);

  ike_error = ssh_ikev2_sa_add(ike_sa_payload,
			       0,
			       SSH_IKEV2_TRANSFORM_TYPE_PRF,
			       (prf_transform_id & 0xffff),
			       SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));

  if (ike_error != SSH_IKEV2_ERROR_OK)
    goto error;

  auth_transform_id = ssh_find_keyword_number(ssh_ikev2_mac_algorithms,
					      p1->ike_sa->mac_algorithm);
  if (auth_transform_id == -1)
    goto error;
  key_size = (auth_transform_id >> 16);

  ike_error = ssh_ikev2_sa_add(ike_sa_payload,
			       0,
			       SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			       (auth_transform_id & 0xffff),
			       SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));

  if (ike_error != SSH_IKEV2_ERROR_OK)
    goto error;

  ike_error = ssh_ikev2_sa_add(ike_sa_payload,
			       0,
			       SSH_IKEV2_TRANSFORM_TYPE_D_H,
			       p1->dh_group,
			       0);

  if (ike_error != SSH_IKEV2_ERROR_OK)
    goto error;

  ike_sa_payload->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_IKE;
  *sa_payload_return = ike_sa_payload;
  return SSH_IKEV2_ERROR_OK;

 error:
  SSH_ASSERT(ike_error != SSH_IKEV2_ERROR_OK);
  ssh_ikev2_sa_free(pm->sad_handle, ike_sa_payload);
  return ike_error;
}

SshIkev2Error
ssh_pm_build_ike_sa_from_tunnel(SshPm pm, SshPmTunnel tunnel,
				SshIkev2PayloadSA *sa_payload_return)
{
  SshIkev2PayloadSA ike_sa_payload = NULL;
  SshUInt32 num_ciphers, num_hashes, num_dh_groups, i;
  SshUInt32 min_key_size, max_key_size, default_key_size;
  SshUInt32 key_size_increment, key_size;
  Boolean fixed_length;
  SshIkev2Error ike_error = 0;

  *sa_payload_return = NULL;

  if ((ike_sa_payload = ssh_ikev2_sa_allocate(pm->sad_handle)) == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  /* Count how many transforms we need. */
  (void) ssh_pm_ike_num_algorithms(pm,
                                   tunnel->u.ike.algorithms,
                                   tunnel->u.ike.ike_groups,
                                   &num_ciphers, &num_hashes, &num_dh_groups);

  SSH_ASSERT(num_ciphers * num_hashes * num_dh_groups > 0);

  /* Create cipher transforms. */
  for (i = 0; i < num_ciphers; i++)
    {
      SshPmCipher cipher;

      cipher = ssh_pm_ike_cipher(pm, i, tunnel->u.ike.algorithms);
      SSH_ASSERT(cipher != NULL);

      /* Resolve the key size to propose with this cipher for our
         tunnel. */
      ssh_pm_cipher_key_sizes(tunnel, cipher, SSH_PM_ALG_IKE_SA,
			      &min_key_size, &max_key_size,
			      &key_size_increment, &default_key_size);

      fixed_length = ssh_pm_cipher_is_fixed_key_length(cipher);

      if (fixed_length)
	{
	  ike_error = ssh_ikev2_sa_add(ike_sa_payload,
				       0,
				       SSH_IKEV2_TRANSFORM_TYPE_ENCR,
				       cipher->ike_encr_transform_id,
				       0);
	}
      else
	{
	  SSH_ASSERT(key_size_increment > 0);
	  SSH_ASSERT((max_key_size - min_key_size) % key_size_increment == 0);

	  /* Add the default key size first, this is our preferred
	     key size.*/
	  SSH_DEBUG(SSH_D_MIDOK,
		    ("Adding keysize %d to proposal",
		     (int) default_key_size));
	  ike_error +=
	    ssh_ikev2_sa_add(
			 ike_sa_payload,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_ENCR,
			 cipher->ike_encr_transform_id,
			 SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(default_key_size));

	  for (key_size = min_key_size;
	       key_size <= max_key_size;
	       key_size += key_size_increment)
	    {
	      if (key_size == default_key_size)
		continue;

	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) key_size));
	      ike_error +=
		ssh_ikev2_sa_add(ike_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_ENCR,
				 cipher->ike_encr_transform_id,
				 SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
	    }
	}

      if (ike_error != SSH_IKEV2_ERROR_OK)
	{
	  ssh_ikev2_sa_free(pm->sad_handle, ike_sa_payload);
	  return ike_error;
	}
    }

  /* Create mac transforms. */
  for (i = 0; i < num_hashes; i++)
    {
      SshPmMac mac;

      mac = ssh_pm_ike_mac(pm, i, tunnel->u.ike.algorithms);
      SSH_ASSERT(mac != NULL);

      /* Resolve the key size to propose with this mac for our
         tunnel. */
      ssh_pm_mac_key_sizes(tunnel, mac, SSH_PM_ALG_IKE_SA,
			   &min_key_size, &max_key_size,
			   &key_size_increment, &default_key_size);

      fixed_length = ssh_pm_mac_is_fixed_key_length(mac);

      if (fixed_length)
	{
	  SSH_ASSERT(mac->ike_prf_transform_id != 0);

	  ike_error = ssh_ikev2_sa_add(ike_sa_payload,
				       0,
				       SSH_IKEV2_TRANSFORM_TYPE_PRF,
				       mac->ike_prf_transform_id,
				       0);
	}
      else if (mac->ike_prf_transform_id == 0)
	{
	  /* There are separate IDs for different
	     keysizes. Let's follow keysizes to gather
	     the IDs. */
	  SshIkev2TransformID prf_id;

	  SSH_ASSERT(key_size_increment > 0);
	  SSH_ASSERT((max_key_size - min_key_size)
		     % key_size_increment == 0);

	  /* Add the default key size first, this is our preferred
	     key size.*/
	  SSH_DEBUG(SSH_D_MIDOK,
		    ("Adding keysize %d to proposal",
		     (int) default_key_size));

	  prf_id = ssh_pm_mac_ike_prf_id_for_keysize(mac,
						     default_key_size);
	  SSH_ASSERT(prf_id != 0);
	  
	  ike_error +=
	    ssh_ikev2_sa_add(ike_sa_payload,
			     0,
			     SSH_IKEV2_TRANSFORM_TYPE_PRF,
			     prf_id,
			     0);

	  for (key_size = min_key_size;
	       key_size <= max_key_size;
	       key_size += key_size_increment)
	    {
	      if (key_size == default_key_size)
		continue;
	      
	      prf_id = ssh_pm_mac_ike_prf_id_for_keysize(mac,
							 key_size);
	      SSH_ASSERT(prf_id != 0);
	      
	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) key_size));

	      ike_error +=
		ssh_ikev2_sa_add(ike_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_PRF,
				 prf_id, 
                                 0);
	    }
	}
      else
	{
	  SSH_ASSERT(key_size_increment > 0);
	  SSH_ASSERT((max_key_size - min_key_size) % key_size_increment == 0);

	  /* Add the default key size first, this is our preferred
	     key size.*/
	  SSH_DEBUG(SSH_D_MIDOK,
		    ("Adding keysize %d to proposal",
		     (int) default_key_size));
	  ike_error +=
	    ssh_ikev2_sa_add(
			  ike_sa_payload,
			  0,
			  SSH_IKEV2_TRANSFORM_TYPE_PRF,
			  mac->ike_prf_transform_id,
			  SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(default_key_size));

	  for (key_size = min_key_size;
	       key_size <= max_key_size;
	       key_size += key_size_increment)
	    {
	      if (key_size == default_key_size)
		continue;

	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) key_size));
	      ike_error +=
		ssh_ikev2_sa_add(ike_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_PRF,
				 mac->ike_prf_transform_id,
				 SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
	    }
	}

      if (ike_error != SSH_IKEV2_ERROR_OK)
	{
	  ssh_ikev2_sa_free(pm->sad_handle, ike_sa_payload);
	  return ike_error;
	}

      if (fixed_length)
	{
	  SSH_ASSERT(mac->ike_auth_transform_id != 0);

	  ike_error = ssh_ikev2_sa_add(ike_sa_payload,
				       0,
				       SSH_IKEV2_TRANSFORM_TYPE_INTEG,
				       mac->ike_auth_transform_id,
				       0);
	}
      else if (mac->ike_auth_transform_id == 0)
	{
	  /* There are separate IDs for different
	     keysizes. Let's follow keysizes to gather
	     the IDs. */
	  SshIkev2TransformID ike_auth_id;
	  
	  SSH_ASSERT(key_size_increment > 0);
	  SSH_ASSERT((max_key_size - min_key_size)
		     % key_size_increment == 0);

	  /* Add the default key size first, this is our preferred
	     key size.*/
	  SSH_DEBUG(SSH_D_MIDOK,
		    ("Adding keysize %d to proposal",
		     (int) default_key_size));

	  ike_auth_id = ssh_pm_mac_ike_auth_id_for_keysize(mac,
							   default_key_size);
	  SSH_ASSERT(ike_auth_id != 0);
	  
	  ike_error +=
	    ssh_ikev2_sa_add(ike_sa_payload,
			     0,
			     SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			     ike_auth_id,
			     0);

	  for (key_size = min_key_size;
	       key_size <= max_key_size;
	       key_size += key_size_increment)
	    {
	      if (key_size == default_key_size)
		continue;
	      
	      ike_auth_id = ssh_pm_mac_ike_auth_id_for_keysize(mac,
							       key_size);
	      SSH_ASSERT(ike_auth_id != 0);
	      
	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) key_size));

	      ike_error +=
		ssh_ikev2_sa_add(ike_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
				 ike_auth_id, 
                                 0);
	    }
	}
      else
	{
	  SSH_ASSERT(key_size_increment > 0);
	  SSH_ASSERT((max_key_size - min_key_size) % key_size_increment == 0);

	  /* Add the default key size first, this is our preferred
	     key size.*/
	  SSH_DEBUG(SSH_D_MIDOK,
		    ("Adding keysize %d to proposal",
		     (int) default_key_size));
	  ike_error +=
	    ssh_ikev2_sa_add(
			  ike_sa_payload,
			  0,
			  SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			  mac->ike_auth_transform_id,
			  SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(default_key_size));

	  for (key_size = min_key_size;
	       key_size <= max_key_size;
	       key_size += key_size_increment)
	    {
	      if (key_size == default_key_size)
		continue;

	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) key_size));
	      ike_error +=
		ssh_ikev2_sa_add(ike_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
				 mac->ike_auth_transform_id,
				 SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
	    }
	}

      if (ike_error != SSH_IKEV2_ERROR_OK)
	{
	  ssh_ikev2_sa_free(pm->sad_handle, ike_sa_payload);
	  return ike_error;
	}
    }

  for (i = 0; i < num_dh_groups; i++)
    {
      SshPmDHGroup dhgroup;

      dhgroup = ssh_pm_tunnel_dh_group(tunnel, i, FALSE);

      SSH_ASSERT(dhgroup != NULL);

      /* Do not allow group 0 at initial exchange */
      if (dhgroup->group_desc == 0)
	continue;

      ike_error = ssh_ikev2_sa_add(ike_sa_payload,
				   0,
				   SSH_IKEV2_TRANSFORM_TYPE_D_H,
				   dhgroup->group_desc,
				   0);

      if (ike_error != SSH_IKEV2_ERROR_OK)
	{
	  ssh_ikev2_sa_free(pm->sad_handle, ike_sa_payload);
	  return ike_error;
	}
    }

  ike_sa_payload->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_IKE;

  *sa_payload_return = ike_sa_payload;
  return SSH_IKEV2_ERROR_OK;
}

static SshIkev2Error
pm_build_ipsec_sa_from_tunnel(SshPm pm, SshPmQm qm, SshPmTunnel tunnel,
			      SshIkev2PayloadSA *sa_payload_return)
{
  SshIkev2PayloadSA ipsec_sa_payload = NULL;
  SshUInt32 i, num_ciphers, num_macs, num_dh_groups;
  SshUInt32 min_key_size, max_key_size, default_key_size;
  SshUInt32 key_size_increment, key_size;
  Boolean fixed_length;
  SshIkev2Error ike_error = 0;

  *sa_payload_return = NULL;

  if ((ipsec_sa_payload = ssh_ikev2_sa_allocate(pm->sad_handle)) == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  SSH_PM_ASSERT_QM(qm);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Check if policy allows NAT's. */
  if ((tunnel->flags & SSH_PM_T_NO_NATS_ALLOWED) &&
      (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT ||
       qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
    {
      ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
			  qm, "error");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
		    "  Message: negotiation aborted");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
		    "  Reason: Policy does not allow NAT's");
      
      ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);

#ifdef SSHDIST_IPSEC_MOBIKE
      if (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
	return SSH_IKEV2_ERROR_UNEXPECTED_NAT_DETECTED;
      else
#endif /* SSHDIST_IPSEC_MOBIKE */
	return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Count how many algorithms we have. */
  (void) ssh_pm_ipsec_num_algorithms(pm,
				     qm->transform,
				     tunnel->u.ike.pfs_groups,
				     &num_ciphers, &num_macs, NULL,
				     &num_dh_groups);

  if (qm->transform & SSH_PM_IPSEC_ESP)
    {
      SSH_ASSERT(num_ciphers != 0);

      /* Create cipher transforms. */
      for (i = 0; i < num_ciphers; i++)
	{
	  SshPmCipher cipher;

	  cipher = ssh_pm_ipsec_cipher(pm, i, qm->transform);
	  SSH_ASSERT(cipher != NULL);

	  ssh_pm_cipher_key_sizes(tunnel, cipher, SSH_PM_ALG_IPSEC_SA,
				  &min_key_size, &max_key_size,
				  &key_size_increment, &default_key_size);

	  fixed_length = ssh_pm_cipher_is_fixed_key_length(cipher);

	  if (fixed_length)
	    {
	      ike_error = ssh_ikev2_sa_add(ipsec_sa_payload,
					   0,
					   SSH_IKEV2_TRANSFORM_TYPE_ENCR,
					   cipher->esp_transform_id,
					   0);
	    }
	  else
	    {
	      SSH_ASSERT(key_size_increment > 0);
	      SSH_ASSERT((max_key_size - min_key_size) %
			 key_size_increment == 0);

	      /* Add the default key size first, this is our preferred
		 key size.*/
	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) default_key_size));

	      ike_error +=
		ssh_ikev2_sa_add(
			    ipsec_sa_payload,
			    0,
			    SSH_IKEV2_TRANSFORM_TYPE_ENCR,
			    cipher->esp_transform_id,
			    SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(default_key_size));


	      for (key_size = min_key_size;
		   key_size <= max_key_size;
		   key_size += key_size_increment)
		{
		  if (key_size == default_key_size)
		    continue;

		  SSH_DEBUG(SSH_D_MIDOK,
			    ("Adding keysize %d to proposal",
                             (int) key_size));

		  ike_error +=
		    ssh_ikev2_sa_add(
				 ipsec_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_ENCR,
				 cipher->esp_transform_id,
				 SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
		}
	    }

	  if (ike_error != SSH_IKEV2_ERROR_OK)
	    {
	      ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);
	      return ike_error;
	    }
	}

      /* Create mac transforms. */
      for (i = 0; i < num_macs; i++)
	{
	  SshPmMac mac = NULL;
	  mac = ssh_pm_ipsec_mac(pm, i, qm->transform);
	  SSH_ASSERT(mac != NULL);

	  ssh_pm_mac_key_sizes(tunnel, mac, SSH_PM_ALG_IPSEC_SA,
			       &min_key_size, &max_key_size,
			       &key_size_increment, &default_key_size);

	  fixed_length = ssh_pm_mac_is_fixed_key_length(mac);

	  if (fixed_length)
	    {
	      ike_error = ssh_ikev2_sa_add(ipsec_sa_payload,
					   0,
					   SSH_IKEV2_TRANSFORM_TYPE_INTEG,
					   mac->ah_transform_id,
					   0);
	    }
          else if (mac->ah_transform_id == 0)
	    {
	      /* There are separate IDs for different
                 keysizes. Let's follow keysizes to gather
                 the IDs. */
              SshIkev2TransformID auth_id;

	      SSH_ASSERT(key_size_increment > 0);
	      SSH_ASSERT((max_key_size - min_key_size)
			 % key_size_increment == 0);

	      /* Add the default key size first, this is our preferred
		 key size.*/
	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) default_key_size));

              auth_id = ssh_pm_mac_auth_id_for_keysize(mac,
                                                       default_key_size);
              SSH_ASSERT(auth_id != 0);

	      ike_error +=
		ssh_ikev2_sa_add(
			   ipsec_sa_payload,
			   0,
			   SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                           auth_id,
                           0);

	      for (key_size = min_key_size;
		   key_size <= max_key_size;
		   key_size += key_size_increment)
		{
		  if (key_size == default_key_size)
		    continue;

                  auth_id = ssh_pm_mac_auth_id_for_keysize(mac,
                                                           key_size);
                  SSH_ASSERT(auth_id != 0);

		  SSH_DEBUG(SSH_D_MIDOK,
			    ("Adding keysize %d to proposal",
			     (int) key_size));

		  ike_error +=
		    ssh_ikev2_sa_add(
				 ipsec_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
				 auth_id, 
                                 0);
		}
	    }
	  else
	    {
	      SSH_ASSERT(key_size_increment > 0);
	      SSH_ASSERT((max_key_size - min_key_size)
			 % key_size_increment == 0);

	      /* Add the default key size first, this is our preferred
		 key size.*/
	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) default_key_size));

	      ike_error +=
		ssh_ikev2_sa_add(
			   ipsec_sa_payload,
			   0,
			   SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			   mac->ike_auth_transform_id,
			   SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(default_key_size));

	      for (key_size = min_key_size;
		   key_size <= max_key_size;
		   key_size += key_size_increment)
		{
		  if (key_size == default_key_size)
		    continue;

		  SSH_DEBUG(SSH_D_MIDOK,
			    ("Adding keysize %d to proposal",
			     (int) key_size));

		  ike_error +=
		    ssh_ikev2_sa_add(
				 ipsec_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
				 mac->ike_auth_transform_id,
				 SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
		}
	    }

	  if (ike_error != SSH_IKEV2_ERROR_OK)
	    {
	      ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);
	      return ike_error;
	    }

	}
    }
  else if (qm->transform & SSH_PM_IPSEC_AH)
    {
      SSH_ASSERT(num_macs > 0);

      /* Create mac transforms. */
      for (i = 0; i < num_macs; i++)
	{
	  SshPmMac mac = NULL;

	  mac = ssh_pm_ipsec_mac(pm, i, qm->transform);
	  SSH_ASSERT(mac != NULL);

	  ssh_pm_mac_key_sizes(tunnel, mac, SSH_PM_ALG_IPSEC_SA,
			       &min_key_size, 
			       &max_key_size, 
			       &key_size_increment, 
			       &default_key_size);

	  fixed_length = ssh_pm_mac_is_fixed_key_length(mac);

	  if (fixed_length)
	    {
	      ike_error =
		ssh_ikev2_sa_add(
			   ipsec_sa_payload,
			   0,
			   SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			   mac->ah_transform_id,
			   fixed_length ? 0 :
			   SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(default_key_size));
	    }
          else if (mac->ah_transform_id == 0)
	    {
	      /* There are separate IDs for different
                 keysizes. Let's follow keysizes to gather
                 the IDs. */
              SshIkev2TransformID auth_id;

	      SSH_ASSERT(key_size_increment > 0);
	      SSH_ASSERT((max_key_size - min_key_size)
			 % key_size_increment == 0);

	      /* Add the default key size first, this is our preferred
		 key size.*/
	      SSH_DEBUG(SSH_D_MIDOK,
			("Adding keysize %d to proposal",
			 (int) default_key_size));

              auth_id = ssh_pm_mac_auth_id_for_keysize(mac,
                                                       default_key_size);
              SSH_ASSERT(auth_id != 0);

	      ike_error +=
		ssh_ikev2_sa_add(
			   ipsec_sa_payload,
			   0,
			   SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                           auth_id,
                           0);

	      for (key_size = min_key_size;
		   key_size <= max_key_size;
		   key_size += key_size_increment)
		{
		  if (key_size == default_key_size)
		    continue;

                  auth_id = ssh_pm_mac_auth_id_for_keysize(mac,
                                                           key_size);
                  SSH_ASSERT(auth_id != 0);

		  SSH_DEBUG(SSH_D_MIDOK,
			    ("Adding keysize %d to proposal",
			     (int) key_size));

		  ike_error +=
		    ssh_ikev2_sa_add(
				 ipsec_sa_payload,
				 0,
				 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
				 auth_id, 
                                 0);
		}
	    }

	  if (ike_error != SSH_IKEV2_ERROR_OK)
	    {
	      ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);
	      return ike_error;
	    }
	}
    }

  /* Check for PFS group. However do not try to do Diffie-Hellman when
     creating SA's as part of the IKE exchange since the Diffie-Hellman
     was already performed at the IKE SA init stage. */
  if ((qm->ed->state != SSH_IKEV2_STATE_IKE_AUTH_1ST) &&
      (qm->ed->state != SSH_IKEV2_STATE_IKE_AUTH_LAST))
    {
      SshPmDHGroup dhgroup;

      for (i = 0; i < num_dh_groups; i++)
	{
	  /* Request using the first matching group. */
	  dhgroup = ssh_pm_tunnel_dh_group(tunnel, i, TRUE);
	  SSH_ASSERT(dhgroup != NULL);

	  ike_error = ssh_ikev2_sa_add(ipsec_sa_payload,
				       0,
				       SSH_IKEV2_TRANSFORM_TYPE_D_H,
				       dhgroup->group_desc,
				       0);

	  if (ike_error != SSH_IKEV2_ERROR_OK)
	    {
	      ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);
	      return ike_error;
	    }
	  SSH_DEBUG(SSH_D_HIGHOK, ("pfsgroup=%d", dhgroup->group_desc));
	}
    }

  /* Add ESN options. As default option we add both ESN and NO_ESN,
     but if tunnel sets only SSH_PM_IPSEC_SHORTSEQ or SSH_PM_IPSEC_LONGSEQ,
     we use only the specified option. Setting both flags equals setting
     neither. */
  if ((tunnel->transform & SSH_PM_IPSEC_SHORTSEQ) ||
      !(tunnel->transform & SSH_PM_IPSEC_LONGSEQ))

    {
      ike_error = ssh_ikev2_sa_add(ipsec_sa_payload,
				   0,
				   SSH_IKEV2_TRANSFORM_TYPE_ESN,
				   SSH_IKEV2_TRANSFORM_ESN_NO_ESN,
				   0);

      if (ike_error != SSH_IKEV2_ERROR_OK)
	{
	  ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);
	  return ike_error;
	}
    }

  if ((tunnel->transform & SSH_PM_IPSEC_LONGSEQ) ||
      !(tunnel->transform & SSH_PM_IPSEC_SHORTSEQ))
    {
      
      ike_error = ssh_ikev2_sa_add(ipsec_sa_payload,
                                   0,
                                   SSH_IKEV2_TRANSFORM_TYPE_ESN,
                                   SSH_IKEV2_TRANSFORM_ESN_ESN,
                                   0);
      
      if (ike_error != SSH_IKEV2_ERROR_OK)
        {
          ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);
          return ike_error;
        }
    }

  ipsec_sa_payload->protocol_id[0] = (qm->transform & SSH_PM_IPSEC_ESP)
    ? SSH_IKEV2_PROTOCOL_ID_ESP
    : ((qm->transform & SSH_PM_IPSEC_AH)
       ? SSH_IKEV2_PROTOCOL_ID_AH
       : SSH_IKEV2_PROTOCOL_ID_NONE);

  *sa_payload_return = ipsec_sa_payload;
  return SSH_IKEV2_ERROR_OK;
}

/*--------------------------------------------------------------------*/
/*       IKE SPD policy calls      	                 	      */
/*--------------------------------------------------------------------*/


/* ******************** Fill proposals for IKE SA ***************************/

SshOperationHandle
ssh_pm_ike_spd_fill_ike_sa(SshSADHandle sad_handle,
			   SshIkev2ExchangeData ed,
			   SshIkev2SpdFillSACB reply_callback,
			   void *reply_callback_context)
{
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshPm pm = sad_handle->pm;
  SshIkev2PayloadSA ike_sa_payload = NULL;
  SshPmTunnel tunnel;
  SshIkev2Error ike_error;

  SSH_PM_ASSERT_P1(p1);

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, NULL,
                        reply_callback_context);
      return NULL;
    }

  ike_error = SSH_IKEV2_ERROR_OK;

  if (ed->state == SSH_IKEV2_STATE_REKEY_IKE)
    {
      /* Verify that we have a completed Phase-I IKE SA */
      if (!SSH_PM_P1_READY(p1))
	{
	  (*reply_callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT, NULL,
			    reply_callback_context);
	  return NULL;
	}

      /* Construct the SA Payload from the IKE SA. */
      ike_error = pm_build_ike_sa_from_p1(pm, p1, &ike_sa_payload);
    }
  else
    {
      SSH_PM_ASSERT_P1N(p1);
      SSH_ASSERT(p1->done == 0);

      if (!SSH_PM_P1_USABLE(p1) || !p1->n || !p1->n->tunnel)
	goto error;

      tunnel = p1->n->tunnel;
      SSH_ASSERT(tunnel != NULL);

      SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

      ike_error = ssh_pm_build_ike_sa_from_tunnel(pm, tunnel, &ike_sa_payload);
    }

#ifdef DEBUG_LIGHT
  if (ike_error == SSH_IKEV2_ERROR_OK && ike_sa_payload != NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Initiator's proposing IKE SA payload %@",
			      ssh_ikev2_payload_sa_render, ike_sa_payload));
    }
#endif /* DEBUG_LIGHT */

  (*reply_callback)(ike_error, ike_sa_payload, reply_callback_context);
  return NULL;

 error:
  (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, NULL, reply_callback_context);
  return NULL;
}


/* *********************** Select an IKE SA proposal. ***********************/

typedef struct SshPmSpdSelectIkeSaContextRec
{
  SshOperationHandleStruct op[1];
  SshFSMThreadStruct thread[1];
  SshUInt8 aborted : 1;
  SshSADHandle sad_handle;
  SshIkev2ExchangeData ed;
  SshIkev2PayloadSA sa_in;
  SshIkev2SpdSelectSACB reply_callback;
  void *reply_callback_context;
} *SshPmSpdSelectIkeSaContext;

static void
pm_ike_spd_select_ike_sa_thread_destructor(SshFSM fsm, void *context)
{
  SshPmSpdSelectIkeSaContext ctx = context;
  
  SSH_ASSERT(ctx != NULL);  
  
  SSH_DEBUG(SSH_D_LOWSTART, ("Select IKE SA thread destructor."));

  /* Free sa reference. */
  ssh_ikev2_sa_free(ctx->sad_handle, ctx->sa_in);      
  
  if (!ctx->aborted)
    ssh_operation_unregister(ctx->op);

  /* Free ed reference. 
     This might free the obstack this ctx was allocated from. */
  ssh_ikev2_exchange_data_free(ctx->ed);      
}

static void
pm_ike_spd_select_ike_sa_abort(void *context)
{
  SshPmSpdSelectIkeSaContext ctx = context;
  SSH_DEBUG(SSH_D_LOWOK, ("Select IKE SA operation aborted"));
  ctx->aborted = 1;
}

SSH_FSM_STEP(ssh_pm_st_ike_spd_select_ike_sa_start)
{
#ifdef SSH_IPSEC_TCPENCAP
  SshPmSpdSelectIkeSaContext ctx = thread_context;
  SshPmP1 p1 = (SshPmP1) ctx->ed->ike_sa;
#endif /* SSH_IPSEC_TCPENCAP */

  SSH_DEBUG(SSH_D_LOWSTART, ("Select IKE SA thread starts."));

#ifdef SSH_IPSEC_TCPENCAP
  /* Fetch the TCP encapsulation mapping from engine. */
  if (p1->compat_flags & SSH_PM_COMPAT_TCPENCAP)
    SSH_FSM_SET_NEXT(ssh_pm_st_ike_spd_select_ike_sa_get_ike_mapping);
  else
#endif /* SSH_IPSEC_TCPENCAP */
    SSH_FSM_SET_NEXT(ssh_pm_st_ike_spd_select_ike_sa);

  return SSH_FSM_CONTINUE;
}

#ifdef SSH_IPSEC_TCPENCAP
static void
pm_ike_spd_select_ike_sa_get_ike_mapping_cb(SshPm pm, SshUInt32 conn_id, 
					    void *context)
{
  SshPmSpdSelectIkeSaContext ctx = context;
  SshPmP1 p1 = (SshPmP1) ctx->ed->ike_sa;
  
  if (conn_id != SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_LOWOK,
		("IKE SA %p is using encapsulating TCP connection 0x%lx",
		 p1->ike_sa, (unsigned long) conn_id));
      p1->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
		("IKE SA %p is not using TCP encapsulation", p1->ike_sa));
      p1->ike_sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
}

SSH_FSM_STEP(ssh_pm_st_ike_spd_select_ike_sa_get_ike_mapping)
{
  SshPmSpdSelectIkeSaContext ctx = thread_context;
  SshPmP1 p1 = (SshPmP1) ctx->ed->ike_sa;

  SSH_DEBUG(SSH_D_LOWOK, ("Getting encapsulating TCP connection for IKE SA %p",
			  p1->ike_sa));

  SSH_FSM_SET_NEXT(ssh_pm_st_ike_spd_select_ike_sa);
  SSH_FSM_ASYNC_CALL({
    /* Fetch encapsulating TCP connection ID from the engine. */
    ssh_pme_tcp_encaps_get_ike_mapping(ctx->sad_handle->pm->engine,
			           p1->ike_sa->server->ip_address,
			           p1->ike_sa->remote_ip,
			           p1->ike_sa->ike_spi_i,
				   pm_ike_spd_select_ike_sa_get_ike_mapping_cb,
				   ctx);
  });
  SSH_NOTREACHED;
}
#endif /* SSH_IPSEC_TCPENCAP */

SSH_FSM_STEP(ssh_pm_st_ike_spd_select_ike_sa)
{
  SshPmSpdSelectIkeSaContext ctx = thread_context;
  SshSADHandle sad_handle = ctx->sad_handle;
  SshIkev2ExchangeData ed = ctx->ed;
  SshIkev2PayloadSA sa_in = ctx->sa_in;
  SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshIpAddr local, remote;
  SshIkev2PayloadSA sa_policy;
  SshPmP1 p1 = (SshPmP1) ctx->ed->ike_sa;
  SshPm pm = sad_handle->pm;
  SshPmTunnel tunnel = NULL;
  SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
  int proposal_index;
  Boolean ikev1 = FALSE;
  SshPmQm qm;
  
  PM_SUSPEND_CONDITION_WAIT(pm, thread);

  SSH_DEBUG(SSH_D_MIDOK, ("Enter SA %p ED %p", ed->ike_sa, ed));
  SSH_PM_ASSERT_P1(p1);
  
  if (ctx->aborted)
    return SSH_FSM_FINISH;

  if (ed->state == SSH_IKEV2_STATE_REKEY_IKE)
    {













      if (!p1->done)
	{
	  (*ctx->reply_callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT, 0, NULL,
				 ctx->reply_callback_context);
	  return SSH_FSM_FINISH;
	}

      /* Construct the SA Payload from the IKE SA. */
      ike_error = pm_build_ike_sa_from_p1(pm, p1, &sa_policy);
    }
  else
    {
      SSH_PM_ASSERT_P1N(p1);
      SSH_ASSERT(!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR));
      SSH_ASSERT(p1->n->tunnel == NULL);

      qm = (SshPmQm) ed->application_context;
      if (qm)
	SSH_PM_ASSERT_QM(qm);

      /* Parse the notify payloads received from the Initiator's first
	 packet. */
      ssh_pm_ike_parse_notify_payloads(ed, qm);

      /* Search for a tunnel that matches the local and remote IP addresses of
	 the IKE endpoints. */
      local = ed->ike_sa->server->ip_address;
      remote = ed->ike_sa->remote_ip;

      SSH_DEBUG(SSH_D_HIGHOK, ("Search for a tunnel matching the IKE peers, "
			       "local:%@, remote:%@",
			       ssh_ipaddr_render, local,
			       ssh_ipaddr_render, remote));
#ifdef SSHDIST_IKEV1
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	ikev1 = TRUE;
#endif /* SSHDIST_IKEV1 */
      tunnel = ssh_pm_tunnel_lookup(pm, ikev1, local, remote, sa_in,
				    &p1->n->failure_mask,
				    &p1->n->ike_failure_mask);
      if (!tunnel)
	{
	  SshIkev2Error error_code = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;

	  /* If this is an IKEv2 negotiation and tunnel selection failed,
	     but there was an acceptable tunnel which uses IKEv1 then
	     return the error status to try IKEv1 instead. */
	  if (!ikev1 &&
	      (p1->n->failure_mask &  SSH_PM_E_IKE_VERSION_MISMATCH))
	    error_code = SSH_IKEV2_ERROR_USE_IKEV1;

	  SSH_DEBUG(SSH_D_FAIL, ("No suitable tunnel found for this IKE "
				 "negotiation"));

	  (*ctx->reply_callback)(error_code, 0, NULL, 
				 ctx->reply_callback_context);
	  return SSH_FSM_FINISH;
	}

      SSH_DEBUG(SSH_D_LOWOK, ("Found a tunnel (%s)", tunnel->tunnel_name));

      /* Success. */
      SSH_ASSERT(tunnel != NULL);

      /* Store the tunnel. */
      p1->tunnel_id = tunnel->tunnel_id;
      p1->n->tunnel = tunnel;
      SSH_PM_TUNNEL_TAKE_REF(p1->n->tunnel);

      /* Store tunnel flags. */
      if (tunnel->flags & SSH_PM_T_DISABLE_NATT)
	p1->ike_sa->flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T;
      
      /* Use the tunnel to select the transforms appropiate to our tunnel's
	 policy. */
      ike_error = ssh_pm_build_ike_sa_from_tunnel(pm, tunnel, &sa_policy);
    }

  if (ike_error != SSH_IKEV2_ERROR_OK)
    {
      (*ctx->reply_callback)(ike_error, 0, NULL, ctx->reply_callback_context);
      return SSH_FSM_FINISH;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Responder's tunnel IKE SA payload is %@",
			  ssh_ikev2_payload_sa_render, sa_policy));
  SSH_DEBUG(SSH_D_MIDOK, ("Initiator's proposed IKE SA payload is %@",
			  ssh_ikev2_payload_sa_render, sa_in));

#ifdef SSHDIST_IKEV1
  /* Use the tunnel to set our local lifetimes to the IKE exchange data
     where it is visible to the IKEv1 fallback code. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      SSH_ASSERT(tunnel != NULL);
      ed->ike_ed->sa_life_seconds = tunnel->u.ike.ike_sa_life_seconds;

      SSH_DEBUG(SSH_D_MIDOK, ("Set IKE SA Policy lifetimes sec=%d"
			      "to the exchange data",
			      (int) ed->ike_ed->sa_life_seconds));
    }
#endif /* SSHDIST_IKEV1 */

  if (ssh_ikev2_sa_select(sa_in, sa_policy, &proposal_index,
			  selected_transforms,
			  NULL))
    {
      ssh_ikev2_sa_free(pm->sad_handle, sa_policy);

      /* Check the proposal index is as expected. */
      if (sa_in->protocol_id[proposal_index] != SSH_IKEV2_PROTOCOL_ID_IKE)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Unexpected proposal index, failing IKE SA "
				 "selection."));

	  (*ctx->reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
				 0, NULL, ctx->reply_callback_context);
	  return SSH_FSM_FINISH;
	}

      /* Success. */
      (*ctx->reply_callback)(SSH_IKEV2_ERROR_OK,
			     proposal_index, selected_transforms,
			     ctx->reply_callback_context);
      return SSH_FSM_FINISH;
    }
  else
    {
      ssh_ikev2_sa_free(pm->sad_handle, sa_policy);

      (*ctx->reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
			     0, NULL, ctx->reply_callback_context);

      return SSH_FSM_FINISH;
    }
  SSH_NOTREACHED;
  return SSH_FSM_FINISH;
}


SshOperationHandle
ssh_pm_ike_spd_select_ike_sa(SshSADHandle sad_handle,
			     SshIkev2ExchangeData ed,
			     SshIkev2PayloadSA sa_in,
			     SshIkev2SpdSelectSACB reply_callback,
			     void *reply_callback_context)
{
  SshPmSpdSelectIkeSaContext ctx;
  
  SSH_DEBUG(SSH_D_MIDOK, ("Enter SA %p ED %p", ed->ike_sa, ed));
  
  SSH_ASSERT(ed != NULL);
  SSH_PM_ASSERT_P1(((SshPmP1) ed->ike_sa));
  
  if (ssh_pm_get_status(sad_handle->pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, 0, NULL, 
			reply_callback_context);
      return NULL;
    }

  if (!SSH_PM_P1_USABLE((SshPmP1)ed->ike_sa))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, 0, NULL, 
			reply_callback_context);
      return NULL;
    }
  
  /* Alloc operation context. */
  ctx = ssh_obstack_calloc(ed->obstack, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, 0, NULL, 
			reply_callback_context);
      return NULL;
    }
      
  ctx->sad_handle = sad_handle;
  ssh_ikev2_exchange_data_take_ref(ed);
  ctx->ed = ed;
  ssh_ikev2_sa_take_ref(sad_handle, sa_in);
  ctx->sa_in = sa_in;
  ctx->reply_callback = reply_callback;
  ctx->reply_callback_context = reply_callback_context;
  
  ssh_fsm_thread_init(&sad_handle->pm->fsm, ctx->thread,
		      ssh_pm_st_ike_spd_select_ike_sa_start, NULL,
		      pm_ike_spd_select_ike_sa_thread_destructor, ctx);
  ssh_fsm_set_thread_name(ctx->thread, "Select IKE SA");
  
  ssh_operation_register_no_alloc(ctx->op,
				  pm_ike_spd_select_ike_sa_abort, ctx);
  
  return ctx->op;
}


/* ************************* Fill proposals for IPSEC SA  *******************/
#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_ISAKMP_CFG_MODE
static SshIpAddr
pm_first_ipv4_address(SshPmRemoteAccessAttrs attrs)
{
  SshIpAddr addr;
  int i;

  if (!attrs)
    return NULL;

  for (i = 0; i < attrs->num_addresses; i++)
    {
      addr = &attrs->addresses[i];
      if (SSH_IP_IS4(addr))
        return addr;
    }

  return NULL;
}

static SshIpAddr
pm_first_ipv6_address(SshPmRemoteAccessAttrs attrs)
{
  SshIpAddr addr;
  int i;

  if (!attrs)
    return NULL;

  for (i = 0; i < attrs->num_addresses; i++)
    {
      addr = &attrs->addresses[i];
      if (SSH_IP_IS6(addr))
        return addr;
    }

  return NULL;
}

/* If requested by the rule, adjust local traffic selector of an
   IKEv1-based IPsec SA according to what is received by config mode
   (when using IPsec tunnel mode) or according to the local IKE
   address (when using IPsec transport mode). */
static Boolean
pm_adjust_local_address(SshIkev2ExchangeData ed)
{
  SshPmQm qm = ed->application_context;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshIkev2PayloadTS ts;
  SshInetIPProtocolID proto;
  SshIpAddr addr;
  SshUInt16 port;

  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) ||
      !(qm->rule->flags & SSH_PM_RULE_ADJUST_LOCAL_ADDRESS))
    return TRUE;

  if ((ts = qm->rule->side_to.ts) &&
      ts->number_of_items_used > 0 &&
      SSH_IP_IS6(ts->items[0].start_address))
    {
      if (!(qm->tunnel->flags & SSH_PM_T_TRANSPORT_MODE))
        addr = pm_first_ipv6_address(p1->remote_access_attrs);
      else if (SSH_IP_IS6(p1->ike_sa->server->ip_address))
        addr = p1->ike_sa->server->ip_address;
      else
        addr = NULL;
    }
  else
    {
      if (!(qm->tunnel->flags & SSH_PM_T_TRANSPORT_MODE))
        addr = pm_first_ipv4_address(p1->remote_access_attrs);
      else if (SSH_IP_IS4(p1->ike_sa->server->ip_address))
        addr = p1->ike_sa->server->ip_address;
      else
        addr = NULL;
    }

  if (!addr)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Cannot set IPSec SA local address "
                 "because suitable address not available"));
      return FALSE;
    }

  if (!ed->ipsec_ed->source_ip)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Cannot set IPSec SA local address "
                 "because address not allocated"));
      return FALSE;
    }

  memcpy(ed->ipsec_ed->source_ip, addr, sizeof *addr);

  if (SSH_IP_IS4(ed->ipsec_ed->source_ip))
    ed->ipsec_ed->source_ip->mask_len = 32;
  else
    ed->ipsec_ed->source_ip->mask_len = 128;

  if (!(ts = qm->rule->side_from.ts) || ts->number_of_items_used < 1)
    {
      proto = 0;
      port = 0;
    }
  else
    {
      proto = ts->items[0].proto;
      port = ts->items[0].start_port;
    }

  ed->ipsec_ed->protocol = proto;
  ed->ipsec_ed->source_port = port;

  return TRUE;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IKEV1 */

SshOperationHandle
ssh_pm_ike_spd_fill_ipsec_sa(SshSADHandle sad_handle,
			     SshIkev2ExchangeData ed,
			     SshIkev2SpdFillSACB reply_callback,
			     void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmQm qm = ed->application_context;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshIkev2PayloadSA ipsec_sa_payload = NULL;
  SshIkev2Error ike_error;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
			NULL, reply_callback_context);
      return NULL;
    }

  /* Check the case of responder IKEv1 negotiations where the IKE SA has
     been deleted (ed->application_context is cleared). */
  if (qm == NULL || !SSH_PM_P1_USABLE(p1))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE,
			NULL, reply_callback_context);
      return NULL;
    }

  SSH_PM_ASSERT_QM(qm);

  if ((qm->transform & SSH_PM_IPSEC_AH) && (qm->transform & SSH_PM_IPSEC_ESP))
    {
      SSH_DEBUG(SSH_D_FAIL, ("AH & ESP bundles are not supported"));
      (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
			NULL, reply_callback_context);
      return NULL;
    }

#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_ISAKMP_CFG_MODE
  if (!pm_adjust_local_address(ed))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                        NULL, reply_callback_context);
      return NULL;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IKEV1 */

  ike_error = pm_build_ipsec_sa_from_tunnel(pm, qm, qm->tunnel,
					    &ipsec_sa_payload);

#ifdef DEBUG_LIGHT
  if (ike_error == SSH_IKEV2_ERROR_OK && ipsec_sa_payload != NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Initiator's proposing IPSec SA payload %@",
			      ssh_ikev2_payload_sa_render, ipsec_sa_payload));
    }
#endif /* DEBUG_LIGHT */

  (*reply_callback)(ike_error, ipsec_sa_payload, reply_callback_context);
  return NULL;
}


/* ************************* Select an IPSEC SA proposal. ********************/

SshIkev2Error
pm_ike_spd_select_ipsec_sa(SshPm pm,
			   SshIkev2ExchangeData ed,
			   SshIkev2PayloadSA sa_in,
			   SshIkev2PayloadTransform
			   selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
			   int *proposal_index)
{
  SshIkev2PayloadSA sa_policy = NULL;
  SshPmQm qm = ed->application_context;
  SshIkev2Error ike_error;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    return SSH_IKEV2_ERROR_SUSPENDED;

  /* Check the case of responder IKEv1 negotiations where the IKE SA has
     been deleted (ed->application_context is cleared). */
  if (qm == NULL || !SSH_PM_P1_USABLE((SshPmP1)ed->ike_sa))
    return SSH_IKEV2_ERROR_SA_UNUSABLE;

  SSH_PM_ASSERT_QM(qm);
  SSH_ASSERT(qm->tunnel != NULL);

  /* Check if already in error state ... might be in case of simultaneus
     IPsec SA rekey. See sad_ike_spis.c for details. */
  if (qm->error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("This SA lost on simultaneus IPsec rekey arbitration."));
      return qm->error;
    }

#ifdef SSHDIST_IKEV1
  /* Use the tunnel to set our local lifetimes to the IPSec exchange data
     where it is visible to the IKEv1 fallback code. */
  if (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      ed->ipsec_ed->sa_life_seconds = qm->tunnel->u.ike.life_seconds;
      ed->ipsec_ed->sa_life_kbytes = qm->tunnel->u.ike.life_kb;

      SSH_DEBUG(SSH_D_MIDOK, ("Set IPSec SA Policy lifetimes sec=%d, kb=%d "
			      "to the exchange data",
			      (int) ed->ipsec_ed->sa_life_seconds,
			      (int) ed->ipsec_ed->sa_life_kbytes));
    }
#endif /* SSHDIST_IKEV1 */

  /* Use the tunnel to select the transforms appropriate to our tunnel's
     policy. */
  ike_error = pm_build_ipsec_sa_from_tunnel(pm, qm, qm->tunnel, &sa_policy);

  if (ike_error != SSH_IKEV2_ERROR_OK)
    return ike_error;

  SSH_DEBUG(SSH_D_MIDOK, ("Responder's tunnel IPSec SA payload is %@",
			  ssh_ikev2_payload_sa_render, sa_policy));

  SSH_DEBUG(SSH_D_MIDOK, ("Initiator's proposed IPSec SA payload is %@",
			  ssh_ikev2_payload_sa_render, sa_in));

  if (ssh_ikev2_sa_select(sa_in, sa_policy, proposal_index,
			  selected_transforms,
			  &qm->ike_failure_mask))
    {
      ssh_ikev2_sa_free(pm->sad_handle, sa_policy);

      /* Check the proposal index is as expected. */
      if ((sa_in->protocol_id[*proposal_index] != SSH_IKEV2_PROTOCOL_ID_ESP &&
	   sa_in->protocol_id[*proposal_index] != SSH_IKEV2_PROTOCOL_ID_AH)
	  || (!qm->tunnel_accepted && !qm->transport_recv))
	{
	  SSH_DEBUG(SSH_D_FAIL, 
		    ("Unexpected proposal index, failing SA selection"));
	  return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
	}

      /* Success */
      return SSH_IKEV2_ERROR_OK;
    }
  else
    {
      /* Failure */
      ssh_ikev2_sa_free(pm->sad_handle, sa_policy);
      return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }
}

typedef struct SshPmSpdSelectIPsecSaContextRec
{
  SshOperationHandleStruct op[1];
  SshFSMThreadStruct thread[1];
  SshUInt8 aborted : 1;
  SshUInt8 failed : 1;
  SshSADHandle sad_handle;
  SshIkev2ExchangeData ed;
  SshIkev2PayloadSA sa_in;
  SshIkev2SpdSelectSACB reply_callback;
  void *reply_callback_context;
} *SshPmSpdSelectIPsecSaContext;

static void
pm_ike_spd_select_ipsec_sa_thread_destructor(SshFSM fsm, void *context)
{
  SshPmSpdSelectIPsecSaContext ctx = context;

  SSH_ASSERT(ctx != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, ("Select IPsec SA thread destructor."));

  /* Free sa reference. */
  ssh_ikev2_sa_free(ctx->sad_handle, ctx->sa_in);

  if (!ctx->aborted)
    ssh_operation_unregister(ctx->op);

  /* Free ed reference.
     This might free the obstack this ctx was allocated from. */
  ssh_ikev2_exchange_data_free(ctx->ed);
}

static void
pm_ike_spd_select_ipsec_sa_abort(void *context)
{
  SshPmSpdSelectIkeSaContext ctx = context;
  SSH_DEBUG(SSH_D_LOWOK, ("Select IPsec SA operation aborted"));
  ctx->aborted = 1;
}

static void 
ssh_pm_st_ike_spd_select_ipsec_sa_trd_cb(SshPm pm,
					 const SshEngineTransform trd,
					 void *context)
{
  SshPmSpdSelectIPsecSaContext ctx = context;
  SshPmQm qm = ctx->ed->application_context;
  
  if (trd != NULL && qm != NULL && !ctx->aborted)
    {
      qm->transform = trd->data.transform;
    }
  else
    {
      ctx->failed = 1;
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Could not fetch transform from engine, "
		 "failing IPsec SA select"));
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
}

SSH_FSM_STEP(ssh_pm_st_ike_spd_select_ipsec_sa_fetch_trd)
{  
  SshPm pm = fsm_context;
  SshPmSpdSelectIPsecSaContext ctx = thread_context;
  SshPmQm qm = ctx->ed->application_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_ike_spd_select_ipsec_sa);

  if (ctx->aborted)
    return SSH_FSM_FINISH;

  /* If the application context has vanished (i.e. qm is terminated),
     mark failure and handle the error case in next step. */
  if (qm == NULL)
    {
      ctx->failed = 1;
      return SSH_FSM_CONTINUE;
    }
    
  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Fetching transform object from engine for transform 0x%lx",
	     (unsigned long) qm->trd_index));
  
  /* Fetch transform object from engine and set qm->transform. */
  SSH_ASSERT(qm->trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_FSM_ASYNC_CALL({
    ssh_pme_get_transform(pm->engine, qm->trd_index,
			  ssh_pm_st_ike_spd_select_ipsec_sa_trd_cb, ctx);
  });
}

SSH_FSM_STEP(ssh_pm_st_ike_spd_select_ipsec_sa)
{
  SshPm pm = fsm_context;
  SshPmSpdSelectIPsecSaContext ctx = thread_context;
  SshIkev2Error ike_error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
  int proposal_index;
  SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];

  if (ctx->aborted)
    return SSH_FSM_FINISH;

  if (!ctx->failed)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Selecting IPsec SA from initiator's proposal "
		 "using existing SA algorithms"));
      ike_error = pm_ike_spd_select_ipsec_sa(pm, ctx->ed, ctx->sa_in,
					     selected_transforms,
					     &proposal_index);
    }
  
  if (ike_error == SSH_IKEV2_ERROR_OK)
    (*ctx->reply_callback)(SSH_IKEV2_ERROR_OK, proposal_index,
			   selected_transforms, ctx->reply_callback_context);
  else
    (*ctx->reply_callback)(ike_error, 0, NULL, ctx->reply_callback_context);
  
  return SSH_FSM_FINISH;
}

SshOperationHandle
ssh_pm_ike_spd_select_ipsec_sa(SshSADHandle sad_handle,
			       SshIkev2ExchangeData ed,
			       SshIkev2PayloadSA sa_in,
			       SshIkev2SpdSelectSACB reply_callback,
			       void *reply_callback_context)
{
  SshIkev2Error ike_error;
  int proposal_index;
  SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshPmQm qm = ed->application_context;
  SshPmSpdSelectIPsecSaContext ctx;

  SSH_DEBUG(SSH_D_LOWOK, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (ssh_pm_get_status(sad_handle->pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
			0, NULL, reply_callback_context);
      return NULL;
    }

  /* Check the case of responder IKEv1 negotiations where the IKE SA has
     been deleted (ed->application_context is cleared). */
  if (qm == NULL || !SSH_PM_P1_USABLE((SshPmP1)ed->ike_sa))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE,
			0, NULL, reply_callback_context);
      return NULL;
    }

  SSH_PM_ASSERT_QM(qm);
  SSH_ASSERT(qm->tunnel != NULL);

  /* Check if already in error state ... might be in case of simultaneus
     IPsec SA rekey. See sad_ike_spis.c for details. */
  if (qm->error)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("This SA lost on simultaneus IPsec rekey arbitration."));
      (*reply_callback)(qm->error, 0, NULL, reply_callback_context);
      return NULL;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* Check if policy requires cfgmode for IKEv2 SAs. The check is here and
     not in ssh_pm_ike_conf_request() because this gets called for both
     initial and create child exchanges. Cfgmode cannot be required for
     IKEv1 SAs because we do not know if an IKEv1 SA is created without
     cfgmode to replace an expired IKEv1 SA that was originally negotiated
     with cfgmode. */
  if ((qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0
#ifdef SSHDIST_IKEV1
      && (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
#endif /* SSHDIST_IKEV1 */
      && (qm->tunnel->flags & SSH_PM_TR_REQUIRE_CFGMODE)
      && qm->p1->remote_access_attrs == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Policy requires cfgmode for IKE SA, "
		 "failing child SA negotiation"));
      (*reply_callback)(SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED, 0, NULL,
			reply_callback_context);
      return NULL;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  
  /* For rekeyes fetch the transform object from engine and do IPsec SA
     selection based on the old SA algorithms. We do not allow the algorithms
     to change during IPsec SA rekey. */
  if (qm->rekey)
    {
      /* Alloc operation context. */
      ctx = ssh_obstack_calloc(ed->obstack, sizeof(*ctx));
      if (ctx == NULL)
	{
	  (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, 0, NULL, 
			    reply_callback_context);
	  return NULL;
	}
      
      ctx->sad_handle = sad_handle;
      ssh_ikev2_exchange_data_take_ref(ed);
      ctx->ed = ed;
      ssh_ikev2_sa_take_ref(sad_handle, sa_in);
      ctx->sa_in = sa_in;
      ctx->reply_callback = reply_callback;
      ctx->reply_callback_context = reply_callback_context;
      
      ssh_fsm_thread_init(&sad_handle->pm->fsm, ctx->thread,
			  ssh_pm_st_ike_spd_select_ipsec_sa_fetch_trd, NULL,
			  pm_ike_spd_select_ipsec_sa_thread_destructor, ctx);
      ssh_fsm_set_thread_name(ctx->thread, "Select IPsec SA");
      
      ssh_operation_register_no_alloc(ctx->op,
				      pm_ike_spd_select_ipsec_sa_abort, ctx);

      return ctx->op;
    }
  
  /* For non-rekeys use tunnel policy for IPsec SA selection. */
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Selecting IPsec SA from initiator's proposal "
		 "using tunnel policy"));
      ike_error = pm_ike_spd_select_ipsec_sa(sad_handle->pm, ed, sa_in,
					     selected_transforms,
					     &proposal_index);
      if (ike_error == SSH_IKEV2_ERROR_OK)
	(*reply_callback)(SSH_IKEV2_ERROR_OK, proposal_index, 
			  selected_transforms, reply_callback_context);
      else
	(*reply_callback)(ike_error, 0, NULL, reply_callback_context);
      
      return NULL;
    }
}


/* *********************** Narrow traffic selectors. *************************/

SshOperationHandle
ssh_pm_ike_narrow_traffic_selectors(SshSADHandle sad_handle,
				    SshIkev2ExchangeData ed,
				    SshIkev2PayloadTS ts_in_local,
				    SshIkev2PayloadTS ts_in_remote,
				    SshIkev2SpdNarrowCB reply_callback,
				    void *reply_callback_context)
{
  SshIkev2PayloadTS ts_rule_local, ts_rule_remote;
  SshIkev2PayloadTS ts_local, ts_remote;
  SshPm pm = sad_handle->pm;
  SshPmQm qm = ed->application_context;
  SshIkev2Error status;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
			NULL, NULL, reply_callback_context);
      return NULL;
    }

  /* Check the case of responder IKEv1 negotiations where the IKE SA has
     been deleted (ed->application_context is cleared). */
  if (qm == NULL || !SSH_PM_P1_USABLE((SshPmP1)ed->ike_sa))
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE,
			NULL, NULL, reply_callback_context);
      return NULL;
    }

  SSH_PM_ASSERT_QM(qm);

  SSH_DEBUG(SSH_D_LOWOK, ("Enter SA %p, ED %p: TS proposal = %@ <-> %@",
			  ed->ike_sa, ed,
			  ssh_ikev2_ts_render, ts_in_local,
			  ssh_ikev2_ts_render, ts_in_remote));


  /* Get the policy rule's traffic selectors. */
  if (!ssh_pm_rule_get_traffic_selectors(pm, qm->rule, qm->forward,
					 &ts_rule_local, &ts_rule_remote))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot get traffic selectors from the policy "
			      "rule"));
      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, NULL, NULL,
			reply_callback_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("TS policy = %@ <-> %@",
			  ssh_ikev2_ts_render, ts_rule_local,
			  ssh_ikev2_ts_render, ts_rule_remote));

  ts_local = ts_remote = NULL;

  /* Narrow the traffic selectors. */
  if (!ssh_ikev2_ts_narrow(sad_handle, FALSE, &ts_local,
			   ts_in_local, ts_rule_local) ||
      !ssh_ikev2_ts_narrow(sad_handle, FALSE, &ts_remote,
			   ts_in_remote, ts_rule_remote))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not narrow traffic selectors SA %p ED %p",
			      ed->ike_sa, ed));
      if (ts_local)
	ssh_ikev2_ts_free(sad_handle, ts_local);
      if (ts_remote)
	ssh_ikev2_ts_free(sad_handle, ts_remote);

      ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			  qm, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
		    "  Message: Could not narrow traffic selectors");

      (*reply_callback)(SSH_IKEV2_ERROR_TS_UNACCEPTABLE, NULL, NULL,
			reply_callback_context);
      return NULL;
    }
  else
    {
      ssh_pm_ts_max_enforce(sad_handle, &ts_local);
      ssh_pm_ts_max_enforce(sad_handle, &ts_remote);
      SSH_DEBUG(SSH_D_HIGHOK, ("TS narrowed = %@ <-> %@",
			       ssh_ikev2_ts_render, ts_local,
			       ssh_ikev2_ts_render, ts_remote));

      status = SSH_IKEV2_ERROR_OK;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* For remote access servers, we additionally need to narrow the remote
     traffic selector with the IP address(es) we have assigned to the
     client. Also the local traffic selectors need to be narrowed with
     any subnet we have provided the client access to. */
  if (qm->p1->remote_access_attrs && 
        qm->p1->remote_access_attrs->num_addresses &&
        !SSH_PM_RULE_IS_VIRTUAL_IP(qm->rule))
    {
      SshIkev2PayloadTS ts_attrs_local, ts_attrs_remote;

      ts_attrs_local = ts_attrs_remote = NULL;
      status = ssh_pm_narrow_remote_access_attrs(pm, FALSE,
						 qm->p1->remote_access_attrs,
						 ts_local, ts_remote,
						 &ts_attrs_local,
						 &ts_attrs_remote);

      (*reply_callback)(status, ts_attrs_local, ts_attrs_remote,
			reply_callback_context);

      if (status == SSH_IKEV2_ERROR_OK)
	{
	  ssh_ikev2_ts_free(sad_handle, ts_attrs_local);
	  ssh_ikev2_ts_free(sad_handle, ts_attrs_remote);
	}

      ssh_ikev2_ts_free(sad_handle, ts_local);
      ssh_ikev2_ts_free(sad_handle, ts_remote);

      if (status == SSH_IKEV2_ERROR_TS_UNACCEPTABLE)
	{
	  ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			      qm, "failed");
	  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
			"  Message: Could not narrow traffic selectors");
	}
      return NULL;
    }
  else
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    {
      (*reply_callback)(status, ts_local, ts_remote, reply_callback_context);
    }

  ssh_ikev2_ts_free(sad_handle, ts_local);
  ssh_ikev2_ts_free(sad_handle, ts_remote);
  return NULL;
}


/* **************************** Notifications ********************************/

SshOperationHandle
ssh_pm_ike_spd_notify_request(SshSADHandle sad_handle,
			      SshIkev2ExchangeData ed,
			      SshIkev2SpdNotifyCB reply_callback,
			      void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmQm qm = NULL;
  SshPmInfo info = NULL;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));





  if (ed->application_context)
    {
      info = (SshPmInfo) ed->application_context;
      switch (info->type)
        {
        case SSH_PM_ED_DATA_QM:
          qm = (SshPmQm) ed->application_context;
	  info = NULL;
	  SSH_PM_ASSERT_QM(qm);
          break;
        case SSH_PM_ED_DATA_INFO_QM:
          qm = info->u.qm;
	  SSH_PM_ASSERT_QM(qm);
          break;
        case SSH_PM_ED_DATA_INFO_P1:
          break;
#ifdef SSHDIST_IPSEC_MOBIKE
        case SSH_PM_ED_DATA_INFO_MOBIKE:	  
          break;
#endif /* SSHDIST_IPSEC_MOBIKE */
	case SSH_PM_ED_DATA_INFO_OLD_SPI:
        case SSH_PM_ED_DATA_INFO_DPD:
          break;

        default:
          SSH_NOTREACHED;
        }
    }

  ssh_pm_ike_parse_notify_payloads(ed, qm);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  /* Announce support for certificate lookups at the initiators first
     auth packet or responders init-sa packet. For responder we have
     not yet allocated QM. */
  if ((qm == NULL && ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
      || (qm != NULL
	  && qm->initiator
	  && ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST))
    {
      /* We do support receiving these */
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			SSH_IKEV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED,
			NULL, 0,
			reply_callback_context);

    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_MOBIKE
  /* If initiator supports mobike and local policy supports mobike, 
     then reply that we (as responder) support it too. */
  if (p1 && p1->n 
      && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0
      && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST
      && p1->n->peer_supports_mobike
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      && (!ed->ike_ed->resp_require_another_auth || 
          (ed->ike_ed->authentication_round == 2))
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
      && (p1->n->tunnel->flags & SSH_PM_T_MOBIKE))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Peer supports MobIKE, we support MobIKE"));
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED,
			NULL, 0,
			reply_callback_context);      
    }

  if (info && info->type == SSH_PM_ED_DATA_INFO_DPD
      && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
      && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("DPD for MobIKE initiator SA, adding "
				   "address update notification"));
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES,
			NULL, 0,
			reply_callback_context);      
      
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* If the tunnel is set to require multiple authentications AND
     we are responder in init-state */
  if (p1 && p1->n 
      && p1->n->tunnel && p1->n->tunnel->second_auth_domain_name
      && !(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
      && (ed->state == SSH_IKEV2_STATE_IKE_INIT_SA))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Add multiple authentication notify"));
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED,
			NULL, 0,
			reply_callback_context);      
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  if (p1 != NULL && (ed->state == SSH_IKEV2_STATE_REKEY_IKE))
    {
      SshPmTunnel tunnel;
      unsigned char buffer[4];
      
      if ((tunnel = ssh_pm_p1_get_tunnel(pm, p1)) != NULL)
	{
	  /* Update the window size of the IKE SA. */	  
	  p1->ike_window_size = tunnel->ike_window_size;
	  
	  SSH_PUT_32BIT(buffer, tunnel->ike_window_size);
	  
	  SSH_DEBUG(SSH_D_LOWSTART, ("Sending IKE window size notification "
				       "for rekeyed IKE SA of size %d",
				       (int) p1->ike_window_size));
	  
	  (*reply_callback)(SSH_IKEV2_ERROR_OK,
			    SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			    SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE,
			    buffer, sizeof(buffer),
			    reply_callback_context);
	}
    }
      
  if (qm)
    {
      /* Send initial contact notification if appropiate */
      if (qm->send_initial_contact
	  && qm->initiator
	  && (
#ifdef SSHDIST_IKEV1
	      ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	       && ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
	      ||
#endif /* SSHDIST_IKEV1 */
	      ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST))
	{
	  SSH_DEBUG(SSH_D_LOWSTART, ("Sending Initial contact notify"));

	  (*reply_callback)(SSH_IKEV2_ERROR_OK,
			    SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			    SSH_IKEV2_NOTIFY_INITIAL_CONTACT,
			    NULL, 0,
			    reply_callback_context);
	}

      /* Set local window size if not already set (done on last auth
	 packet, information and create-child exchanges only). */
      if (qm->tunnel && qm->p1
	  && qm->tunnel->ike_window_size != qm->p1->ike_window_size
	  && (ed->state == SSH_IKEV2_STATE_CREATE_CHILD
	      || ed->state == SSH_IKEV2_STATE_INFORMATIONAL
	      || (qm->initiator
		  && ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST)
	      || (!qm->initiator
		  && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST)))
	{
	  unsigned char buffer[4];
	  SSH_DEBUG(SSH_D_LOWSTART, ("Sending IKE window size notification "
				     "for size %d",
				     (int) qm->tunnel->ike_window_size));
	  
	  /* Record the updated tunnel window size to the Phase I. */
	  qm->p1->ike_window_size = qm->tunnel->ike_window_size;

	  SSH_PUT_32BIT(buffer, qm->tunnel->ike_window_size);
	  (*reply_callback)(SSH_IKEV2_ERROR_OK,
			    SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			    SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE,
			    buffer, sizeof(buffer),
			    reply_callback_context);
	}

      /* Notification messages specific to IPSec. Either on
	 create-child exchange or last message of init-sa exchange. */
      if (ed->state == SSH_IKEV2_STATE_CREATE_CHILD
	  || (qm->initiator
	      && ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST)
	  || (!qm->initiator
	      && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST))
	{
	  /* Send transport notification if the tunnel specifies it. */
	  if (qm->tunnel
	      && (qm->tunnel->flags & SSH_PM_T_TRANSPORT_MODE))
	    {
	      SSH_DEBUG(SSH_D_LOWSTART,
			("Sending notify message requesting transport mode"));
	      qm->transport_sent = 1;

	      (*reply_callback)(SSH_IKEV2_ERROR_OK,
				SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
				SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE,
				NULL, 0,
				reply_callback_context);
	    }

#ifdef SSHDIST_IPSEC_IPCOMP
	  if (qm->transform & SSH_PM_IPSEC_IPCOMP)
	    {
	      unsigned char payload[3]; /* two octet CPI + tranform */

	      SSH_PUT_16BIT(payload, qm->spis[SSH_PME_SPI_IPCOMP_IN]);
	      qm->ipcomp_spi_in = qm->spis[SSH_PME_SPI_IPCOMP_IN];

	      if (qm->initiator)
		{
		  /* Initiator sends all he is configured with. */
		  if (qm->transform & SSH_PM_COMPRESS_DEFLATE)
		    {
		      payload[2] = SSH_IKEV2_IPCOMP_DEFLATE;
		      (*reply_callback)(SSH_IKEV2_ERROR_OK,
					SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
					SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED,
					payload, sizeof(payload),
					reply_callback_context);
		    }
		  if (qm->transform & SSH_PM_COMPRESS_LZS)
		    {
		      payload[2] = SSH_IKEV2_IPCOMP_LZS;
		      (*reply_callback)(SSH_IKEV2_ERROR_OK,
					SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
					SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED,
					payload, sizeof(payload),
					reply_callback_context);
		    }
		}
	      else
		{
		  /* Responder transmits the selected. */
		  if (qm->ipcomp_chosen != 0)
		    {
		      SSH_PUT_8BIT(payload + 2, qm->ipcomp_chosen);
		      (*reply_callback)(SSH_IKEV2_ERROR_OK,
					SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
					SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED,
					payload, sizeof(payload),
					reply_callback_context);
		    }
		}
	    }
#endif /* SSHDIST_IPSEC_IPCOMP */

	  if (qm->transform & SSH_PM_IPSEC_ESP)
	    {
	      /* We do not support TFC padding, indicate this. */
	      (*reply_callback)(SSH_IKEV2_ERROR_OK,
				SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
				SSH_IKEV2_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED,
				NULL, 0,
				reply_callback_context);
	    }

	  /* Non-first fragments are processed by the same SA as first
	     fragments, indicate this. */
	  (*reply_callback)(SSH_IKEV2_ERROR_OK,
			    SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
			    SSH_IKEV2_NOTIFY_NON_FIRST_FRAGMENTS_ALSO,
			    NULL, 0,
			    reply_callback_context);
	}
    }

  (*reply_callback)(SSH_IKEV2_ERROR_OK,
		    SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
		    SSH_IKEV2_NOTIFY_RESERVED, NULL, 0,
		    reply_callback_context);

  return NULL;
}

void
ssh_pm_ike_spd_notify_received(SshSADHandle sad_handle,
			       SshIkev2NotifyState notify_state,
			       SshIkev2ExchangeData ed,
			       SshIkev2ProtocolIdentifiers protocol_id,
			       unsigned char *spi,
			       size_t spi_size,
			       SshIkev2NotifyMessageType notify_message_type,
			       unsigned char *notification_data,
			       size_t notification_data_size)
{
  SshPm pm = sad_handle->pm;
  SshUInt32 spis[1];
  SshInetIPProtocolID ipproto = SSH_IPPROTO_ANY;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshPmQm qm = NULL;
  SshPmInfo info = NULL;
  Boolean authenticated = FALSE;





  if (notify_state == SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_INITIAL ||
      notify_state == SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_FINAL)
    authenticated = TRUE;

  SSH_DEBUG(SSH_D_LOWSTART,
	    ("Enter SA %p, ED %p, state %d, received notification "
	     "message %s authenticated=%d", ed->ike_sa, 
	     ed, ed->state,
	     ssh_ikev2_notify_to_string(notify_message_type),
	     authenticated));

  if (p1 == NULL || !SSH_PM_P1_USABLE(p1))
    return;

  if (ed->application_context)
    {
      info = (SshPmInfo) ed->application_context;
      switch (info->type)
        {
        case SSH_PM_ED_DATA_QM:
          qm = (SshPmQm) ed->application_context;
	  info = NULL;
          break;
        case SSH_PM_ED_DATA_INFO_QM:
          qm = info->u.qm;
          break;
        case SSH_PM_ED_DATA_INFO_P1:
          break;
#ifdef SSHDIST_IPSEC_MOBIKE
        case SSH_PM_ED_DATA_INFO_MOBIKE:	  
          break;
#endif /* SSHDIST_IPSEC_MOBIKE */	  
	case SSH_PM_ED_DATA_INFO_OLD_SPI:
        case SSH_PM_ED_DATA_INFO_DPD:	  
          break;
        default:
          SSH_NOTREACHED;
        }
    }

  if (qm != NULL)
    SSH_PM_ASSERT_QM(qm);

  /* First handle unauthenticated notifies. The only unauthenticated notifies 
     we process are NO_PROPOSAL_CHOSEN and AUTHENTICATION_FAILED for which 
     we just log the notify without otherwise acting on it. */
  if (!authenticated) 
    {
      switch (notify_message_type)
	{
	case SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN:
	case SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED:
	  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			"Plain-text notification `%s' (%d) "
			"from %@:%d for protocol %s."
			" Initiator SPI %@ Responder SPI %@",
			ssh_find_keyword_name(ssh_ikev2_notify_to_string_table,
					      notify_message_type),
			notify_message_type,
			ssh_ipaddr_render, p1->ike_sa->remote_ip,
			p1->ike_sa->remote_port,
		      ssh_find_keyword_name(ssh_ikev2_protocol_to_string_table,
					      protocol_id),
			ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_i,
			ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_r);
	  break;
#ifdef SSHDIST_IKE_CERT_AUTH
	case SSH_IKEV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED:
	  if (p1->n) 
	    p1->n->cert_access_supported = 1;
	  break;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_MOBIKE
	case SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED:
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Peer supports MobIKE."));
	  if (p1->n)
	    p1->n->peer_supports_mobike = 1;
	  break;
#endif /* SSHDIST_IPSEC_MOBIKE */

	default:
	  SSH_DEBUG(SSH_D_MIDOK, ("Ignoring unauthenticated notify message "
				  "of type %d", notify_message_type));
	  break;
	}

      return;
    }

  /* Now process authenticated notify messages. */
  SSH_ASSERT(authenticated == TRUE);
  switch (notify_message_type)
    {
    case SSH_IKEV2_NOTIFY_INITIAL_CONTACT:
      /* Process the initial contact notification. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Received an initial contact notification from `%@:%d'",
		 ssh_ipaddr_render, ed->ike_sa->remote_ip,
		 ed->ike_sa->remote_port));
      
      SSH_PM_ASSERT_P1(p1);
      if (p1->done && !p1->received_1contact)
	ssh_pm_process_initial_contact_notification(pm, p1);
      else
	p1->received_1contact = 1;
      break;

    case SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE:
      if (qm)
	qm->transport_recv = 1;
      break;

    case SSH_IKEV2_NOTIFY_INVALID_SELECTORS:

      /* Apparently we have sent IPsec packets whose selectors do not match
	 those of the SA on which it was delivered. If this message is
	 received, our SA state has most likely been corrupted, and we
	 should tear down this SA. */
      SSH_PM_ASSERT_P1(p1);

      if (protocol_id == SSH_IKEV2_PROTOCOL_ID_AH)
	ipproto = SSH_IPPROTO_AH;
      else if (protocol_id == SSH_IKEV2_PROTOCOL_ID_ESP)
	ipproto = SSH_IPPROTO_ESP;
      else
	return;
      
      /* Ignore notification messages with a corrupt SPI size. */
      if (spi_size != 4)
	return;
      
      spis[0] = SSH_GET_32BIT(spi);

      /* Delete SA from engine and send delete notification for the SPI. */

      /* Take a reference to protect the IKE SA. It is freed in 
	 ssh_pm_p1_send_ipsec_delete_notification(). */
      ssh_pm_ike_sa_take_ref(pm->sad_handle, p1->ike_sa);

      /* Delete the SA from engine and send delete notification for it. */
      ssh_pm_delete_by_spi(pm, spis[0], ipproto,
			   p1->ike_sa->remote_ip, p1->ike_sa->remote_port, 
			   ssh_pm_delete_by_spi_send_notifications_cb, p1);
      break;
      
    case SSH_IKEV2_NOTIFY_INVALID_SPI:
      /* The peer does not know the SPI we are using for sending IPSec
	 packets. Just delete the SPI. */
      SSH_PM_ASSERT_P1(p1);
      
      if (protocol_id == SSH_IKEV2_PROTOCOL_ID_AH)
	ipproto = SSH_IPPROTO_AH;
      else if (protocol_id == SSH_IKEV2_PROTOCOL_ID_ESP)
	ipproto = SSH_IPPROTO_ESP;
      else
	return;
      
      /* Ignore notification messages with a corrupt SPI size. */
      if (spi_size != 4)
	return;
      
      spis[0] = SSH_GET_32BIT(spi);
      
      ssh_pm_invalid_spi_notify(pm, SSH_PM_IKE_SA_INDEX(p1),
				p1->ike_sa->server->ip_address,
				p1->ike_sa->remote_ip, 
				p1->ike_sa->remote_port,
				ipproto, spis[0]);
      break;
  
    case SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED:
#ifdef SSHDIST_IPSEC_IPCOMP
      if (qm
	  && (qm->transform & SSH_PM_IPSEC_IPCOMP)
	  && (qm->ipcomp_chosen == 0)
	  && (notification_data_size == 3))
	{
	  if (qm->initiator)
	    {
	      /* Read the selected IPCOMP from response. */
	      qm->ipcomp_spi_out = SSH_GET_16BIT(notification_data);
	      qm->ipcomp_chosen = SSH_GET_8BIT(notification_data + 2);
	    }
	  else
	    {
	      SshUInt8 proposed;

	      /* Responder does selection here, prosessing the
		 initiator request against policy. */ 







	      proposed = SSH_GET_8BIT(notification_data + 2);

	      if (((qm->transform & SSH_PM_COMPRESS_DEFLATE)
		   && (proposed == SSH_IKEV2_IPCOMP_DEFLATE))
		  ||
		  ((qm->transform & SSH_PM_COMPRESS_LZS)
		   && (proposed == SSH_IKEV2_IPCOMP_LZS)))
		{
		  qm->ipcomp_chosen = proposed;
		  qm->ipcomp_spi_out = SSH_GET_16BIT(notification_data);
		}
	    }
	}
#endif /* SSHDIST_IPSEC_IPCOMP */
      break;

    case SSH_IKEV2_NOTIFY_ADDITIONAL_TS_POSSIBLE:
      if (qm)
	qm->additional_ts_received = 1;
      break;

    case SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD:
      /* Wrong guess of D-H group when creating child SA. Need to
	 restart current operation. */
      if (protocol_id != SSH_IKEV2_PROTOCOL_ID_IKE
	  && ed->state == SSH_IKEV2_STATE_CREATE_CHILD
	  && qm
	  && qm->initiator)
	{
	  SshPmQm newqm, n, p;
	  
	  /* Copy QM */
	  if ((newqm = ssh_pm_qm_alloc(pm, qm->rekey)) == NULL)
	    return;
	  n = newqm->next;
	  p = newqm->prev;
	  memcpy(newqm, qm, sizeof(*qm));
	  
	  /* Reinit */
	  newqm->error = SSH_IKEV2_ERROR_OK;
	  newqm->ike_done = 0;
	  newqm->transport_sent = 0;
	  newqm->transport_recv = 0;
	  newqm->ed = NULL;
	  
	  newqm->next = n;
	  newqm->prev = p;
	  
	  /* Steal traffic selectors, tunnel, SPIs, and 
	     packet from old QM. */
	  qm->packet = NULL;
	  
	  /* Explicitly move tunnel references to newqm for clarity. */
	  SSH_PM_RULE_LOCK(newqm->rule);
	  SSH_PM_RULE_UNLOCK(pm, qm->rule);
	  qm->rule = NULL;
	  
	  if (newqm->tunnel)
	    SSH_PM_TUNNEL_TAKE_REF(newqm->tunnel);
	  if (newqm->p1_tunnel)
	    SSH_PM_TUNNEL_TAKE_REF(newqm->p1_tunnel);
	  
	  qm->local_ts = qm->remote_ts = NULL;
	  qm->local_trigger_ts = qm->remote_trigger_ts = NULL;
	  memset(qm->spis, 0, sizeof(qm->spis));
	  
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
	  /* Move VIP object reference to new QM. */
	  newqm->vip = qm->vip;
	  qm->vip = NULL;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
	  
	  ssh_fsm_thread_init(&pm->fsm,
			      &newqm->thread, ssh_pm_st_qm_i_n_restart_qm, 
			      NULL_FNPTR, pm_qm_thread_destructor, newqm);
	}
      break;
      
    case SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN:
    case SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED:
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
		    "Authenticated notification `%s' (%d) "
		    "from %@:%d for protocol %s."
		    " Initiator SPI %@ Responder SPI %@",
		    ssh_find_keyword_name(ssh_ikev2_notify_to_string_table,
					  notify_message_type),
		    notify_message_type,
		    ssh_ipaddr_render, p1->ike_sa->remote_ip,
		    p1->ike_sa->remote_port,
		    ssh_find_keyword_name(ssh_ikev2_protocol_to_string_table,
					  protocol_id),
		    ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_i,
		    ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_r);
      break;

#ifdef SSHDIST_IPSEC_MOBIKE
    case SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES:
      if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
	{
	  SSH_DEBUG(SSH_D_UNCOMMON, 
		    ("Received address update for non-MobIKE SA %p, ignoring",
		     p1->ike_sa));
	}     
      else if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR)
	       == 0)
	{
	  SSH_DEBUG(SSH_D_LOWOK,
		    ("Received address update notify from peer for IKE SA %p",
		     p1->ike_sa));
	}
      else
	{
	  SSH_DEBUG(SSH_D_UNCOMMON, 
		    ("Responder sent us an address update"
		     " for IKE SA %p, ignoring", p1->ike_sa));
	}
      break;
      
    case SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS:
    case SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS:
    case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES:
      if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
	{
	  SSH_DEBUG(SSH_D_UNCOMMON, 
		    ("Received additional address notify for "
		     "non-MobIKE SA %p, ignoring",
		     p1->ike_sa));
	}
      else
	{
	  SSH_DEBUG(SSH_D_MIDOK, ("Additional addresses notify received"));
	}
      break;
#endif /* SSHDIST_IPSEC_MOBIKE */

    default:
      break;
    }
}


void
ssh_pm_ike_spd_responder_exchange_done(SshSADHandle sad_handle,
				       SshIkev2Error error,
				       SshIkev2ExchangeData ed)
{
  /* Currently this policy call is not called for IKEv1 SAs, as the
     only need for this call is to export the IKEv2 SAs and to trigger
     MOBIKE operations. If some IKEv1 specific functionality is added here
     then the IKEv2 fallback code must be modified to call this policy
     call. */

  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshIkev2PayloadNotify notify;
#ifdef SSHDIST_IPSEC_MOBIKE
  Boolean address_update_received = FALSE;
  Boolean additional_addresses_received = FALSE;
#endif /* SSHDIST_IPSEC_MOBIKE */  

  /* Update IKE SA. */
  switch (ed->state)
    {
      /* Do not update IKE SA for initial exchanges. */
    case SSH_IKEV2_STATE_IKE_INIT_SA:
    case SSH_IKEV2_STATE_IKE_AUTH_1ST:
#ifdef SSHDIST_IKE_EAP_AUTH
    case SSH_IKEV2_STATE_IKE_AUTH_EAP:
#endif /* SSHDIST_IKE_EAP_AUTH */
    case SSH_IKEV2_STATE_IKE_AUTH_LAST:
      break;
    
      /* Update old rekeyed IKE SA eventhough it is marked unusable. */
    case SSH_IKEV2_STATE_REKEY_IKE:
      ssh_pm_ike_sa_event_updated(pm, p1);
      break;

      /* Update IKE SA after successfull CREATE_CHILD or INFORMATIONAL
	 exchanges. */
    default:
      if (!p1->unusable)
	ssh_pm_ike_sa_event_updated(pm, p1);
      break;
    }

  if (error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Responder exchange failed"));
      return;
    }
  
  /* Iterate through received notifies. */
  for (notify = ed->notify; notify != NULL; notify = notify->next_notify)
    {
      switch (notify->notify_message_type)
	{
#ifdef SSHDIST_IPSEC_MOBIKE	  
	case SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES:
	  if (ed->info_ed 
	      && ed->info_ed->unexpected_nat_detected == 0
	      && address_update_received == FALSE)
	    {
	      address_update_received = TRUE;
	      ssh_pm_mobike_address_update_received(pm, p1, ed);
	    }
	  break;

	case SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS:
	case SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS:
	case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES:
	  if (additional_addresses_received == FALSE)
	    {
	      additional_addresses_received = TRUE;
	      ssh_pm_mobike_additional_addresses_received(pm, p1, ed);
	    }
	  break;
#endif /* SSHDIST_IPSEC_MOBIKE */
	  
	default:
	  break;
	}
    }
}
