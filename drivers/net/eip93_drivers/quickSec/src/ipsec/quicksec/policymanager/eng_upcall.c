/*
 * eng_upcall.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Functions in the PM that are called from the engine.
 *
 */

#include "sshincludes.h"
#include "sshudp.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmUpcall"


/************************** Static help functions ***************************/

/* Create SA selectors for the negotiation `qm' that was started from
   a trigger (or from hand-constructed trigger in the non-delayed open
   case).  The SA selectors are taken from the high-level policy rule,
   or from the triggered packet if the tunnel specifies per-port or
   per-host SAs. The parameter 'forward' states in which direction
   the negotiation is proceeding. It is FALSE only for hand-constructed
   triggers. */
static Boolean
pm_make_traffic_selectors(SshPm pm,
			  SshPmQm qm, SshPmRule rule,
			  Boolean forward,
			  SshIkev2PayloadTS *local_ts,
			  SshIkev2PayloadTS *remote_ts)
{
  SshPmRuleSideSpecification src;
  SshPmRuleSideSpecification dst;
  SshPmTunnel tunnel;
  int i;

  *local_ts = *remote_ts = NULL;

  /* Take the traffic selectors from the rule. */
  if (forward)
    {
      src = &rule->side_from;
      dst = &rule->side_to;
    }
  else
    {
      dst = &rule->side_from;
      src = &rule->side_to;
    }

  tunnel = dst->tunnel;
  SSH_ASSERT(tunnel != NULL);

  /* Here we process everything related to PER_HOST_SA or PER_PORT_SA
     or all transport mode stuff. */
  if ((!(tunnel->transform & SSH_PM_IPSEC_TUNNEL) ||
       (tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
       (tunnel->flags & SSH_PM_T_PER_PORT_SA)) &&
      (qm->tunnel->manual_tn == 0))
    {
      /* Allocate local and remote traffic selectors. */
      *local_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
      if (*local_ts == NULL)
	return FALSE;
      
      *remote_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
      if (*remote_ts == NULL)
	{
	  ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
	  *local_ts = NULL;
	  return FALSE;
	}

      if (tunnel->flags & SSH_PM_T_PER_PORT_SA)
	{
	  /* Add a local traffic selector item from the trigger packet. */
	  if (ssh_ikev2_ts_item_add(*local_ts,
				    qm->sel_ipproto,
				    &qm->sel_src,
				    &qm->sel_src,
				    qm->sel_src_port,
				    qm->sel_src_port)
	      != SSH_IKEV2_ERROR_OK)
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item to local TS"));
	      ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
	      ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
	      *local_ts = *remote_ts = NULL;
	      return FALSE;
	    }
	  
	  /* Add a remote traffic selector item from the trigger packet. */
	  if (ssh_ikev2_ts_item_add(*remote_ts,
				    qm->sel_ipproto,
				    &qm->sel_dst,
				    &qm->sel_dst,
				    qm->sel_dst_port,
				    qm->sel_dst_port)
	      != SSH_IKEV2_ERROR_OK)
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item to remote TS"));
	      ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
	      ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
	      *local_ts = *remote_ts = NULL;
	      return FALSE;
	    }

	  /* Do not bother sending trigger traffic selectors. */
	  qm->send_trigger_ts = 0;
	}

      /* PER_HOST and transport mode */
      else
	{
	  /* Loop through source traffic selector items and take protocol
	     and port selectors, use source IP from trigger packet. */
	  for (i = 0;
	       rule->side_from.ts != NULL
		 && i < rule->side_from.ts->number_of_items_used;
	       i++)
	    {
	      /* Assert that IP address families match. Traffic selectors
		 have already been checked for mixed IP address families
		 in ssh_pm_rule_add(). */
	      SSH_ASSERT((SSH_IP_IS4(&qm->sel_src) 
			  && SSH_IP_IS4(rule->side_from.ts->items[i].
					start_address))
			 ||
			 (SSH_IP_IS6(&qm->sel_src)
			  && SSH_IP_IS6(rule->side_from.ts->items[i].
					start_address)));

	      if (ssh_ikev2_ts_item_add(*local_ts,
				       rule->side_from.ts->items[i].proto,
				       &qm->sel_src,
				       &qm->sel_src,
				       rule->side_from.ts->items[i].start_port,
				       rule->side_from.ts->items[i].end_port)
		  != SSH_IKEV2_ERROR_OK)
		{
		  SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item to local TS"));
		  ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
		  ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
		  *local_ts = *remote_ts = NULL;
		  return FALSE;
		}
	    }

	  /* Loop through destination traffic selector items and take protocol
	     and port selectors, use destination IP from trigger packet. */
	  for (i = 0; 
	       rule->side_to.ts != NULL
		 && i < rule->side_to.ts->number_of_items_used;
	       i++)
	    {
	      /* Assert that IP address families match. Traffic selectors
		 have already been checked for mixed IP address families
		 in ssh_pm_rule_add(). */
	      SSH_ASSERT((SSH_IP_IS4(&qm->sel_dst) 
			  && SSH_IP_IS4(rule->side_to.ts->items[i].
					start_address))
			 ||
			 (SSH_IP_IS6(&qm->sel_dst)
			  && SSH_IP_IS6(rule->side_to.ts->items[i].
					start_address)));

	      if (ssh_ikev2_ts_item_add(*remote_ts,
					rule->side_to.ts->items[i].proto,
					&qm->sel_dst,
					&qm->sel_dst,
					rule->side_to.ts->items[i].start_port,
					rule->side_to.ts->items[i].end_port)
		  != SSH_IKEV2_ERROR_OK)
		{
		  SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item to remote TS"));
		  ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
		  ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
		  *local_ts = *remote_ts = NULL;
		  return FALSE;
		}
	    }

	  /* Assert that local and remote traffic selectors each have 
	     atleast one item. */ 
	  SSH_ASSERT((*local_ts)->number_of_items_used > 0);
	  SSH_ASSERT((*remote_ts)->number_of_items_used > 0);
	}
    }
  else
    {
#ifdef SSHDIST_ISAKMP_CFG_MODE
      /* If rekeying an IPSec SA established using IKE CFG mode we need to
	 narrow the rule's traffic selectors with the remote access
	 attributes that we assigned during the IKE negotiation. */
      SshPmP1 p1 = ssh_pm_p1_by_peer_handle(pm, qm->peer_handle);
      Boolean client;
      
      /* Are we the remote access client or server? */
      client = SSH_PM_RULE_IS_VIRTUAL_IP(rule) ? TRUE : FALSE;
      
      if (!client && p1 && p1->remote_access_attrs)
	{

	  if (ssh_pm_narrow_remote_access_attrs(pm, client,
						p1->remote_access_attrs,
						src->ts, dst->ts,
						local_ts, remote_ts)
	      != SSH_IKEV2_ERROR_OK)
	    return FALSE;
	}
      else
#endif /* SSHDIST_ISAKMP_CFG_MODE */
	{
	  /* Otherwise just take the traffic selectors from the policy rule */
	  *local_ts = ssh_ikev2_ts_dup(pm->sad_handle, src->ts);
	  if (*local_ts == NULL)
	    return FALSE;

	  *remote_ts = ssh_ikev2_ts_dup(pm->sad_handle, dst->ts);
	  if (*remote_ts == NULL)
	    {
	      ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
	      *local_ts = NULL;
	      return FALSE;
	    }
	}
    }

  SSH_DEBUG(SSH_D_MIDOK, ("SA traffic selectors for %s direction of the rule: "
			  "local=%@, remote=%@",
			  forward ? "FORWARD" : "REVERSE",
			  ssh_ikev2_ts_render, *local_ts,
			  ssh_ikev2_ts_render, *remote_ts));
  return TRUE;
}

#ifdef WITH_IKE
/* Create traffic selectors for negotiation `qm' which is a rekey
   negotiation for an existing SA bundle.  The selectors are constructed
   from the existing outbound SA rule `engine_rule' and from its transform
   `trd'.  The function returns TRUE if the selectors were created and FALSE
   on error. */
static Boolean
pm_make_engine_rule_traffic_selectors(SshPm pm, SshPmQm qm,
				      const SshEnginePolicyRule engine_rule,
				      const SshEngineTransformData trd)
{
  SshUInt16 start_port, end_port;
  SshIpAddrStruct ip_low, ip_high;
  SshInetIPProtocolID ipproto;
  SshIkev2Error ike_error;
  unsigned char *plow, *phigh;

  if (!(engine_rule->selectors & SSH_SELECTOR_SRCIP) ||
      !(engine_rule->selectors & SSH_SELECTOR_DSTIP))
    {
      SSH_DEBUG(SSH_D_FAIL,
		("This rule does not have both src and dst "
		 "selectors, cannot construct traffic selectors"));
      return FALSE;
    }

  qm->local_trigger_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  if (qm->local_trigger_ts == NULL)
    return FALSE;

  qm->remote_trigger_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  if (qm->remote_trigger_ts == NULL)
    {
      ssh_ikev2_ts_free(pm->sad_handle, qm->local_trigger_ts);
      qm->local_trigger_ts = NULL;

      return FALSE;
    }

  /* IP protocol selector. */
  if (engine_rule->selectors & SSH_SELECTOR_IPPROTO)
    ipproto = engine_rule->ipproto;
  else
    ipproto = SSH_IPPROTO_ANY;

  /* Construct the local traffic selector */
  plow = engine_rule->src_ip_low;
  phigh = engine_rule->src_ip_high;

  if (engine_rule->protocol == SSH_PROTOCOL_IP4)
    {
      SSH_IP4_DECODE(&ip_low, plow);
      SSH_IP4_DECODE(&ip_high, phigh);
    }
  else
    {
      SSH_ASSERT(engine_rule->protocol == SSH_PROTOCOL_IP6);
      SSH_IP6_DECODE(&ip_low, plow);
      SSH_IP6_DECODE(&ip_high, phigh);
    }

  /* Port numbers. */
  /* ICMP type-code are stored in the dst port selector. */
  if ((engine_rule->selectors & SSH_SELECTOR_ICMPTYPE) ||
      (engine_rule->selectors & SSH_SELECTOR_ICMPCODE))
    {
      start_port = engine_rule->dst_port_low;
      end_port = engine_rule->dst_port_high;
    }
  else if (engine_rule->selectors & SSH_SELECTOR_SRCPORT)
    {
      start_port = engine_rule->src_port_low;
      end_port = engine_rule->src_port_high;
    }
  else
    {
      start_port = 0;
      end_port = 0xffff;
    }

  ipproto = (ipproto == SSH_IPPROTO_ANY) ? 0 : ipproto;

  /* Add the local traffic selector item. */
  ike_error = ssh_ikev2_ts_item_add(qm->local_trigger_ts, ipproto,
				    &ip_low, &ip_high,
				    start_port, end_port);
  if (ike_error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item, error %s",
			     ssh_ikev2_error_to_string(ike_error)));
      return FALSE;
    }

  /* Construct the remote traffic selector */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (trd->natt_flags & SSH_ENGINE_NATT_OA_R)
    {
      plow = trd->natt_oa_r;
      phigh = trd->natt_oa_r;
    }
  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    {
      plow = engine_rule->dst_ip_low;
      phigh = engine_rule->dst_ip_high;
    }

  if (engine_rule->protocol == SSH_PROTOCOL_IP4)
    {
      SSH_IP4_DECODE(&ip_low, plow);
      SSH_IP4_DECODE(&ip_high, phigh);
    }
  else
    {
      SSH_ASSERT(engine_rule->protocol == SSH_PROTOCOL_IP6);
      SSH_IP6_DECODE(&ip_low, plow);
      SSH_IP6_DECODE(&ip_high, phigh);
    }

  /* ICMP type-code or Port numbers. */
  if ((engine_rule->selectors & SSH_SELECTOR_DSTPORT) ||
      (engine_rule->selectors & SSH_SELECTOR_ICMPTYPE) ||
      (engine_rule->selectors & SSH_SELECTOR_ICMPCODE))
    {
      start_port = engine_rule->dst_port_low;
      end_port = engine_rule->dst_port_high;
    }
  else
    {
      start_port = 0;
      end_port = 0xffff;
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
#ifdef SSHDIST_IPSEC_NAT
  /* Handle the L2tp transport NAT-T case where internal NAT-to is applied,
     in this case the original selectors are got from 
     engine_rule->nat_dst_ip_* */
  if (engine_rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST &&
      trd->transform & SSH_PM_IPSEC_NATT &&
      trd->transform & SSH_PM_IPSEC_L2TP)
    {
      SSH_ASSERT(SSH_IP_DEFINED(&engine_rule->nat_dst_ip_low));
      SSH_ASSERT(SSH_IP_DEFINED(&engine_rule->nat_dst_ip_high));
      ip_low = engine_rule->nat_dst_ip_low;
      ip_high = engine_rule->nat_dst_ip_high;
      start_port = end_port = engine_rule->nat_dst_port;
    }
#endif /* SSHDIST_IPSEC_NAT */
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  
  ipproto = (ipproto == SSH_IPPROTO_ANY) ? 0 : ipproto;

  /* Add the remote traffic selector item. */
  ike_error = ssh_ikev2_ts_item_add(qm->remote_trigger_ts, ipproto,
				    &ip_low, &ip_high,
				    start_port, end_port);
  if (ike_error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item, error %s",
			     ssh_ikev2_error_to_string(ike_error)));
      return FALSE;
    }

  /* The SA selectors are also the default values for traffic selectors.
     Therefore, the trigger rule is also our default value for `rule'. */
  qm->local_ts = qm->local_trigger_ts;
  qm->remote_ts = qm->remote_trigger_ts;
  ssh_ikev2_ts_take_ref(pm->sad_handle, qm->local_ts);
  ssh_ikev2_ts_take_ref(pm->sad_handle, qm->remote_ts);

  SSH_DEBUG(SSH_D_MIDOK, ("Traffic selectors: local=%@, remote=%@",
			  ssh_ikev2_ts_render, qm->local_ts,
			  ssh_ikev2_ts_render, qm->remote_ts));
  return TRUE;
}
#endif /* WITH_IKE */


/*********** Global trigger and auto-start related help functions ***********/

Boolean
ssh_pm_resolve_policy_rule_traffic_selectors(SshPm pm, SshPmQm qm)
{
  /* Create traffic selectors for this negotiation. */
  if (!pm_make_traffic_selectors(pm,
				 qm, qm->rule,
				 qm->forward,
				 &qm->local_trigger_ts,
				 &qm->remote_trigger_ts))
    return FALSE;

  /* The SA selectors are also the default values for traffic selectors.
     Therefore, the trigger rule is also our default value for `rule'. */
  qm->local_ts = qm->local_trigger_ts;
  qm->remote_ts = qm->remote_trigger_ts;
  ssh_ikev2_ts_take_ref(pm->sad_handle, qm->local_ts);
  ssh_ikev2_ts_take_ref(pm->sad_handle, qm->remote_ts);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Selectors from triggered packet: local=%@, "
			       "remote=%@",
			       ssh_ikev2_ts_render, qm->local_trigger_ts,
			       ssh_ikev2_ts_render, qm->remote_trigger_ts));

  return TRUE;
}

/*********** Functions in the PM that are called from the engine ************/



void
ssh_pm_pmp_interface_change(SshPm pm, const struct SshIpInterfacesRec *ifs)
{
  SshIpInterfacesStruct ifs_struct;
  SshInterceptorInterface *ifp1, *ifp2;
  Boolean log_received_interfaces, log_added_interfaces;
  Boolean log_removed_interfaces, seen;
  SshUInt32 i, j;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      /* The policy manager is shutting down. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Policy manager shutting down: ignoring interface change"));
      return;
    }

  /* Initialize new interface table. */
  if (ssh_ip_init_interfaces(&ifs_struct) == FALSE)
    goto error;

  log_received_interfaces = TRUE;

  /* Add and log any newly added interfaces */  
  for (i = 0, log_added_interfaces = TRUE; i < ifs->nifs; i++)
    {
      ifp1 = &ifs->ifs[i];
      
      /* Skip interfaces that have link down. */
      if (ifp1->flags & SSH_INTERFACE_FLAG_LINK_DOWN)
	continue;

      /* Add interface to new interface table. */
      if (ssh_ip_init_interfaces_add(&ifs_struct, ifp1) == FALSE)
	{
	  SSH_DEBUG(SSH_D_FAIL,
		    ("Could not add interface to interface table"));
	  goto error;
	}
      
      /* Check if this is a new interface. */
      for (j = 0, seen = FALSE; j < pm->ifs.nifs; j++)
	{
	  ifp2 = &pm->ifs.ifs[j];
	  
	  if (ssh_ip_interface_compare(ifp1, ifp2))
	    {
	      seen = TRUE;
	      break;
	    }
	}

      if (!seen)
	{
	  if (log_received_interfaces)
	    {
	      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
			    "");
	      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
			    "Received interface information for %d "
			    "interfaces:", (int) ifs->nifs);

	      log_received_interfaces = FALSE;
	    }
	  
	  if (log_added_interfaces)
	    {
	      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
			    "Added interfaces: ");
	      log_added_interfaces = FALSE;
	    }
	  ssh_pm_log_interceptor_interface(ifp1);
	}
    }

  /* Log any removed interfaces */  
  for (i = 0, log_removed_interfaces = TRUE; i < pm->ifs.nifs; i++)
    {
      ifp1 = &pm->ifs.ifs[i];

      for (j = 0, seen = FALSE; j < ifs->nifs; j++)
	{
	  ifp2 = &ifs->ifs[j];
	 
	  /* Skip interfaces that have link down. */
	  if (ifp2->flags & SSH_INTERFACE_FLAG_LINK_DOWN)
	    continue;
 
	  if (ssh_ip_interface_compare(ifp1, ifp2))
	    {
	      seen = TRUE;
	      break;
	    }
	}

      if (!seen)
	{
	  if (log_received_interfaces)
	    {
	      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
			    "");
	      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
			    "Received interface information for %d "
			    "interfaces:", (int) ifs->nifs);

	      log_received_interfaces = FALSE;
	    }

	  if (log_removed_interfaces)
	    {
	      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
			    "Removed interfaces: ");
	      
	      log_removed_interfaces = FALSE;
	    }

	  ssh_pm_log_interceptor_interface(ifp1);
	}
    }

  /* Finalize interface table initialization. */
  if (ssh_ip_init_interfaces_done(&ifs_struct) == FALSE)
    goto error;

  /* Replace existing interface table with the new interface table. */
  ssh_ip_uninit_interfaces(&pm->ifs);
  pm->ifs = ifs_struct;

  /* Notify the main thread that the interface information has
     changed. */
  pm->iface_change = 1;
  ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

  return;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize interface table"));
  ssh_ip_uninit_interfaces(&ifs_struct);
  return;
}

#ifdef SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES
void
ssh_pm_pmp_receive_ether_arprequest(SshPm pm, const SshIpAddr target)
{
  unsigned char targetip_string[SSH_IP_ADDR_STRING_SIZE];

  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
    {
      ssh_ipaddr_print(target, targetip_string, sizeof(targetip_string));

      SSH_DEBUG(SSH_D_MIDOK,
		("Sending empty UDP:500 datagram for fake ARP to %s.",
		 targetip_string));
      ssh_udp_send(pm->fake_arp_listener, targetip_string, ssh_custr("500"),
		   ssh_custr("\000"), 1);
    }
}
#endif /* SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES */

void
ssh_pm_pmp_trigger(SshPm pm,
		   const SshEnginePolicyRule policy_rule,
		   SshUInt32 flow_index,
		   const SshIpAddr nat_src_ip,
		   SshUInt16 nat_src_port,
		   const SshIpAddr nat_dst_ip,
		   SshUInt16 nat_dst_port,
		   SshUInt32 tunnel_id,
		   SshUInt32 prev_transform_index,
		   SshUInt32 ifnum, SshUInt32 flags,
		   unsigned char *data, size_t len)
{
  SshIpAddrStruct src;
  SshIpAddrStruct dst;
  SshInetIPProtocolID ipproto = SSH_IPPROTO_ANY;
  size_t hlen;
  SshUInt16 src_port = 0;
  SshUInt16 dst_port = 0;
  SshUInt32 spi = 0;
  SshUInt32 seq = 0;
  SshUInt32 ipv6_flow = SSH_IPSEC_INVALID_INDEX;
  SshPmRule rule;
#ifdef WITH_IKE
  SshPmQm qm = NULL;
#endif /* WITH_IKE */
  SshPmTunnel tunnel;
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  SshPmAppgwConn master_conn = NULL;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
    {
      /* The policy manager is not active (i.e. we are suspended or suspending
         or destroyed).  Do not start new
	 negotiations. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Policy manager not active: ignoring trigger"));
      goto drop;
    }

  /* We hit the reverse direction of a dangling flow, possible in
     some odd cases. */
  if (policy_rule->type != SSH_ENGINE_RULE_TRIGGER)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Not a trigger rule!"));
      goto drop;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Trigger received: "
	     "prev_transform_index=0x%x, ifnum=%d, flags=0x%x, index=%d "
	     "flow index=%d",
	     (unsigned int) prev_transform_index, (int) ifnum, (int) flags,
	     (int) policy_rule->rule_index,
	     (int) flow_index));

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("NAT info: NAT IP src/dst %@ / %@, "
	     "NAT Ports src/dst %d / %d",
	     ssh_ipaddr_render, nat_src_ip,
	     ssh_ipaddr_render, nat_dst_ip,
	     nat_src_port, nat_dst_port));

#ifdef DEBUG_LIGHT
  /* Dump whole trigger packet if it fits into 192 bytes. */
  if (len < (128 + 64))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
			("Triggered packet: length %d bytes", len),
			data, len);
    }

  /* Else dump header and trailer of trigger packet and omit middle. */  
  else
    {
      SSH_DEBUG(SSH_D_PCKDMP, ("Triggered packet: length %d", len));
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Header (first 128 bytes):"),
			data, 128);
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Trailer (last 64 bytes):"),
			data + len - 64, 64);
    }
#endif /* DEBUG_LIGHT */

  /* Get selectors from the packet. */
  switch (policy_rule->protocol)
    {
    case SSH_PROTOCOL_IP4:
      if (len < SSH_IPH4_HDRLEN)
	goto bad_packet;

      SSH_IPH4_SRC(&src, data);
      SSH_IPH4_DST(&dst, data);
      ipproto = SSH_IPH4_PROTO(data);
      hlen = SSH_IPH4_HLEN(data) << 2;
      break;

    case SSH_PROTOCOL_IP6:
      if (len < SSH_IPH6_HDRLEN)
	goto bad_packet;

      SSH_IPH6_SRC(&src, data);
      SSH_IPH6_DST(&dst, data);
      ipv6_flow = SSH_IPH6_FLOW(data);

      if (!ssh_pm_fetch_ip6_payload(data, len, &hlen, &ipproto, NULL, &dst))
	goto bad_packet;
      break;

    default:
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
		    "Trigger for non-IP packet of protocol %d.  "
		    "Dropping request for policy",
		    policy_rule->protocol);
      goto drop;
      break;
    }

  /* Fetch upper-level protocol information if available. */
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
    case SSH_IPPROTO_SCTP:
      /* The port numbers are laid out the same way in TCP, UDP and SCTP
	 protocols. */
      if (hlen + 4 > len)
	goto bad_packet;

      src_port = SSH_UDPH_SRCPORT(data + hlen);
      dst_port = SSH_UDPH_DSTPORT(data + hlen);
      break;

    case SSH_IPPROTO_ESP:
      /* Fetch SPI value. */
      if (hlen + SSH_ESPH_OFS_SPI + 4 > len)
	goto bad_packet;

      spi = SSH_GET_32BIT(data + hlen + SSH_ESPH_OFS_SPI);
      seq = SSH_GET_32BIT(data + hlen + SSH_ESPH_OFS_SEQ);
      break;

    case SSH_IPPROTO_AH:
      /* Fetch SPI value. */
      if (hlen + SSH_AHH_OFS_SPI + 4 > len)
	goto bad_packet;

      spi = SSH_GET_32BIT(data + hlen + SSH_AHH_OFS_SPI);
      seq = SSH_GET_32BIT(data + hlen + SSH_AHH_OFS_SEQ);
      break;

    case SSH_IPPROTO_ICMP:
      src_port = (SSH_ICMPH_TYPE(data + hlen + SSH_ICMPH_OFS_TYPE) << 8) |
	SSH_ICMPH_TYPE(data + hlen + SSH_ICMPH_OFS_CODE);

      dst_port = src_port;
      nat_src_port = src_port;
      nat_dst_port = dst_port;
      break;

    case SSH_IPPROTO_IPV6ICMP:
      src_port = (SSH_ICMP6H_TYPE(data + hlen + SSH_ICMP6H_OFS_TYPE) << 8) |
	SSH_ICMP6H_TYPE(data + hlen + SSH_ICMP6H_OFS_CODE);

      dst_port = src_port;
      nat_src_port = src_port;
      nat_dst_port = dst_port;

      break;
    default:
      /* Nothing here. */
      break;
    }

#if DEBUG_LIGHT
  {
    char protonamebuf[8];
    const char *protoname;

    protoname = ssh_find_keyword_name(ssh_ip_protocol_id_keywords, ipproto);
    if (protoname == NULL)
      {
	ssh_snprintf(protonamebuf, sizeof(protonamebuf), "%d", ipproto);
	protoname = protonamebuf;
      }

    if (src_port)
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Selectors: %@.%d > %@.%d: %s",
				   ssh_ipaddr_render, &src, src_port,
				   ssh_ipaddr_render, &dst, dst_port,
				   protoname));
    else if (spi)
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Selectors: %@ > %@ SPI %08lx: %s",
				   ssh_ipaddr_render, &src,
				   ssh_ipaddr_render, &dst,
				   (unsigned long) spi, protoname));
    else
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Selectors: %@ > %@: %s",
				   ssh_ipaddr_render, &src,
				   ssh_ipaddr_render, &dst,
				   protoname));
  }
#endif /* DEBUG_LIGHT */

  /* Check the trigger type. */
  if (policy_rule->flags & SSH_PM_ENGINE_RULE_CR)
    {
      if (ipproto == SSH_IPPROTO_AH || ipproto == SSH_IPPROTO_ESP ||
	  ipproto == SSH_IPPROTO_UDP)
	{
	  unsigned char src_buf[16], dst_buf[16];
	  unsigned char seq_buf[4], spi_buf[4];
	  unsigned char ipv6_flow_buf[4];
	  size_t src_len, dst_len, ipv6_flow_len;


	  /* Unknown SPI for NAT-T encapsulated packets. Fetch the SPI and
	     sequence number from the ESP header that follows the NAT-T UDP
	     header. */
	  if (ipproto == SSH_IPPROTO_UDP)
	    {
	      if (hlen +  SSH_UDPH_HDRLEN + 4 > len)
		goto bad_packet;

	      ipproto = SSH_IPPROTO_ESP;
	      spi = SSH_GET_32BIT(data + hlen + SSH_UDPH_HDRLEN);
	      seq = SSH_GET_32BIT(data + hlen + SSH_UDPH_HDRLEN  + 4);
	    }

	  SSH_PUT_32BIT(spi_buf, spi);
	  SSH_PUT_32BIT(seq_buf, seq);
	  SSH_IP_ENCODE(&src, src_buf, src_len);
	  SSH_IP_ENCODE(&dst, dst_buf, dst_len);

	  if (ipv6_flow != SSH_IPSEC_INVALID_INDEX)
	    {
	      SSH_PUT_32BIT(ipv6_flow_buf, ipv6_flow);
	      ipv6_flow_len = sizeof(ipv6_flow_buf);
	    }
	  else
	    {
	      ipv6_flow_len = 0;
	    }

	  ssh_pm_audit_event(pm, SSH_PM_AUDIT_POLICY,
			     ipproto == SSH_IPPROTO_AH ?
			     SSH_AUDIT_AH_SA_LOOKUP_FAILURE :
			     SSH_AUDIT_ESP_SA_LOOKUP_FAILURE,
			     SSH_AUDIT_SPI, spi_buf, sizeof(spi_buf),
			     SSH_AUDIT_SEQUENCE_NUMBER,
			     seq_buf, sizeof(seq_buf),
			     SSH_AUDIT_SOURCE_ADDRESS, src_buf, src_len,
			     SSH_AUDIT_DESTINATION_ADDRESS, dst_buf, dst_len,
			     SSH_AUDIT_IPV6_FLOW_ID,
			     ipv6_flow_buf, ipv6_flow_len,
			     SSH_AUDIT_ARGUMENT_END);

#ifdef WITH_IKE
	  ssh_pm_unknown_spi_packet(pm, &dst, &src, ipproto, spi,
				    policy_rule->protocol, tunnel_id,
				    ifnum, flags, prev_transform_index,
				    data, len);
#else /* WITH_IKE */
	  ssh_free(data);
#endif /* WITH_IKE */
	}
      else
	{
	  ssh_free(data);
	}
      return;
    }

  /* Resolve our policy context. */
  rule = (SshPmRule) policy_rule->policy_context;
  SSH_ASSERT(rule != NULL);
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  if (policy_rule->flags & SSH_PM_ENGINE_RULE_SLAVE)
    {
      master_conn = (SshPmAppgwConn) policy_rule->policy_context;
      SSH_ASSERT(master_conn != NULL);
      rule = master_conn->rule;
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  SSH_ASSERT(rule != NULL);

  /* Is the rule still valid? */
  if (SSH_PM_RULE_INACTIVE(pm, rule))
    {
      SSH_DEBUG(SSH_D_FAIL,
		("The rule `%@' is not in the active configuration",
		 ssh_pm_rule_render, rule));
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
		    "The rule is not in the active configuration.  "
		    "Dropping request for policy");
      goto drop;
    }

  /* Take the tunnels of the rule. */
  if (policy_rule->flags & SSH_PM_ENGINE_RULE_FORWARD)
    tunnel = rule->side_to.tunnel;
  else
    tunnel = rule->side_from.tunnel;
  
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

  /* Check IPSec and application gateway processing. */
  if (tunnel == NULL ||
      policy_rule->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      SshPmService service = rule->service;
      SshUInt32 trigger_rule_index;
      SshUInt32 to_tunnel_id = 0;
      SshIpAddr new_dst_ip = NULL;
      SshUInt16 new_dst_port = 0;

      SSH_ASSERT(service != NULL);
      SSH_ASSERT(service->appgw_ident != NULL);

      if ((flags & SSH_PME_PACKET_APPGW_TRIGGER) == 0)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("received appgw non-session trigger for "
		     "appgw_request()"));
	  goto drop;
	}

      if ((policy_rule->flags
	   & (SSH_ENGINE_RULE_USE_ONCE | SSH_ENGINE_RULE_USED))
	  == (SSH_ENGINE_RULE_USE_ONCE | SSH_ENGINE_RULE_USED))
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("trigger already used to instantiate an appgw map, "
		     "dropping trigger"));
	  goto drop;
	}

      /* Resolve some attributes of the packet.  The
	 `triger_rule_index' is needed when the application gateway
	 mappings are created.  The mapping flows are associated with
	 the rule.  The tunnel ID specifies the rule-set from which
	 the packet was triggered to policy manager, e.g. it specifies
	 the tunnel from which the packet arrived.

	 Here we perform a sleight of hand, the logic below is
	 clearly dependent on the way the appgw framework and QM
	 handlers install rules into the engine. */

      if (policy_rule->transform_index == SSH_IPSEC_INVALID_INDEX)
	trigger_rule_index = policy_rule->rule_index;
      else if (policy_rule->transform_index != SSH_IPSEC_INVALID_INDEX)
	trigger_rule_index = policy_rule->depends_on;
      else
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Unable to deduce trigger rule!"));
	  goto drop;
	}

      /* If we are a backwards appgw rule, switch ft/tt id's */
      if (tunnel)
	to_tunnel_id = tunnel->tunnel_id;

      SSH_DEBUG(SSH_D_MY, ("flags=0x%08lx",
			   (unsigned long) policy_rule->flags));

      /* If engine allocated a destination NAT mapping for this
	 connection. Then let the appgw frame know about this. */
      if ((!SSH_IP_EQUAL(nat_dst_ip, &dst)) || nat_dst_port != dst_port)
	{
	  new_dst_ip = nat_dst_ip;
	  new_dst_port = nat_dst_port;

	  SSH_DEBUG(SSH_D_MY,("new ip:port=%@:%u",
			      ssh_ipaddr_render,new_dst_ip,
			      new_dst_port));
	}

      ssh_pm_appgw_request(pm, rule, service, master_conn,
			   policy_rule->rule_index,
			   flow_index,
			   policy_rule->protocol, ifnum, flags,
			   trigger_rule_index,
			   tunnel_id, to_tunnel_id,
			   policy_rule->transform_index,
			   prev_transform_index,
			   &src, &dst, ipproto, src_port, dst_port,
			   new_dst_ip, new_dst_port,
			   data, len);
      return;
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

#ifndef WITH_IKE
  goto drop;
#else /* WITH_IKE */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  if (SSH_PM_RULE_IS_VIRTUAL_IP(rule) && tunnel == rule->side_to.tunnel)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Getting virtual IP interface for rule `%@'",
                                 ssh_pm_rule_render, rule));

      if (!ssh_pm_use_virtual_ip(pm, tunnel, rule))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not get virtual IP interface"));
          ssh_free(data);
          return;
        }

      if (tunnel->vip->unusable)
	{
          /* VIP interface was just started, silently ignore trigger. */
          ssh_free(data);
          return;
        }
      else
        {
          /* VIP interface is up and running, continue with a normal
             QM negotiation unless... */
	  SSH_DEBUG(SSH_D_HIGHOK, ("Virtual IP interface is already up"));
#ifdef SSHDIST_L2TP
          if (tunnel->flags & SSH_PM_TI_L2TP)
            {
              /* ... this is an L2TP tunnel. */
              ssh_free(data);
              return;
            }
#endif /* SSHDIST_L2TP */

	  SSH_ASSERT(SSH_IP_DEFINED(&src));
	  if (!ssh_pm_address_is_virtual(pm, tunnel->vip, &src))
	    {
              /* ... packet does not belong to the virtual adapter. */
	      SSH_DEBUG(SSH_D_FAIL, ("Source address of trigger packet is "
				     "not from the virtual adpater, ignoring "
				     "trigger"));
	      ssh_free(data);
	      return;
	    }
	}
    }

  if (SSH_PM_RULE_IS_L2TP(rule) && tunnel == rule->side_to.tunnel
      && tunnel->vip && tunnel->vip->shutdown)
    {
      SSH_DEBUG(SSH_D_LOWOK,
		("Virtual interface for rule `%@' is shutting down, "
		 "ignoring trigger",
		 ssh_pm_rule_render, rule));
      ssh_free(data);
      return;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Check if the rule is already being used for a Quick-Mode negotiation. */
  if (rule->ike_in_progress)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("The rule already has an ongoing IKE "
			     "negotiation. Dropping trigger request."));
      goto drop;
    }

  /* Allocate and init Quick-Mode context for this negotiation. */
  qm = ssh_pm_qm_alloc(pm, FALSE);
  if (qm == NULL)
    goto drop;

  /* Mark that this rule is being used for a Quick-Mode negotiation. */
  rule->ike_in_progress = 1;

  qm->initiator = 1;
  qm->trigger = 1;
  qm->send_trigger_ts = (tunnel->flags & SSH_PM_TI_NO_TRIGGER_PACKET) ? 0 : 1;
  qm->forward = (policy_rule->flags & SSH_PM_ENGINE_RULE_FORWARD) ? 1 : 0;
  qm->rule = rule;
  SSH_PM_RULE_LOCK(qm->rule);

  qm->tunnel = tunnel;
  SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);

  qm->packet = data;
  qm->packet_len = len;
  qm->packet_protocol = policy_rule->protocol;

  qm->packet_tunnel_id = tunnel_id;
  qm->packet_prev_transform_index = prev_transform_index;
  qm->packet_ifnum = ifnum;
  qm->packet_flags = flags;
  qm->sel_src = src;
  qm->sel_dst = dst;
  qm->sel_ipproto = ipproto;
  qm->sel_src_port = src_port;
  qm->sel_dst_port = dst_port;

  /* Store trigger flow_index. */
  qm->flow_index = flow_index;

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  qm->master_connection = master_conn;

  /* Cache the original src ip, so that we can make a proper
     ssh_appgw_new_request() in case we need to. */
  qm->packet_orig_src_ip = src;
  qm->packet_orig_src_port = src_port;
  qm->packet_orig_dst_ip = dst;
  qm->packet_orig_dst_port = dst_port;

  qm->sel_src = *nat_src_ip;
  qm->sel_src_port = nat_src_port;
  qm->sel_dst = *nat_dst_ip;
  qm->sel_dst_port = nat_dst_port;

  qm->appgw_trigger_rule = *policy_rule;
  qm->is_appgw_new_session = 0;
  if (flags & (SSH_PME_PACKET_APPGW_TRIGGER | SSH_PME_PACKET_SESSION_TRIGGER))
    qm->is_appgw_new_session = 1;

  qm->is_appgw_slave = (policy_rule->flags & SSH_PM_ENGINE_RULE_SLAVE) ? 1 : 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("associated NAT: src=%@:%d dst=%@:%d",
			       ssh_ipaddr_render, nat_src_ip, nat_src_port,
			       ssh_ipaddr_render, nat_dst_ip, nat_dst_port));
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  /* Create SA selectors for this negotiation and resolve also widest
     possible traffic selectors for the IPSec SA. */
  if (!ssh_pm_resolve_policy_rule_traffic_selectors(pm, qm))
    {
      rule->ike_in_progress = 0;
      ssh_pm_qm_free(pm, qm);
      SSH_DEBUG(SSH_D_FAIL, ("Couldn't able to resolve Policy rules"));
      return;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Take a vip reference for the duration of the qm negotiation. */
  if (SSH_PM_RULE_IS_VIRTUAL_IP(qm->rule) && tunnel == rule->side_to.tunnel
      && qm->tunnel->vip)
    {
      if (!ssh_pm_virtual_ip_take_ref(pm, qm->tunnel))
	{
	  rule->ike_in_progress = 0;
	  ssh_pm_qm_free(pm, qm);
          SSH_DEBUG(SSH_D_FAIL, ("Couldn't able to take the VIP ref for QM"));
          return;
	}
      qm->vip = qm->tunnel->vip;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Start a Quick-Mode initiator thread. */
  ssh_fsm_thread_init(&pm->fsm, &qm->thread, ssh_pm_st_qm_i_trigger,
  		      NULL_FNPTR, pm_qm_thread_destructor, qm);
  ssh_fsm_set_thread_name(&qm->thread, "QM trigger");

#endif /* WITH_IKE */  

  /* All done. */
  return;

  /* Error handling. */

 bad_packet:

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
		"Malformed packet for trigger.  Dropping request for policy");

 drop:

  /* We must consume the packet data. */
  ssh_free(data);
}

Boolean
ssh_pm_pmp_transform_event(SshPm pm, SshPmeFlowEvent event,
			   SshUInt32 transform_index,
			   const SshEngineTransform tr,
			   SshUInt32 rule_index,
			   const SshEnginePolicyRule rule,
			   SshTime run_time)
{
  SshPmRule pm_rule = NULL;
  SshPmTunnel tunnel = NULL;
  SshEngineTransformControl trc = &tr->control;
  SshEngineTransformData trd = &tr->data;
  SshPmPeer peer;
  SshADTHandle handle;
#ifdef WITH_IKE
  SshInetIPProtocolID ipproto;
  SshPmQm qm = NULL;
  SshPmP1 p1 = NULL;
  SshIkev2ExchangeData ed;
  SshTime now, lastike;
  SshUInt32 inbound_spi, outbound_spi, old_inbound_spi, old_outbound_spi;
  int slot;
#endif /* WITH_IKE */  

  /* Resolve the tunnel that was being used in the negotiation. */
  if (rule)
    {
      pm_rule = (SshPmRule) rule->policy_context;
      
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
      if (rule->flags & SSH_PM_ENGINE_RULE_SLAVE)
	{
	  SshPmAppgwConn master_conn = (SshPmAppgwConn) rule->policy_context;
	  SSH_ASSERT(master_conn != NULL);
	  pm_rule = master_conn->rule;
	}
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
      
      if (pm_rule) 
	{ 
	  if (rule->flags & SSH_PM_ENGINE_RULE_FORWARD)
	    tunnel = pm_rule->side_to.tunnel;
	  else
	    tunnel = pm_rule->side_from.tunnel;
	  SSH_ASSERT(tunnel != NULL);
	}      
    }      

#ifdef WITH_IKE
  if (trd->transform & SSH_PM_IPSEC_AH)
    {
      ipproto = SSH_IPPROTO_AH;
      inbound_spi = trd->spis[SSH_PME_SPI_AH_IN];
      outbound_spi = trd->spis[SSH_PME_SPI_AH_OUT];
    }
  else if (trd->transform & SSH_PM_IPSEC_ESP)
    {
      ipproto = SSH_IPPROTO_ESP;
      inbound_spi = trd->spis[SSH_PME_SPI_ESP_IN];
      outbound_spi = trd->spis[SSH_PME_SPI_ESP_OUT];
    }
  else
    {
      SSH_NOTREACHED;
      ipproto = SSH_IPPROTO_ANY;
      inbound_spi = 0;
      outbound_spi = 0;
    }
#endif /* WITH_IKE */

  switch (event)
    {
#ifdef WITH_IKE
    case SSH_ENGINE_EVENT_REKEY_REQUIRED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Received `rekey' event for transform 0x%x",
				   (unsigned int) transform_index));

      SSH_ASSERT(rule != NULL);
      if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("Policy manager not active: ignoring event"));
	  return TRUE;
	}

      /* Check the rule has a valid transform index. */
      if (rule->transform_index == SSH_IPSEC_INVALID_INDEX)
	return TRUE;

      /* Check if this is not our master rule for this transform data.
	 This can happen if the high-level policy was reconfigured and
	 the master rule disappeared.  In that case, we simply let the
	 SA to expire and we renegotiate all SAs with appropriate
	 traffic selectors. */
      if (rule->policy_context == NULL
	  || rule->type != SSH_ENGINE_RULE_APPLY
	  || (rule->flags & SSH_PM_ENGINE_RULE_SLAVE))
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("Rekey event for non-master rule: ignoring event"));
	  return TRUE;
	}

      SSH_ASSERT(pm_rule != NULL);
      SSH_ASSERT(tunnel != NULL);

      /* Rekey SA only if it has processed any packets or 
	 if it is a no-trigger rule and it should be kept up always. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("out_packets=%u, replay_offset=%u",
				   (unsigned int) trd->out_packets_low,
				   (unsigned int) trd->replay_offset_low));

      if (SSH_UINT64_IS_ZERO(trd->out_packets_low, trd->out_packets_high)
	  && trd->replay_mask[0] == 0 && trd->replay_offset_low == 0
	  && trd->replay_offset_high == 0)
	{
	  if ((pm_rule->flags & SSH_PM_RULE_I_NO_TRIGGER) == 0)
	    {
	      SSH_DEBUG(SSH_D_NICETOKNOW,
			("No packets for the transform: ignoring event"));
	      return TRUE;
	    }
	}

      if (ssh_pm_outbound_spi_neg_ongoing(pm, outbound_spi, inbound_spi))
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("The spi %lx already has an ongoing negotiation. "
		     "Dropping rekey request.",
		     (unsigned long) outbound_spi));
	  return TRUE;
	}
     
      /* We are going to rekey the SA.  Allocate and init Quick-Mode
	 context for this negotiation. */
      qm = ssh_pm_qm_alloc(pm, TRUE);
      if (qm == NULL)
	{
	  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			"The maximum number of active Quick-Mode negotiations "
			"reached.  Rekey not done");
	  return FALSE;
	}

      qm->initiator = 1;
      qm->forward = (rule->flags & SSH_PM_ENGINE_RULE_FORWARD ? 1 : 0);
      qm->rekey = 1;
      qm->peer_handle = trc->peer_handle;

      qm->old_inbound_spi = inbound_spi;
      qm->old_outbound_spi = outbound_spi;

      qm->rule = pm_rule;
      SSH_PM_RULE_LOCK(qm->rule);

      qm->tunnel = tunnel;
      SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);

      SSH_PM_QM_SET_P1_TUNNEL(qm);      
      SSH_ASSERT(qm->p1_tunnel != NULL);
      SSH_PM_TUNNEL_TAKE_REF(qm->p1_tunnel);

      qm->packet_ifnum = trd->own_ifnum;

      /* The destination address is needed for the cases where the
	 tunnel does not specify any peer IP addresses. */
      qm->sel_dst = trd->gw_addr;
#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* For IKEv1 negotiated SAs, the IKEv1 SA might have been
	 deleted. We store NAT-T remote port here and later use
	 it to initiate a new IKEv1 SA */
      if (trd->natt_flags &
	  (SSH_ENGINE_NATT_LOCAL_BEHIND_NAT |
	   SSH_ENGINE_NATT_REMOTE_BEHIND_NAT))
	{
	  qm->sel_dst_port = trd->remote_port;
	  qm->sel_src = trd->own_addr;
	}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IKEV1 */

      qm->trd_index = rule->transform_index;
      
      /* Propose the algorithms of the existing IPsec SA. We do not allow
	 the algorithms to change during IPsec SA rekey. */
      qm->transform = trd->transform;

      /* For transport mode and perport/perhost SA's we construct the
	 traffic selectors for rekey from the engine rule. This assumes that
	 these SA's have only a single SA outbound rule associated to them,
	 i.e. they were installed from a single pair of traffic selector
	 items. However for SCTP multihoming rules we always use the
	 high-level policy rule and not the engine rule. */
      if (
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
	  ((pm_rule->flags & SSH_PM_RULE_MULTIHOME) == 0) &&
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
	  ((tunnel->flags & SSH_PM_T_PER_HOST_SA)
	   || (tunnel->flags & SSH_PM_T_PER_PORT_SA)
	   || ((trd->transform & SSH_PM_IPSEC_TUNNEL) == 0)
	   || (trc->control_flags & SSH_ENGINE_TR_C_IKEV1_SA)))
	{
	  /* Create traffic selectors for this rekey negotiation from
	     the engine rule. */
	  if (!pm_make_engine_rule_traffic_selectors(pm, qm, rule, trd))
	    {
	      ssh_pm_qm_free(pm, qm);
	      return TRUE;
	    }
	}
      else
	{
	  /* Create traffic selectors for this rekey negotiation from the
	     high-level policy rule. */
	  if (!ssh_pm_resolve_policy_rule_traffic_selectors(pm, qm))
	    {
	      ssh_pm_qm_free(pm, qm);
	      return TRUE;
	    }
	}

      qm->p1 = ssh_pm_p1_by_peer_handle(pm, trc->peer_handle);

#ifdef SSH_IPSEC_TCPENCAP
      /* Use the same encapsulating connection for the rekey. */
      memcpy(qm->tcp_encaps_conn_spi, trc->tcp_encaps_conn_spi, 
	     SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH);
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      /* If this is a virtual IP rule, then take a vip reference for
	 the duration of the qm negotiation to ensure that the VIP
	 interface does not disappear. */
      if (SSH_PM_RULE_IS_VIRTUAL_IP(qm->rule) && qm->tunnel->vip)
	{
	  if (!ssh_pm_virtual_ip_take_ref(pm, qm->tunnel))
	    {
	      ssh_pm_qm_free(pm, qm);
	      return TRUE;
	    }
	  qm->vip = qm->tunnel->vip;
	}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      /* Remove old inbound and outbound SPI's. */
      SSH_ASSERT((trd->transform & SSH_PM_IPSEC_MANUAL) == 0);
      ssh_pm_spi_in_remove_by_trd(pm, trd, TRUE);
      ssh_pm_spi_out_remove_by_trd(pm, trd, TRUE);

      /* Mark the SPI having a active negotiation. */
      if (ssh_pm_mark_outbound_spi_neg_started(pm, outbound_spi, inbound_spi))
	qm->spi_neg_started = 1;
      else
	SSH_DEBUG(SSH_D_ERROR, ("spi %lx disappeared from spi table",
				(unsigned long) outbound_spi));

      /* Start a Quick-Mode initator thread from the rekey state. */
      ssh_fsm_thread_init(&pm->fsm, &qm->thread, ssh_pm_st_qm_i_rekey,
			  NULL_FNPTR, pm_qm_thread_destructor, qm);
      ssh_fsm_set_thread_name(&qm->thread, "QM rekey");
      /* All done. */
      break;

    case SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED:
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Received `rekey inbound invalidated' event for "
		 "transform 0x%x",
		 (unsigned int) transform_index));
      
      if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("Policy manager not active: ignoring event"));
	  return TRUE;
	}

      /* Send delete notification to SA's peer. */
      if (ipproto == SSH_IPPROTO_AH)
	{
	  old_inbound_spi = trd->old_spis[SSH_PME_SPI_AH_IN];
	  old_outbound_spi = trd->old_spis[SSH_PME_SPI_AH_OUT];
	}
      else if (ipproto == SSH_IPPROTO_ESP)
	{
	  old_inbound_spi = trd->old_spis[SSH_PME_SPI_ESP_IN];
	  old_outbound_spi = trd->old_spis[SSH_PME_SPI_ESP_OUT];
	}
      else
	{
	  SSH_DEBUG(SSH_D_LOWOK,
		    ("Transform does not have AH or ESP: "
		     "delete notification not sent"));
	  return TRUE;
	}
      
      /* Check if this SPI is already being invalidated. */
      if (ssh_pm_outbound_spi_neg_ongoing(pm, old_outbound_spi,
					  old_inbound_spi))
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("The spi %lx already has an ongoing negotiation. "
		     "Dropping rekey inbound invalidated request.",
		     (unsigned long) old_outbound_spi));
	  return TRUE;
	}

      ssh_pm_send_old_inbound_spi_delete_notification(pm,
						      trc->peer_handle,
						      tunnel, pm_rule,
						      ipproto,
						      old_inbound_spi,
						      old_outbound_spi,
						      transform_index);
      break;

    case SSH_ENGINE_EVENT_IDLE:

      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Received `idle' event for transform 0x%x",
		 (unsigned int) transform_index));
      
      if ((ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
          || !rule->policy_context)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("Policy manager not active: ignoring"));
	  return TRUE;
	}
      
      p1 = ssh_pm_p1_by_peer_handle(pm, trc->peer_handle);
      if (p1 == NULL)
	{
	  /* No IKE SA found. */
	  
	  if ((trc->control_flags & SSH_ENGINE_TR_C_IKEV1_SA) == 0)
	    {
	      SSH_DEBUG(SSH_D_NICETOKNOW,
			("IKEv2 SA not valid: ignoring idle event"));
	      return TRUE;
	    }

	  if (ssh_pm_outbound_spi_neg_ongoing(pm, outbound_spi, inbound_spi))
	    {
	      SSH_DEBUG(SSH_D_NICETOKNOW, 
			("The spi %lx already has an ongoing negotiation. "
			 "Dropping idle event.",
			 (unsigned long) outbound_spi));
	      return TRUE;
	    }

	  /* IKE SA has gone away, DPD was originally enabled as we
	     got the event, and we have sent traffic without
	     receiving any responses. We do not know the time of
	     last evidence, and can not send notify right away. We'd
	     be happy to receive something from the peer specified
	     on the transform. In this case we verify that the peer
	     is alive by negotiating a new IKE SA. */

	  qm = ssh_pm_qm_alloc(pm, TRUE);
	  if (qm == NULL)
	    {
	      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			    "The maximum number of active Quick-Mode "
			    "negotiations reached.  DPD not done");
	      return FALSE;
	    }

	  qm->peer_handle = trc->peer_handle;
	  qm->sa_handler_done = 1; /* No SA handler for empty INFO */
	  qm->initiator = 1;
	  qm->rule = pm_rule;
	  SSH_PM_RULE_LOCK(qm->rule);
	  qm->forward = (rule->flags & SSH_PM_ENGINE_RULE_FORWARD) ? 1 : 0;

	  qm->tunnel = tunnel;
	  SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);

	  qm->transform = tunnel->transform;

	  qm->packet_ifnum = trd->own_ifnum;
	  qm->sel_dst = trd->gw_addr;

	  /* Indicate that this qm is used for performing DPD */
	  qm->dpd = 1;
	  qm->packet = NULL;

	  qm->old_inbound_spi = inbound_spi;
	  qm->old_outbound_spi = outbound_spi;

	  SSH_DEBUG(SSH_D_HIGHOK, ("DPD: Creating new IKEv1 SA"));

	  /* Mark the SPI having a active negotiation. */      
	  if (ssh_pm_mark_outbound_spi_neg_started(pm, outbound_spi,
						   inbound_spi))
	    qm->spi_neg_started = 1;
	  else
	    SSH_DEBUG(SSH_D_ERROR, ("spi %lx disappeared from spi table",
				    (unsigned long) outbound_spi));

	  /* Start a Quick-Mode initator thread from the initiator state
	     after trigger processing. */
	  ssh_fsm_thread_init(&pm->fsm, &qm->thread,
			      ssh_pm_st_qm_i_start_negotiation,
			      NULL_FNPTR,
			      pm_qm_thread_destructor,
			      qm);

	  ssh_fsm_set_thread_name(&qm->thread, "DPD IKE create");
	  return TRUE;
	}

      /* IKE SA found. */

      lastike = ssh_ikev2_sa_last_input_packet_time(p1->ike_sa);
      now = ssh_time();

      SSH_DEBUG(SSH_D_HIGHOK,
		("DPD: Last IKE time: %d now: %d", (int)lastike, (int)now));

      if ((now - lastike) < (10 * pm->dpd_worry_metric))
	{
	  SSH_DEBUG(SSH_D_HIGHOK,
		    ("DPD: Recent IKE packet proofs remote being alive"));
	  return TRUE;
	}

      /* Check if last IKE negotiation is more recent than the last sent
	 IPsec packet. If so then there has not been any outgoing IPsec
	 traffic since last DPD or IKE negotiation and this idle event
	 can be ignored. */
      if (lastike > trd->last_out_packet_time)
	{
	  SSH_DEBUG(SSH_D_HIGHOK,
		    ("DPD: Last IKE negotiation is more recent than the last "
		     "sent IPsec packet, ignoring idle event."));
	  return TRUE;
	}

      if (ssh_pm_servers_select(pm, p1->ike_sa->server->ip_address,
				SSH_PM_SERVERS_MATCH_IKE_SERVER,
				p1->ike_sa->server,
				SSH_INVALID_IFNUM) == NULL)
	{
	  SSH_DEBUG(SSH_D_HIGHOK,
		    ("DPD: IKE server deletion is pending, "
		     "ignoring idle event"));
	  return TRUE;
	}
	
      if (pm_ike_async_call_pending(p1->ike_sa))
	{
	  SSH_DEBUG(SSH_D_HIGHOK, ("DPD not needed; IKE is active."));
	  return TRUE;
	}

      if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
	{
	  SSH_DEBUG(SSH_D_HIGHOK, ("DPD not possible; IKE is busy."));
	  return TRUE;
	}
	
      ed = ssh_ikev2_info_create(p1->ike_sa, 0);
      if (ed != NULL)
	{
	  SshPmInfo info = ssh_pm_info_alloc(pm, ed, SSH_PM_ED_DATA_INFO_DPD);
	  if (info == NULL)
	    {
	      ssh_ikev2_info_destroy(ed);
	      return TRUE;
	    }
	    
	  /* Failure to transmit informational exchange will result
	     into deletion of IKE SA. Therefore we do not need to
	     worry about it. */
	  ed->application_context = info;
	  PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
			    ssh_ikev2_info_send(ed,
						pm_ike_info_done_callback));
	}
      break;
#endif /* WITH_IKE */      

    case SSH_ENGINE_EVENT_EXPIRED:

      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Received `expired' event for transform 0x%x",
		 (unsigned int) transform_index));

      if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("Policy manager shutting down: ignoring event"));
	  return TRUE;
	}
      ssh_pm_notify_ipsec_sa_delete(pm, event, tr);

#ifdef WITH_IKE
      /* Send delete notification to SA's peer. */
      SSH_DEBUG(SSH_D_LOWSTART,
		("Sending delete notification for inbound SPI 0x%lx",
		 (unsigned long) inbound_spi));      
      ssh_pm_send_ipsec_delete_notification(pm, trc->peer_handle,
					    tunnel, pm_rule,
					    ipproto, inbound_spi);
#endif /* WITH_IKE */
      break;
      
    case SSH_ENGINE_EVENT_DESTROYED:
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Received `destroyed' event for transform 0x%x",
		 (unsigned int) transform_index));

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      tunnel = ssh_pm_tunnel_get_by_id(pm, trc->tunnel_id);
      if (tunnel != NULL && tunnel->vip != NULL)
	{
	  if (!ssh_pm_virtual_ip_free(pm, transform_index, tunnel))
	    {
	      SSH_DEBUG(SSH_D_ERROR, 
			("Could not free virtual adapter reference"));
	    }
	}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
      
      if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Policy manager shutting down"));
	  return TRUE;
	}
      
      peer = ssh_pm_peer_by_handle(pm, trc->peer_handle);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IKEV1
      /* Release reference to address allocated for the IKEv1 peer. */
      if (peer && peer->use_ikev1)
	{
	  SshPmActiveCfgModeClient client;
	  
	  client = ssh_pm_cfgmode_client_store_lookup(pm, peer->peer_handle);
	  if (client != NULL)
	    ssh_pm_cfgmode_client_store_unreference(pm, client);
	}
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
      
      ssh_pm_notify_ipsec_sa_delete(pm, event, tr);

#ifdef WITH_IKE
      if (!(trd->transform & SSH_PM_IPSEC_MANUAL))
	{
	  /* Remove all inbound SPI's. */
	  ssh_pm_spi_in_remove_by_trd(pm, trd, TRUE);
	  ssh_pm_spi_in_remove_by_trd(pm, trd, FALSE);
	  
	  /* Remove all outbound SPI's. */
	  ssh_pm_spi_out_remove_by_trd(pm, trd, TRUE);
	  ssh_pm_spi_out_remove_by_trd(pm, trd, FALSE);
	  
	  /* Decrement the child SA count */
	  if (peer)
	    {
	      SSH_ASSERT(peer->num_child_sas > 0);
	      if (peer->num_child_sas != 0)
		peer->num_child_sas--;
	    }
#ifdef SSH_IPSEC_SMALL
	  /* Trigger IKE SA timer to setup childless IKE SA deletion. */
	  p1 = ssh_pm_p1_by_peer_handle(pm, trc->peer_handle);
	  if (p1)
	    ssh_pm_ike_sa_timer_event(pm, p1, ssh_time());
#endif /* SSH_IPSEC_SMALL */
	}
#endif /* WITH_IKE */

      /* Release peer reference. Reference must not be freed before
	 outbound spi mapping is removed. */
      ssh_pm_peer_handle_destroy(pm, trc->peer_handle);

      /* Check auto-start rules. */
      for (handle = ssh_adt_enumerate_start(pm->rule_by_id);
	   handle != SSH_ADT_INVALID;
	   handle = ssh_adt_enumerate_next(pm->rule_by_id, handle))
	{
	  pm_rule = ssh_adt_get(pm->rule_by_id, handle);
	  
	  if (SSH_PM_RULE_INACTIVE(pm, pm_rule))
	    continue;
	  
	  /* Clear any cached transform information from manually keyed
	     tunnels or auto-start rules. */
	  if (pm_rule->side_to.as_up == 0)
	    continue;
	  
	  if (pm_rule->side_to.tunnel
	      && (pm_rule->side_to.tunnel->tunnel_id
		  == trd->inbound_tunnel_id))
	    {
	      SSH_DEBUG(SSH_D_NICETOKNOW,
			("Clearing cached transform information from "
			 "tunnel %u in SshPmRule",
			 (unsigned int) trd->inbound_tunnel_id));
	      
	      if (trd->transform & SSH_PM_IPSEC_MANUAL)
		{
		  /* Invalidate the cached transform index. */
		  SSH_ASSERT(pm_rule->side_to.tunnel->manual_tn);
		  pm_rule->side_to.tunnel->u.manual.trd_index
		    = SSH_IPSEC_INVALID_INDEX;
		}
	      
	      /* Clear auto-start information from the rule. */
	      pm_rule->side_to.as_up = 0;
	      pm_rule->side_to.as_fail_retry = 0;
	      pm_rule->side_to.as_fail_limit = 0;
	      
	      /* And notify main thread that the auto-start
		 rules should be rechecked. */
	      pm->auto_start = 1;
	      ssh_fsm_condition_broadcast(&pm->fsm,
					  &pm->main_thread_cond);
	    }
	}
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  return TRUE;
}

void
ssh_pm_pmp_flow_free_notification(SshPm pm, SshUInt32 flow_index)
{
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  /* Currently only the appgw framework is interested in flow invalid events */
  ssh_pm_appgw_flow_free_notification(pm, flow_index);
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
}
