/*
 *
 * engine_pm_api_util.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Help functions for encoding and decoding PM API objects.
 *
 */

#include "sshincludes.h"
#include "sshencode.h"
#include "sshinetencode.h"
#include "sshaudit.h"
#include "sshtimeouts.h"
#include "quicksec_pm_shared.h"
#include "engine_pm_api.h"
#include "engine_pm_api_marshal.h"

#define SSH_DEBUG_MODULE "SshEnginePmApiUtil"

size_t
ssh_pm_api_encode_engine_audit_events(unsigned char **data_return,
				      SshUInt32 num_events,
				      const SshEngineAuditEvent events)
{
  unsigned char src_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char dst_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH]; 
  unsigned char *data;
  size_t src_ip_len, dst_ip_len, data_len = 0;
  SshUInt32 i, encoded, offset, real_packet_len;
  SshEngineAuditEvent event;

  /* Compute the maximum length of the encoded buffer. */
  for (i = 0; i < num_events; i++)
    {
      event = (SshEngineAuditEvent)((unsigned char *)events +
				    i * sizeof(*event));

      SSH_ASSERT(event->event > 0);
      SSH_ASSERT(event->event < SSH_AUDIT_MAX_VALUE);

      data_len += 2 * sizeof(*event) + event->packet_len;
    }

  if ((data = ssh_malloc(data_len)) == NULL)
    {
      *data_return = NULL;
      return 0;
    }

  for (offset = 0, i = 0; i < num_events; i++)
    {
      event = (SshEngineAuditEvent)((unsigned char *)events +
				    i * sizeof(*event));

      src_ip_len = ssh_encode_ipaddr_array(src_ip_buf, sizeof(src_ip_buf),
					   &event->src_ip);
      dst_ip_len = ssh_encode_ipaddr_array(dst_ip_buf, sizeof(dst_ip_buf),
					   &event->dst_ip);

      real_packet_len = (SshUInt32)event->real_packet_len;

      encoded =
	ssh_encode_array(data + offset, data_len - offset,
			 SSH_ENCODE_UINT32(event->audit_id),
			 SSH_ENCODE_UINT32(event->event),
			 SSH_ENCODE_UINT32(event->ipproto),
			 SSH_ENCODE_UINT32(event->spi),
			 SSH_ENCODE_UINT32(event->seq),
			 SSH_ENCODE_UINT32(event->flowlabel),
			 SSH_ENCODE_UINT32(event->src_ifnum),
			 SSH_ENCODE_UINT32(event->dst_ifnum),
			 SSH_ENCODE_UINT32_STR(src_ip_buf, src_ip_len),
			 SSH_ENCODE_UINT32_STR(dst_ip_buf, dst_ip_len),
			 SSH_ENCODE_UINT32(event->src_port),
			 SSH_ENCODE_UINT32(event->dst_port),
			 SSH_ENCODE_UINT32(event->icmp_type),
			 SSH_ENCODE_UINT32(event->icmp_code),
			 SSH_ENCODE_UINT32(event->to_tunnel_id),
			 SSH_ENCODE_UINT32(event->from_tunnel_id),
			 SSH_ENCODE_UINT32(event->tcp_flags),
			 SSH_ENCODE_UINT32(event->ipv4_option),
			 SSH_ENCODE_UINT32(event->validity_flags),
			 SSH_ENCODE_UINT32(event->packet_corruption),
			 SSH_ENCODE_UINT32(event->packet_attack),
			 SSH_ENCODE_UINT32_STR(event->mediahdr,
			 event->mediahdr_len),
			 SSH_ENCODE_UINT32_STR(event->packet,
			 event->packet_len),
			 SSH_ENCODE_UINT32(real_packet_len),
			 SSH_FORMAT_END);

      offset += encoded;
      if (offset > data_len || encoded == 0)
	{
	  ssh_free(data);
	  *data_return = NULL;
	  return 0;
	}
    }

  *data_return = data;
  return offset;
}

Boolean
ssh_pm_api_decode_engine_audit_events(const unsigned char *data,
				      size_t data_len,
				      SshUInt32 num_events,
				      SshEngineAuditEvent events)
{
  unsigned char *src_ip_buf, *dst_ip_buf, *media_buf;
  size_t src_ip_len, dst_ip_len, media_len;
  SshUInt32 src_port32, dst_port32, icmp_type32, icmp_code32;
  SshUInt32 tcp_flags32, ipproto32, src_ifnum32, dst_ifnum32;
  SshUInt32 ipv4_option32, spi32, seq32, validity_flags32;
  SshUInt32 flowlabel32;
  SshUInt32 consumed, decoded, i, real_packet_len;
  SshEngineAuditEvent event;

  memset(events, 0, num_events * sizeof(SshEngineAuditEventStruct));

  for (consumed = 0, i = 0; i < num_events; i++)
    {
      event = (SshEngineAuditEvent)((unsigned char *)events +
				    i * sizeof(*event));
      decoded =
	ssh_decode_array(data + consumed, data_len - consumed,
			 SSH_DECODE_UINT32(&event->audit_id),
			 SSH_DECODE_UINT32((SshUInt32 *)&event->event),
			 SSH_DECODE_UINT32(&ipproto32),
			 SSH_DECODE_UINT32(&spi32),
			 SSH_DECODE_UINT32(&seq32),
			 SSH_DECODE_UINT32(&flowlabel32),
			 SSH_DECODE_UINT32(&src_ifnum32),
			 SSH_DECODE_UINT32(&dst_ifnum32),
			 SSH_DECODE_UINT32_STR_NOCOPY(&src_ip_buf,
			 &src_ip_len),
			 SSH_DECODE_UINT32_STR_NOCOPY(&dst_ip_buf,
			 &dst_ip_len),
			 SSH_DECODE_UINT32(&src_port32),
			 SSH_DECODE_UINT32(&dst_port32),
			 SSH_DECODE_UINT32(&icmp_type32),
			 SSH_DECODE_UINT32(&icmp_code32),
			 SSH_DECODE_UINT32(&event->to_tunnel_id),
			 SSH_DECODE_UINT32(&event->from_tunnel_id),
			 SSH_DECODE_UINT32(&tcp_flags32),
			 SSH_DECODE_UINT32(&ipv4_option32),
			 SSH_DECODE_UINT32(&validity_flags32),
			 SSH_DECODE_UINT32(&event->packet_corruption),
			 SSH_DECODE_UINT32(&event->packet_attack),
			 SSH_DECODE_UINT32_STR_NOCOPY(&media_buf, &media_len),
			 SSH_DECODE_UINT32_STR_NOCOPY(&event->packet,
			 &event->packet_len),
			 SSH_DECODE_UINT32(&real_packet_len),
			 SSH_FORMAT_END);

      consumed += decoded;
      if (consumed > data_len || decoded == 0)
	return FALSE;

      ssh_decode_ipaddr_array(src_ip_buf, src_ip_len, &event->src_ip);
      ssh_decode_ipaddr_array(dst_ip_buf, dst_ip_len, &event->dst_ip);

      if (media_len > SSH_MAX_MEDIAHDR_SIZE)
	return FALSE;

      if (media_buf)
	{
	  memcpy(event->mediahdr, media_buf, media_len);
	  event->mediahdr_len = media_len;
	}

      event->ipproto = (SshUInt8)ipproto32;
      event->spi = spi32;
      event->seq = seq32;
      event->flowlabel = flowlabel32;
      event->src_ifnum = (SshEngineIfnum)src_ifnum32;
      event->dst_ifnum = (SshEngineIfnum)dst_ifnum32;
      event->src_port = (SshUInt16)src_port32;
      event->dst_port = (SshUInt16)dst_port32;
      event->icmp_type = (SshUInt8)icmp_type32;
      event->icmp_code = (SshUInt8)icmp_code32;
      event->tcp_flags = (SshUInt8)tcp_flags32;
      event->ipv4_option = (SshUInt8)ipv4_option32;
      event->validity_flags = (SshUInt8)validity_flags32;
      event->real_packet_len = (size_t)real_packet_len;

      SSH_ASSERT(event->event > 0);
      SSH_ASSERT(event->event < SSH_AUDIT_MAX_VALUE);
    }
  return TRUE;
}

size_t
ssh_pm_api_encode_policy_rule(unsigned char **data_return,
                              const SshEnginePolicyRule rule)
{
  size_t len;
#ifdef SSHDIST_IPSEC_NAT
  unsigned char nat_src_ip_low_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char nat_dst_ip_low_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char nat_src_ip_high_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char nat_dst_ip_high_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t nat_src_ip_low_len, nat_dst_ip_low_len;
  size_t nat_src_ip_high_len, nat_dst_ip_high_len;
#ifdef SSHDIST_IPSEC_FIREWALL
  unsigned char nat_selector_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t nat_selector_ip_len;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

  nat_selector_ip_len =
    ssh_encode_ipaddr_array(nat_selector_ip_buf,
                                               sizeof(nat_selector_ip_buf),
                                               &rule->nat_selector_dst_ip);
#endif /* SSHDIST_IPSEC_FIREWALL */

  nat_dst_ip_low_len = ssh_encode_ipaddr_array(nat_dst_ip_low_buf,
                                       sizeof(nat_dst_ip_low_buf),
                                       &rule->nat_dst_ip_low);
  SSH_ASSERT(nat_dst_ip_low_len != 0);
  nat_src_ip_low_len = ssh_encode_ipaddr_array(nat_src_ip_low_buf,
                                       sizeof(nat_src_ip_low_buf),
                                       &rule->nat_src_ip_low);
  SSH_ASSERT(nat_src_ip_low_len != 0);

  nat_dst_ip_high_len = ssh_encode_ipaddr_array(nat_dst_ip_high_buf,
                                       sizeof(nat_dst_ip_high_buf),
                                       &rule->nat_dst_ip_high);
  SSH_ASSERT(nat_dst_ip_high_len != 0);
  nat_src_ip_high_len = ssh_encode_ipaddr_array(nat_src_ip_high_buf,
                                       sizeof(nat_src_ip_high_buf),
                                       &rule->nat_src_ip_high);
  SSH_ASSERT(nat_src_ip_high_len != 0);

#endif /* SSHDIST_IPSEC_NAT */

  len = ssh_encode_array_alloc(
                data_return,

                /* Engine policy rule. */
                SSH_ENCODE_UINT32(rule->rule_index),
                SSH_ENCODE_UINT32(rule->precedence),
                SSH_ENCODE_UINT32(rule->tunnel_id),
                SSH_ENCODE_DATA(rule->dst_ip_low, sizeof(rule->dst_ip_low)),
                SSH_ENCODE_DATA(rule->dst_ip_high, sizeof(rule->dst_ip_high)),
                SSH_ENCODE_DATA(rule->src_ip_low, sizeof(rule->src_ip_low)),
                SSH_ENCODE_DATA(rule->src_ip_high, sizeof(rule->src_ip_high)),
                SSH_ENCODE_UINT32((SshUInt32) rule->flags),
                SSH_ENCODE_UINT32((SshUInt32) rule->selectors),
                SSH_ENCODE_UINT32((SshUInt32) rule->dst_port_low),
                SSH_ENCODE_UINT32((SshUInt32) rule->dst_port_high),
                SSH_ENCODE_UINT32((SshUInt32) rule->src_port_low),
                SSH_ENCODE_UINT32((SshUInt32) rule->src_port_high),
                SSH_ENCODE_UINT32((SshUInt32) rule->selector_ifnum),
                SSH_ENCODE_UINT32((SshUInt32) rule->protocol),
                SSH_ENCODE_UINT32((SshUInt32) rule->ipproto),
                SSH_ENCODE_UINT32((SshUInt32) rule->type),

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
                SSH_ENCODE_UINT32((SshUInt32) rule->nat_selector_dst_port),
                SSH_ENCODE_UINT32_STR(nat_selector_ip_buf,
                nat_selector_ip_len),
#endif /* SSHDIST_IPSEC_FIREWALL */
                SSH_ENCODE_UINT32((SshUInt32) rule->nat_src_port),
                SSH_ENCODE_UINT32_STR(nat_src_ip_low_buf, nat_src_ip_low_len),
                SSH_ENCODE_UINT32_STR(nat_src_ip_high_buf, 
				      nat_src_ip_high_len),
                SSH_ENCODE_UINT32((SshUInt32) rule->nat_dst_port),
                SSH_ENCODE_UINT32_STR(nat_dst_ip_low_buf, nat_dst_ip_low_len),
                SSH_ENCODE_UINT32_STR(nat_dst_ip_high_buf, 
				      nat_dst_ip_high_len),
                SSH_ENCODE_UINT32((SshUInt32) rule->nat_flags),
#endif /* SSHDIST_IPSEC_NAT */

                SSH_ENCODE_UINT32(rule->transform_index),
                SSH_ENCODE_UINT32(rule->depends_on),
                SSH_ENCODE_UINT32(rule->flow_idle_session_timeout),
                SSH_ENCODE_UINT32(rule->flow_idle_datagram_timeout),
                SSH_ENCODE_UINT32(rule->flow_max_lifetime),

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                SSH_ENCODE_DATA((unsigned char *)rule->extension_selector_low,
		SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * sizeof(SshUInt32)),
                SSH_ENCODE_DATA((unsigned char *)rule->extension_selector_high,
		SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * sizeof(SshUInt32)),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

                SSH_ENCODE_UINT32_STR(
                (unsigned char *)&rule->policy_context,
		sizeof(rule->policy_context)),

                SSH_FORMAT_END);

  if (len == 0)
    *data_return = NULL;

  return len;
}


Boolean
ssh_pm_api_decode_policy_rule(const unsigned char *data, size_t data_len,
                              SshEnginePolicyRule rule)
{
  SshUInt32 flags;
  SshUInt32 selectors;
  SshUInt32 dst_port_low;
  SshUInt32 dst_port_high;
  SshUInt32 src_port_low;
  SshUInt32 src_port_high;
  SshUInt32 ifnum;
  SshUInt32 protocol;
  SshUInt32 ipproto;
  SshUInt32 type;
#ifdef SSHDIST_IPSEC_NAT
  SshUInt32 nat_src_port, nat_dst_port;
  SshUInt32 nat_flags;
  unsigned char *nat_src_ip_low, *nat_dst_ip_low;
  unsigned char *nat_src_ip_high, *nat_dst_ip_high;
  size_t nat_src_ip_low_len, nat_dst_ip_low_len;
  size_t nat_src_ip_high_len, nat_dst_ip_high_len;
#ifdef SSHDIST_IPSEC_FIREWALL
  SshUInt32 nat_selector_dst_port;
  unsigned char *nat_selector_dst_ip;
  size_t nat_selector_dst_ip_len;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
  unsigned char *policy_context;
  size_t policy_context_len;

  memset(rule, 0, sizeof(*rule));

  if (data_len == 0)
    return FALSE;

  if (ssh_decode_array(
                data, data_len,

                SSH_DECODE_UINT32(&rule->rule_index),
                SSH_DECODE_UINT32(&rule->precedence),
                SSH_DECODE_UINT32(&rule->tunnel_id),
                SSH_DECODE_DATA(rule->dst_ip_low, sizeof(rule->dst_ip_low)),
                SSH_DECODE_DATA(rule->dst_ip_high, sizeof(rule->dst_ip_high)),
                SSH_DECODE_DATA(rule->src_ip_low, sizeof(rule->src_ip_low)),
                SSH_DECODE_DATA(rule->src_ip_high, sizeof(rule->src_ip_high)),
                SSH_DECODE_UINT32(&flags),
                SSH_DECODE_UINT32(&selectors),
                SSH_DECODE_UINT32(&dst_port_low),
                SSH_DECODE_UINT32(&dst_port_high),
                SSH_DECODE_UINT32(&src_port_low),
                SSH_DECODE_UINT32(&src_port_high),
                SSH_DECODE_UINT32(&ifnum),
                SSH_DECODE_UINT32(&protocol),
                SSH_DECODE_UINT32(&ipproto),
                SSH_DECODE_UINT32(&type),
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
                SSH_DECODE_UINT32(&nat_selector_dst_port),
                SSH_DECODE_UINT32_STR_NOCOPY(
                &nat_selector_dst_ip, &nat_selector_dst_ip_len),
#endif /* SSHDIST_IPSEC_FIREWALL */

                SSH_DECODE_UINT32(&nat_src_port),
                SSH_DECODE_UINT32_STR_NOCOPY(&nat_src_ip_low, 
					     &nat_src_ip_low_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&nat_src_ip_high, 
					     &nat_src_ip_high_len),

                SSH_DECODE_UINT32(&nat_dst_port),
                SSH_DECODE_UINT32_STR_NOCOPY(&nat_dst_ip_low, 
					     &nat_dst_ip_low_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&nat_dst_ip_high, 
					     &nat_dst_ip_high_len),
                SSH_DECODE_UINT32(&nat_flags),

#endif /* SSHDIST_IPSEC_NAT */
                SSH_DECODE_UINT32(&rule->transform_index),
                SSH_DECODE_UINT32(&rule->depends_on),
                SSH_DECODE_UINT32(&rule->flow_idle_session_timeout),
                SSH_DECODE_UINT32(&rule->flow_idle_datagram_timeout),
                SSH_DECODE_UINT32(&rule->flow_max_lifetime),

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
		SSH_DECODE_DATA((unsigned char *)rule->extension_selector_low,
		SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * sizeof(SshUInt32)),
		SSH_DECODE_DATA((unsigned char *)rule->extension_selector_high,
		SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * sizeof(SshUInt32)),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

		SSH_DECODE_UINT32_STR_NOCOPY(
                &policy_context, &policy_context_len),

                SSH_FORMAT_END) != data_len)
    /* Malformed message or we run out of memory while decoding the
       packet. */
    return FALSE;

  /* Finalize engine rule. */

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  rule->nat_selector_dst_port = (SshUInt16)nat_selector_dst_port;
  ssh_decode_ipaddr_array(nat_selector_dst_ip, nat_selector_dst_ip_len,
                          &rule->nat_selector_dst_ip);
#endif /* SSHDIST_IPSEC_FIREWALL */

  rule->nat_src_port = (SshUInt16) nat_src_port;
  ssh_decode_ipaddr_array(nat_src_ip_low, nat_src_ip_low_len, 
			  &rule->nat_src_ip_low);
  ssh_decode_ipaddr_array(nat_src_ip_high, nat_src_ip_high_len, 
			  &rule->nat_src_ip_high);
  rule->nat_flags = (SshPmNatFlags) nat_flags;

  rule->nat_dst_port = (SshUInt16) nat_dst_port;
  ssh_decode_ipaddr_array(nat_dst_ip_low, nat_dst_ip_low_len, 
			  &rule->nat_dst_ip_low);
  ssh_decode_ipaddr_array(nat_dst_ip_high, nat_dst_ip_high_len, 
			  &rule->nat_dst_ip_high);

#endif /* SSHDIST_IPSEC_NAT */

  rule->flags = flags;
  rule->selectors = (SshUInt16) selectors;
  rule->dst_port_low = (SshUInt16) dst_port_low;
  rule->dst_port_high = (SshUInt16) dst_port_high;
  rule->src_port_low = (SshUInt16) src_port_low;
  rule->src_port_high = (SshUInt16) src_port_high;
  rule->selector_ifnum = (SshEngineIfnum) ifnum;
  rule->protocol = (SshUInt16) protocol;
  rule->ipproto = (SshUInt16) ipproto;
  rule->type = (SshUInt8) type;

  if (policy_context_len > sizeof(rule->policy_context))
    policy_context_len = sizeof(rule->policy_context);

  memcpy(&rule->policy_context, policy_context, policy_context_len);

  return TRUE;
}


size_t
ssh_pm_api_encode_transform_data(unsigned char **data_return,
                                 const SshEngineTransform tr)
{
  size_t len;
  unsigned char gw_addr[SSH_MAX_IPADDR_ENCODED_LENGTH]; 
  unsigned char own_addr[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t gw_addr_len, own_addr_len;
  unsigned char out_time[sizeof(SshTime)], in_time[sizeof(SshTime)];
  size_t time_len = sizeof(SshTime);
  SshEngineTransformData trd = &tr->data;
  SshEngineTransformControl c_trd = &tr->control;

  gw_addr_len = ssh_encode_ipaddr_array(gw_addr, sizeof(gw_addr),
                                        &trd->gw_addr);
  SSH_ASSERT(gw_addr_len != 0);

  own_addr_len = ssh_encode_ipaddr_array(own_addr, sizeof(own_addr),
                                         &trd->own_addr);
  SSH_ASSERT(own_addr_len != 0);

  ssh_pm_api_encode_time(in_time, time_len, trd->last_in_packet_time);
  ssh_pm_api_encode_time(out_time, time_len, trd->last_out_packet_time);

  len = ssh_encode_array_alloc(
                data_return,

                /* Transform data. */
                SSH_ENCODE_UINT32(trd->transform),
                SSH_ENCODE_UINT32_STR(gw_addr, gw_addr_len),
                SSH_ENCODE_UINT32_STR(own_addr, own_addr_len),
                SSH_ENCODE_UINT32((SshUInt32) trd->own_ifnum),
		/* IKE SA */
                SSH_ENCODE_UINT32((SshUInt32)c_trd->peer_handle),
#ifdef SSHDIST_L2TP
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_flags),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_local_port),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_remote_port),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_local_tunnel_id),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_local_session_id),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_remote_tunnel_id),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_remote_session_id),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_seq_ns),
                SSH_ENCODE_UINT32((SshUInt32) trd->l2tp_seq_nr),
#endif /* SSHDIST_L2TP */
                SSH_ENCODE_UINT32((SshUInt32) trd->local_port),
                SSH_ENCODE_UINT32((SshUInt32) trd->remote_port),
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
                SSH_ENCODE_UINT32((SshUInt32) trd->natt_flags),
                SSH_ENCODE_DATA(trd->natt_oa_l, sizeof(trd->natt_oa_l)),
                SSH_ENCODE_DATA(trd->natt_oa_r, sizeof(trd->natt_oa_r)),
                SSH_ENCODE_DATA(c_trd->peer_id, sizeof(c_trd->peer_id)),
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
                SSH_ENCODE_UINT32(trd->inbound_tunnel_id),
                SSH_ENCODE_UINT32(trd->spis[0]),
                SSH_ENCODE_UINT32(trd->spis[1]),
                SSH_ENCODE_UINT32(trd->spis[2]),
                SSH_ENCODE_UINT32(trd->spis[3]),
                SSH_ENCODE_UINT32(trd->spis[4]),
                SSH_ENCODE_UINT32(trd->spis[5]),
                SSH_ENCODE_DATA(trd->keymat, (size_t)SSH_IPSEC_MAX_KEYMAT_LEN),
                SSH_ENCODE_UINT32((SshUInt32) trd->packet_enlargement),
                SSH_ENCODE_UINT32((SshUInt32) trd->cipher_key_size),
                SSH_ENCODE_UINT32((SshUInt32) trd->cipher_iv_size),
                SSH_ENCODE_UINT32((SshUInt32) trd->cipher_nonce_size),
                SSH_ENCODE_UINT32((SshUInt32) trd->mac_key_size),
		SSH_ENCODE_UINT32(c_trd->control_flags),
                SSH_ENCODE_UINT32((SshUInt32)c_trd->tunnel_id),
		SSH_ENCODE_UINT32((SshUInt32)c_trd->outer_tunnel_id),
                SSH_ENCODE_UINT32_STR(in_time, time_len),
                SSH_ENCODE_UINT32_STR(out_time, time_len),
                SSH_ENCODE_UINT32(trd->out_packets_high),
                SSH_ENCODE_UINT32(trd->out_packets_low),
		SSH_ENCODE_DATA((const unsigned char *) trd->replay_mask,
				sizeof(trd->replay_mask)),
                SSH_ENCODE_UINT32(trd->replay_offset_high),
                SSH_ENCODE_UINT32(trd->replay_offset_low),
                SSH_ENCODE_UINT32(trd->old_spis[0]),
                SSH_ENCODE_UINT32(trd->old_spis[1]),
                SSH_ENCODE_UINT32(trd->old_spis[2]),
                SSH_ENCODE_UINT32(trd->old_spis[3]),
                SSH_ENCODE_UINT32(trd->old_spis[4]),
                SSH_ENCODE_UINT32(trd->old_spis[5]),
#ifdef SSH_IPSEC_TCPENCAP
		SSH_ENCODE_UINT32(trd->tcp_encaps_conn_id),
		SSH_ENCODE_DATA(
		(const unsigned char *) c_trd->tcp_encaps_conn_spi,
		sizeof(c_trd->tcp_encaps_conn_spi)),
#endif /* SSH_IPSEC_TCPENCAP */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
		SSH_ENCODE_UINT32((SshUInt32) trd->decapsulate_extension),
		SSH_ENCODE_DATA((const unsigned char *) trd->extension,
				sizeof(trd->extension)),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
		SSH_ENCODE_UINT32((SshUInt32) trd->df_bit_processing),
		SSH_ENCODE_UINT32((SshUInt32) trd->restart_after_tre),
		SSH_ENCODE_UINT32((SshUInt32) trd->nesting_level),
                SSH_FORMAT_END);

  if (len == 0)
    *data_return = NULL;

  return len;
}


Boolean
ssh_pm_api_decode_transform_data(const unsigned char *data,
                                 size_t data_len, SshEngineTransform tr)
{
  SshEngineTransformData trd;
  SshEngineTransformControl c_trd;
  unsigned char *gw_addr;
  size_t gw_addr_len;
  unsigned char *own_addr;
  size_t own_addr_len;
  unsigned char *in_time, *out_time;
  size_t in_time_len, out_time_len;
  SshUInt32 ifnum;
#ifdef SSHDIST_L2TP
  SshUInt32 l2tp_flags;
  SshUInt32 l2tp_local_port;
  SshUInt32 l2tp_remote_port;
  SshUInt32 l2tp_local_tunnel_id;
  SshUInt32 l2tp_local_session_id;
  SshUInt32 l2tp_remote_tunnel_id;
  SshUInt32 l2tp_remote_session_id;
  SshUInt32 l2tp_seq_ns;
  SshUInt32 l2tp_seq_nr;
#endif /* SSHDIST_L2TP */
  SshUInt32 local_port;
  SshUInt32 remote_port;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  SshUInt32 natt_flags;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  SshUInt32 packet_enlargement;
  SshUInt32 cipher_key_size;
  SshUInt32 cipher_iv_size;
  SshUInt32 cipher_nonce_size; /* for counter mode encryption */
  SshUInt32 mac_key_size;
  SshUInt32 tunnel_id;
  SshUInt32 outer_tunnel_id;
  SshUInt32 peer_handle;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 decapsulate_extension;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  SshUInt32 df_bit_processing;
  SshUInt32 restart_after_tre;
  SshUInt32 nesting_level;

  trd = &tr->data;
  c_trd = &tr->control;

  memset(tr, 0, sizeof(*tr));

  if (data_len == 0)
    return FALSE;

  if (ssh_decode_array(
                data, data_len,

                SSH_DECODE_UINT32(&trd->transform),
                SSH_DECODE_UINT32_STR_NOCOPY(&gw_addr, &gw_addr_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&own_addr, &own_addr_len),
                SSH_DECODE_UINT32(&ifnum),
                SSH_DECODE_UINT32(&peer_handle),
#ifdef SSHDIST_L2TP
                SSH_DECODE_UINT32(&l2tp_flags),
                SSH_DECODE_UINT32(&l2tp_local_port),
                SSH_DECODE_UINT32(&l2tp_remote_port),
                SSH_DECODE_UINT32(&l2tp_local_tunnel_id),
                SSH_DECODE_UINT32(&l2tp_local_session_id),
                SSH_DECODE_UINT32(&l2tp_remote_tunnel_id),
                SSH_DECODE_UINT32(&l2tp_remote_session_id),
                SSH_DECODE_UINT32(&l2tp_seq_ns),
                SSH_DECODE_UINT32(&l2tp_seq_nr),
#endif /* SSHDIST_L2TP */
                SSH_DECODE_UINT32(&local_port),
                SSH_DECODE_UINT32(&remote_port),
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
                SSH_DECODE_UINT32(&natt_flags),
                SSH_DECODE_DATA(trd->natt_oa_l, sizeof(trd->natt_oa_l)),
                SSH_DECODE_DATA(trd->natt_oa_r, sizeof(trd->natt_oa_r)),
                SSH_DECODE_DATA(c_trd->peer_id, sizeof(c_trd->peer_id)),
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
                SSH_DECODE_UINT32(&trd->inbound_tunnel_id),
                SSH_DECODE_UINT32(&trd->spis[0]),
                SSH_DECODE_UINT32(&trd->spis[1]),
                SSH_DECODE_UINT32(&trd->spis[2]),
                SSH_DECODE_UINT32(&trd->spis[3]),
                SSH_DECODE_UINT32(&trd->spis[4]),
                SSH_DECODE_UINT32(&trd->spis[5]),
                SSH_DECODE_DATA(trd->keymat, (size_t)SSH_IPSEC_MAX_KEYMAT_LEN),
		SSH_DECODE_UINT32(&packet_enlargement),
                SSH_DECODE_UINT32(&cipher_key_size),
                SSH_DECODE_UINT32(&cipher_iv_size),
                SSH_DECODE_UINT32(&cipher_nonce_size),
                SSH_DECODE_UINT32(&mac_key_size),
		SSH_DECODE_UINT32(&c_trd->control_flags),
                SSH_DECODE_UINT32(&tunnel_id),
                SSH_DECODE_UINT32(&outer_tunnel_id),
                SSH_DECODE_UINT32_STR_NOCOPY(&in_time, &in_time_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&out_time, &out_time_len),
                SSH_DECODE_UINT32(&trd->out_packets_high),
                SSH_DECODE_UINT32(&trd->out_packets_low),
                SSH_DECODE_DATA((unsigned char *) trd->replay_mask,
				sizeof(trd->replay_mask)),
                SSH_DECODE_UINT32(&trd->replay_offset_high),
                SSH_DECODE_UINT32(&trd->replay_offset_low),
                SSH_DECODE_UINT32(&trd->old_spis[0]),
                SSH_DECODE_UINT32(&trd->old_spis[1]),
                SSH_DECODE_UINT32(&trd->old_spis[2]),
                SSH_DECODE_UINT32(&trd->old_spis[3]),
                SSH_DECODE_UINT32(&trd->old_spis[4]),
                SSH_DECODE_UINT32(&trd->old_spis[5]),
#ifdef SSH_IPSEC_TCPENCAP
		SSH_DECODE_UINT32(&trd->tcp_encaps_conn_id),
		SSH_DECODE_DATA(c_trd->tcp_encaps_conn_spi,
				sizeof(c_trd->tcp_encaps_conn_spi)),
#endif /* SSH_IPSEC_TCPENCAP */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
		SSH_DECODE_UINT32(&decapsulate_extension),
		SSH_DECODE_DATA((unsigned char *) trd->extension,
				sizeof(trd->extension)),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
		SSH_DECODE_UINT32(&df_bit_processing),
		SSH_DECODE_UINT32(&restart_after_tre),
		SSH_DECODE_UINT32(&nesting_level),
                SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Finalize transform data. */

  ssh_decode_ipaddr_array(gw_addr, gw_addr_len, &trd->gw_addr);
  ssh_decode_ipaddr_array(own_addr, own_addr_len, &trd->own_addr);

  trd->last_in_packet_time = ssh_pm_api_decode_time(in_time, in_time_len);
  trd->last_out_packet_time = ssh_pm_api_decode_time(out_time, out_time_len);

  trd->own_ifnum = (SshEngineIfnum) ifnum;
#ifdef SSHDIST_L2TP
  trd->l2tp_flags = (SshUInt8) l2tp_flags;
  trd->l2tp_local_port = (SshUInt16) l2tp_local_port;
  trd->l2tp_remote_port = (SshUInt16) l2tp_remote_port;
  trd->l2tp_local_tunnel_id = (SshUInt16) l2tp_local_tunnel_id;
  trd->l2tp_local_session_id = (SshUInt16) l2tp_local_session_id;
  trd->l2tp_remote_tunnel_id = (SshUInt16) l2tp_remote_tunnel_id;
  trd->l2tp_remote_session_id = (SshUInt16) l2tp_remote_session_id;
  trd->l2tp_seq_ns = (SshUInt16) l2tp_seq_ns;
  trd->l2tp_seq_nr = (SshUInt16) l2tp_seq_nr;
#endif /* SSHDIST_L2TP */
  trd->local_port = (SshUInt16)local_port;
  trd->remote_port = (SshUInt16) remote_port;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  trd->natt_flags = (SshUInt8) natt_flags;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  trd->packet_enlargement = (SshUInt8) packet_enlargement;
  trd->cipher_key_size = (SshUInt8) cipher_key_size;
  trd->cipher_iv_size = (SshUInt8) cipher_iv_size;
  trd->cipher_nonce_size = (SshUInt8) cipher_nonce_size;
  trd->mac_key_size = (SshUInt8) mac_key_size;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if (decapsulate_extension)
    trd->decapsulate_extension = 1;
  else
    trd->decapsulate_extension = 0;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  trd->df_bit_processing = (SshUInt8)df_bit_processing;
  trd->restart_after_tre = (restart_after_tre != 0 ? 1 : 0);
  trd->nesting_level = (SshUInt8) nesting_level;

  c_trd->peer_handle = peer_handle;
  c_trd->tunnel_id = tunnel_id;
  c_trd->outer_tunnel_id = outer_tunnel_id;

  return TRUE;
}


void
ssh_pm_api_encode_uint64(unsigned char buf[8], SshUInt64 value)
{
  SSH_PUT_32BIT(buf, (SshUInt32)((value >> 32) & 0xffffffff));
  SSH_PUT_32BIT(buf + 4, (SshUInt32)(value & 0xffffffff));
}


SshUInt64
ssh_pm_api_decode_uint64(unsigned char buf[8])
{
  SshUInt64 value;

  value = SSH_GET_32BIT(buf);
  value <<= 32;
  value |= SSH_GET_32BIT(buf + 4);

  return value;
}

void ssh_pm_api_encode_time(unsigned char *buf, size_t len, SshTime t)
{
  if (len == 4)
    SSH_PUT_32BIT(buf, (SshUInt32) t);
  else
    {
      ssh_pm_api_encode_uint64(buf, t);
    }
}

SshTime ssh_pm_api_decode_time(unsigned char *buf, size_t len)
{
  if (len == 4)
    return (SshTime)SSH_GET_32BIT(buf);
  else
    return ssh_pm_api_decode_uint64(buf);
}
