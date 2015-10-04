/*
 * rac_virtual_ip_st.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2005, 2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * The virtual IP thread handling obtaining, using, and releasing
 * virtual IP addresses.
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "util_nameserver.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

#define SSH_DEBUG_MODULE "SshPmStVirtualIp"

/************************** Static help functions ***************************/

#ifdef WINDOWS
#ifndef _WIN32_WCE
static __inline
int get_windows_version()
{
  OSVERSIONINFO os;
  int winver;
  
  memset(&os, 0, sizeof(os));

  os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
  
  GetVersionEx(&os);
  
  winver = os.dwMajorVersion;
  
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Windows major version: %d", 
                               winver));
  
  if (winver == 5 || winver == 6)
    return winver;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown Windows major version: %d", 
                             winver));
      return 0;
    }
}
#endif /* _WIN32_WCE */
#endif /* WINDOWS */

static Boolean
ssh_pm_vip_register(SshPmVip vip)
{
#if defined(WIN32_PLATFORM_WFSP)
  const WCHAR internet[] = L"{436EF144-B4FB-4863-A041-8F905A62C572}";
  HKEY provider_key = NULL, adapter_key = NULL;
  BYTE destid_value[sizeof internet];
  DWORD destid_size;
  const char *base_name;
  WCHAR adapter_name[SSH_INTERCEPTOR_IFNAME_SIZE];
  LONG error;
  Boolean status = FALSE;

  /* The following is a workaround for Windows Mobile Standard. When
     the virtual adapter comes up, Windows Mobile Connection Manager
     sees it as an ethernet interface and assigns it to the 'Work' or
     'Internet' meta-network. WM Professional pops up a dialog that
     allows the user to select, however WM Standard silently assigns
     the adapter to the 'Work' meta-network which is not what we
     want. Ideally, we should be able to configure the desired
     meta-network, i.e. 'Internet', using provisioning XML included in
     the .CAB installation file. However, the destination meta-network
     configured using provisioning XML always gets overwritten by the
     WM Standard connection manager when the adapter comes up. There
     seems to be some weird hard-coding in the WM Std connection
     manager that forces the adapter to the 'Work' network. This
     workaround patches the destination network in registry _after_
     the adapter has come up and has been assigned by the connection
     manager. If there is a way to do this with provisioning XML
     Microsoft obviously does not want anybody to know about it. */

  /* Open the key for the adapter under the CM_NetEntries branch, e.g.
     HKLM\Comm\ConnMgr\Providers\
     {f792e23c-dc19-4668-9be4-f8688b4c18d6}\QSVNIC1. */

  if (RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        L"Comm\\ConnMgr\\Providers\\"
        L"{f792e23c-dc19-4668-9be4-f8688b4c18d6}",
        0, 0, &provider_key) != ERROR_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot open provider key"));
      goto end;
    }

  /* Skip backslash-separated adapter name prefix and leave only the
     base name, e.g. QSVNIC1. */
  if ((base_name = strchr(vip->adapter_name, '\\')))
    base_name++;
  else
    base_name = vip->adapter_name;

  _snwprintf(adapter_name, sizeof adapter_name / sizeof adapter_name[0],
             L"%hs", base_name);
  adapter_name[sizeof adapter_name / sizeof adapter_name[0] - 1] = L'\0';

  if (RegOpenKeyEx(provider_key, adapter_name, 0, 0, &adapter_key) !=
      ERROR_SUCCESS)
    {
      /* Adapter key probably not yet created by ConnMgr, keep
         trying. */
      SSH_DEBUG_HEXDUMP(
        SSH_D_NICETOKNOW, ("Cannot open adapter key, adapter name:"),
        (const unsigned char *)adapter_name,
        wcslen(adapter_name) * sizeof adapter_name[0]);
      goto end;
    }

  /* Get the value DestId in the key. */

  destid_size = sizeof destid_value;
  if ((error = RegQueryValueEx(
         adapter_key, L"DestId", NULL, NULL, destid_value, &destid_size)) !=
      ERROR_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("DestId value not found (%08X)", (unsigned)error));
      goto end;
    }

  /* Change DestId to the GUID corresponding to the destination
     network 'The Internet' if it is something different. */

  if (destid_size != sizeof internet)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Bad DestId value"));
      goto end;
    }

  if (!memcmp(destid_value, internet, destid_size))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("DestId is good, not changing"));
    }
  else if (RegSetValueEx(
             adapter_key, L"DestId", 0, REG_SZ,
             (BYTE *)internet, sizeof internet) != ERROR_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("DestId update failed"));
      goto end;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("DestId updated"));
    }

  status = TRUE;

 end:
  if (adapter_key)
    RegCloseKey(adapter_key);
  if (provider_key)
    RegCloseKey(provider_key);

  return status;
#else /* defined(WIN32_PLATFORM_WFSP) */
  return TRUE;
#endif /* defined(WIN32_PLATFORM_WFSP) */
}

static
void ssh_pm_copy_without_mask(SshIpAddr dst, const SshIpAddr src)
{
  *dst = *src;

  if (SSH_IP_IS4(dst))
    dst->mask_len = 32;
  else
    dst->mask_len = 128;
}

static SshPmVirtualAdapter
ssh_pm_virtual_adapter_find_byname(SshPm pm, unsigned char *name)
{
  SshUInt32 i;

  for (i = 0; i < pm->num_virtual_adapters; i++)
    if (strcmp(name, pm->virtual_adapters[i].adapter_name) == 0)
      return &pm->virtual_adapters[i];

  return NULL;
}

static SshPmVirtualAdapter
ssh_pm_virtual_adapter_find_unused(SshPm pm)
{
  SshUInt32 i;

  for (i = 0; i < pm->num_virtual_adapters; i++)
    if (!pm->virtual_adapters[i].reserved
	&& !pm->virtual_adapters[i].in_use)
      return &pm->virtual_adapters[i];
  
  return NULL;
}

/* Adds the rule to the list of rules maintained by the Vip record.
   Returns TRUE if the rule was not in the list and was sucessfully
   added. In all other conditions returns FALSE. */
static Boolean
ssh_pm_vip_add_rule(SshPm pm, SshPmVip vip, SshPmRule rule)
{
  SshPmVipRule vrule;
#ifdef SSHDIST_L2TP
  SshIkev2PayloadTS ts;
  SshUInt32 i;
#endif /* SSHDIST_L2TP */

  for (vrule = vip->rules; vrule != NULL; vrule = vrule->next)
    {
      if (vrule->rule == rule)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Rule already added to virtual IP object"));
	  return FALSE;
	}
    }

  vrule = ssh_calloc(1, sizeof (*vrule));
  if (vrule == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory adding rule to virtual IP"));
      return FALSE;
    }

  SSH_PM_RULE_LOCK(rule);
  vrule->rule = rule;

  vrule->next = vip->rules;
  vip->rules = vrule;

#ifdef SSHDIST_L2TP
  if (vrule->rule->side_to.tunnel->flags & SSH_PM_TI_L2TP)
    {
      ts = vrule->rule->side_to.ts;
      /* Create VIP route entries from rule destinations. */
      for (i = 0; i < ts->number_of_items_used; i++)
        ssh_pm_vip_create_rule_route(vip, &ts->items[i], rule);
      /* Signal the VIP thread to update the routing table. */
      vip->add_routes = 1;
    }
#endif /* SSHDIST_L2TP */

  SSH_DEBUG(SSH_D_LOWOK, ("Rule %u added to VIP", (unsigned)rule->rule_id));
  return TRUE;
}

static Boolean
ssh_pm_vip_remove_deleted_rules(SshPm pm, SshPmVip vip)
{
  SshPmVipRule vrule;
#ifdef SSHDIST_L2TP
  SshUInt32 i;
#endif /* SSHDIST_L2TP */

  for (vrule = vip->rules; vrule; vrule = vrule->next)
    {
      if (vrule->rule->flags & SSH_PM_RULE_I_DELETED)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Removing rule %u from VIP",
                                  (unsigned)vrule->rule->rule_id));
	  
#ifdef SSHDIST_L2TP
          /* Mark associated routes for removal. */
          for (i = 0; i < vip->num_routes; i++)
            {
              if (vip->routes[i].rule == vrule->rule)
                {
                  vip->routes[i].remove = 1;
                  vip->routes[i].clear = 1;
                  vip->routes[i].rule = NULL;
                  vip->remove_routes = 1;
                }
            }
#endif /* SSHDIST_L2TP */
	}
    }

  /* Check if all rules were removed. */
  for (vrule = vip->rules; vrule; vrule = vrule->next)
    {
      if ((vrule->rule->flags & SSH_PM_RULE_I_DELETED) == 0)
	return FALSE;
    }

  return TRUE;
}

/************************* Thread startup/shutdown **************************/

/* Destructor callback for virtual IP thread. */
static void
ssh_pm_vip_thread_destructor(SshFSM fsm, void *context)
{
  SshPmVip vip = (SshPmVip) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);

  ssh_pm_vip_free(pm, vip);
}

Boolean
ssh_pm_use_virtual_ip(SshPm pm, SshPmTunnel tunnel, SshPmRule rule)
{
  SshPmVip vip;
  SshPmVirtualAdapter adapter;

  if (!tunnel || !SSH_PM_TUNNEL_IS_VIRTUAL_IP(tunnel))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Bad tunnel for virtual IP"));
      return FALSE;
    }

  if (!rule || !SSH_PM_RULE_IS_VIRTUAL_IP(rule))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Bad rule for virtual IP"));
      return FALSE;
    }

  if (tunnel->vip)
    {
      if (tunnel->vip->unusable)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Virtual IP is unusable"));
          return FALSE;
        }
      else
        {
          if (!ssh_pm_vip_add_rule(pm, tunnel->vip, rule))
            return FALSE;

          /* If routes were added, wake up the VIP thread. */
          if (tunnel->vip->add_routes)
            ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);

          return TRUE;
        }
    }

  /* Find a virtual adapter. */
  if (strlen(tunnel->vip_name) > 0)
    {
      adapter = ssh_pm_virtual_adapter_find_byname(pm, tunnel->vip_name);
      if (adapter == NULL)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter '%s' not available",
				 tunnel->vip_name));
	  return FALSE;
	}
      else if (adapter->in_use)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter '%s' is in use",
				 tunnel->vip_name));      
	  return FALSE;
	}
    }
  else
    {
      adapter = ssh_pm_virtual_adapter_find_unused(pm);
      if (adapter == NULL)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("No virtual adapters available for use"));
	  return FALSE;
	}
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting virtual IP thread for rule `%@'",
			     ssh_pm_rule_render, rule));

  /* Allocate vip object. */
  vip = ssh_pm_vip_alloc(pm);
  if (vip == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Could not allocate memory for Virtual IP thread"));
      return FALSE;
    }

  vip->pm = pm;

  /* Attach vip object to tunnel. */
  tunnel->vip = vip;
  
  /* Attach virtual adapter to vip object. */
  vip->adapter_ifnum = adapter->adapter_ifnum;
  adapter->in_use = TRUE;

  /* Mark VIP initially unusable. */
  vip->unusable = 1;
  vip->successful = 0;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  if (tunnel->flags & SSH_PM_TI_CFGMODE)
    vip->t_cfgmode = 1;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_L2TP 
  if (tunnel->flags & SSH_PM_TI_L2TP)
    vip->t_l2tp = 1;
#endif /* SSHDIST_L2TP */

  if (!ssh_pm_vip_add_rule(pm, vip, rule))
    {
      tunnel->vip = NULL;
      ssh_free(vip);
      return FALSE;
    }

  /* Initialize VIP condition */
  ssh_fsm_condition_init(&pm->fsm, &vip->cond);

  /* Start a new PM subthread to handle virtual adapter lifecycle. */
  pm->mt_num_sub_threads++;
  ssh_fsm_thread_init(&pm->fsm, &vip->thread, ssh_pm_st_vip_start,
		      NULL_FNPTR, ssh_pm_vip_thread_destructor, vip);
  ssh_fsm_set_thread_name(&vip->thread, "VIP");
  return TRUE;
}

void
ssh_pm_stop_virtual_ip(SshPm pm, SshPmTunnel tunnel)
{
  SSH_ASSERT(tunnel->vip->refcnt == 0);

  SSH_DEBUG(SSH_D_LOWSTART, ("Stopping virtual IP thread for tunnel %p",
			     (void *)tunnel));

  /* Mark vip unusable. */
  tunnel->vip->unusable = 1;

  /* Signal vip thread to start shutdown. */
  tunnel->vip->shutdown = 1;
  ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
}

/********************* Common virtual IP thread states **********************/

SSH_FSM_STEP(ssh_pm_st_vip_start)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Starting virtual IP setup."));

  /* Resolve tunnels. Take one tunnel reference for the 
     vip object for the duration of vip setup. Store tunnel_id for vip
     shutdown. L2TP vip does not take any references. */
  vip->tunnel = vip->rules->rule->side_to.tunnel;
  SSH_ASSERT(vip->tunnel != NULL);
  SSH_ASSERT(SSH_PM_TUNNEL_IS_VIRTUAL_IP(vip->tunnel));
  SSH_PM_TUNNEL_TAKE_REF(vip->tunnel); 

#ifdef SSHDIST_ISAKMP_CFG_MODE
  if (vip->t_cfgmode)
    {
      SSH_ASSERT(vip->t_l2tp == 0);
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_cfgmode);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_L2TP
  if (vip->t_l2tp)
    {
      SSH_ASSERT(vip->t_cfgmode == 0);
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_L2TP */

  SSH_DEBUG(SSH_D_FAIL, ("No virtual IP method selected."));
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Checking vip remote access attributes."));

  /* Check if PM is shutting down. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Try next virtual IP method if attribute retrieval failed. */
  if (vip->successful == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Virtual IP failed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Attributes retrieved, proceed. */
  SSH_ASSERT(vip->attrs.num_addresses >= 1);
  SSH_ASSERT(SSH_IP_DEFINED(&vip->attrs.addresses[0]));
  SSH_ASSERT(SSH_IP_DEFINED(&vip->sgw));

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_select_addresses);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_select_addresses)
{
  SshPmVip vip = (SshPmVip) thread_context;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDOK, ("Selecting virtual IP addresses."));

  /* Sanity check addresses and select only those IPv4 and IPv6 addresses
     that are valid. Note that we do not check the rules here, but we add
     both IPv4 and IPv6 addresses eventhough there might only be a rule for
     one IP address version. */
  if (vip->attrs.num_addresses < 1)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_ERROR,
		    "No address received from the RAS.");
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  if (vip->attrs.num_subnets > SSH_PM_VIRTUAL_IP_MAX_ROUTES)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_ERROR,
		    "RAS sent too many sub-networks.");
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(vip->attrs.num_addresses <= 
	     SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES);

  vip->num_selected_addresses = 0;
  for (i = 0; i < vip->attrs.num_addresses; i++)
    {
      if (SSH_IP_DEFINED(&vip->attrs.addresses[i])
	  && !SSH_IP_IS_NULLADDR(&vip->attrs.addresses[i])
	  && !SSH_IP_IS_BROADCAST(&vip->attrs.addresses[i])
	  && !SSH_IP_IS_MULTICAST(&vip->attrs.addresses[i])
	  && !SSH_IP_IS_LOOPBACK(&vip->attrs.addresses[i])
	  && !SSH_IP6_IS_LINK_LOCAL(&vip->attrs.addresses[i]))
	{
	  SshIpAddr addr =
	    &vip->selected_address[vip->num_selected_addresses++];
	  
	  *addr = vip->attrs.addresses[i];
          
          if (SSH_IP_IS4(addr) && addr->mask_len == 0)
            {
              /* If we receive a 0 network mask we recalculate the
                 mask length based on RFC791. */
              unsigned char byte1;
              byte1 = SSH_IP4_BYTE1(addr);
              
              SSH_DEBUG(SSH_D_UNCOMMON, ("Received invalid netmask "
                                         "value: %d. Calculating new "
                                         "value according to the "
                                         "RFC 791.", addr->mask_len));
              
              ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_WARNING,
                            "");
              ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_WARNING,
                            "Received invalid netmask for the Virtual "
                            "Interface: %d.", 
                            addr->mask_len);
              
              if (byte1 < 0x80) /* 128.0.0.0 */
                addr->mask_len = 8;
              else if (byte1 < 0xC0) /* 192.0.0.0 */
                addr->mask_len = 16;
              else
                addr->mask_len = 24;
              
              ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_WARNING,
                            "Calculating netmask according to the "
                            "RFC 791, new netmask: %d.",
                            addr->mask_len);
              ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_WARNING,
                            "");
            }
#ifdef WINDOWS
#ifndef _WIN32_WCE
          if (SSH_IP_IS4(addr) && addr->mask_len == 32 &&
			  get_windows_version() < 6)
            {
              /* On Windows, shrink a netmask of 32 bits to 31 bits
                 beccause some Windows versions do not accept a 32-bit
                 mask for a LAN interface which the virtual IP
                 interface pretends to be. This may unfortunately
                 cause minor trouble in configurations where the mask
                 really should be 32 (e.g. L2TP). */
              ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_WARNING,
                            "Adjusting netmask from 32 to 31 bits.");
              ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_WARNING,
                            "");
              addr->mask_len = 31;
            }
#endif /* _WIN32_WCE */
#endif /* WINDOWS */
        }
      else
	{
	  SSH_DEBUG(SSH_D_LOWOK,
		    ("Ignoring address %@",
		     ssh_ipaddr_render, &vip->attrs.addresses[i]));
	}
    }

  if (vip->num_selected_addresses == 0)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_ERROR,
		    "No usable address received from the RAS.");
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }
  
#ifdef DEBUG_LIGHT
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Got %d virtual IPs with `%s':",
			       vip->attrs.num_addresses,
                               (vip->t_cfgmode
                                ? "CFGMODE"
                                : "L2TP")));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Selected %d virtual IPs", 
			       (int) vip->num_selected_addresses));

  for (i = 0; i < vip->num_selected_addresses; i++)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("  IP: %@",
				 ssh_ipaddr_render, 
				 &vip->selected_address[i]));

  for (i = 0; i < vip->attrs.num_dns; i++)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("  DNS: %@",
                                 ssh_ipaddr_render, &vip->attrs.dns[i]));

  for (i = 0; i < vip->attrs.num_wins; i++)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("  WINS: %@",
                                 ssh_ipaddr_render, &vip->attrs.wins[i]));

  for (i = 0; i < vip->attrs.num_dhcp; i++)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("  DHCP: %@",
                                 ssh_ipaddr_render, &vip->attrs.dhcp[i]));

  for (i = 0; i < vip->attrs.num_subnets; i++)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("  Sub-network: %@",
                                 ssh_ipaddr_render, &vip->attrs.subnets[i]));
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_sgw_route);
  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_vip_sgw_route_status_cb(SshPm pm, SshUInt32 flags,
			       SshUInt32 ifnum, 
			       const SshIpAddr next_hop,
			       size_t mtu, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if ((flags & SSH_PME_ROUTE_REACHABLE))
    {
      vip->sgw_next_hop = *next_hop;
      vip->sgw_ifnum = ifnum;
      vip->sgw_mtu = mtu;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_get_sgw_route)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshInterceptorRouteKeyStruct key;

  SSH_DEBUG(SSH_D_MIDOK, ("Performing SGW route lookup."));

  ssh_pm_create_route_key(pm, &key, NULL, &vip->sgw, 0, 0, 0,
                          SSH_INVALID_IFNUM);

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_sgw_route_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_route(pm->engine,
				   0,
                                   &key,
				   ssh_pm_vip_sgw_route_status_cb,
				   thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_sgw_route_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  if (!SSH_IP_DEFINED(&vip->sgw_next_hop))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get route to sgw '%@'",
			     ssh_ipaddr_render, &vip->sgw));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_MIDOK,
	    ("SGW route result: '%@' nexthop '%@' ifnum %d mtu %d",
	     ssh_ipaddr_render, &vip->sgw,
	     ssh_ipaddr_render, &vip->sgw_next_hop,
	     (int) vip->sgw_ifnum, (int) vip->sgw_ifnum));

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_sgw_route);
  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_vip_sgw_route_add_success_cb(SshPm pm, 
				    SshInterceptorRouteError error,
				    void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (error == SSH_INTERCEPTOR_ROUTE_ERROR_OK)
    vip->sgw_route_added = 1;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_add_sgw_route)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshInterceptorRouteKeyStruct key;
  SshIpAddr addr;
  SshUInt32 ifnum;

  /* If next hop returned by route lookup is the SGW itself then SGW
     is either directly connected or there is no gateway, i.e. the route
     points to an interface. */
  if (SSH_IP_EQUAL(&vip->sgw_next_hop, &vip->sgw))
    {
      /* Skip adding route if SGW is directly connected. */
      if (ssh_pm_find_interface_by_address_prefix(pm,
                                                  &vip->sgw_next_hop,
                                                  NULL))
        {
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_configure_interface_up);
          return SSH_FSM_CONTINUE;
        }
      /* In case of an interface-only route, use (some) address of the
         interface as the gateway address. */
      addr = ssh_pm_find_interface_address(pm, vip->sgw_ifnum,
                                           SSH_IP_IS6(&vip->sgw), NULL);
      if (!addr) {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to add host route to peer"));
        SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
        return SSH_FSM_CONTINUE;
      }
      vip->sgw_next_hop = *addr;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Adding virtual IP SGW route."));

  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);
  SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(&key, &vip->sgw);

  /* Specify interface if SGW next hop is IPv6 link local. */
  if (SSH_IP6_IS_LINK_LOCAL(&vip->sgw_next_hop))
    ifnum = vip->sgw_ifnum;
  else
    ifnum = SSH_INVALID_IFNUM;

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_sgw_route_result);

  /* Create a gateway route. */
  SSH_FSM_ASYNC_CALL(ssh_pm_route_add(pm,
				      &key,
				      &vip->sgw_next_hop,
				      ifnum,
				      SSH_ROUTE_PREC_HIGHEST,
				      0, /* flags */
				      ssh_pm_vip_sgw_route_add_success_cb,
				      thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_add_sgw_route_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP SGW route addition completed."));

  if (!vip->sgw_route_added)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to add host route to peer"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Added host route to peer"));
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_configure_interface_up);
  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_virtual_adapter_configure_up_cb(SshPm pm,
				       SshVirtualAdapterError error,
				       SshUInt32 num_adapters,
				       SshPmeVirtualAdapter adapters,
				       void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = ssh_fsm_get_tdata(thread);

  if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK)
    {
      SSH_ASSERT(num_adapters == 1);
      SSH_ASSERT(adapters != NULL);
      vip->adapter_configured = 1;
      vip->adapter_ifnum = adapters[0].adapter_ifnum;
      ssh_snprintf(vip->adapter_name, sizeof(vip->adapter_name),
                   "%s", adapters[0].adapter_name);
      
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL, "");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
		    "Virtual IP interface %s configured up", 
		    vip->adapter_name);
    }
  else
    {
      vip->adapter_configured = 0;
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_ERROR, 
		    ("Error - Failed to configure Virtual Adapter up"));
      SSH_DEBUG(SSH_D_FAIL, 
		("Virtual adapter %d configuration failed: %d",
		 (int) vip->adapter_ifnum, error));
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_configure_interface_up)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshVirtualAdapterParamsStruct params;
  Boolean params_set = FALSE;
  Boolean selected_has_ipv6;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDOK, ("Configuring virtual adapter up."));

  /** Check if we selected any IPv6 addresses. */
  selected_has_ipv6 = FALSE;
  for (i = 0; i < vip->num_selected_addresses; i++)
    {
      if (SSH_IP_IS6(&vip->selected_address[i]))
	{
	  selected_has_ipv6 = TRUE;
	  break;
	}
    }

  /* Fill in virtual adapter parameters. */
  memset(&params, 0, sizeof(params));

  /* Calculate mtu for virtual adapter. */
  if (vip->sgw_mtu)
    {



      params.mtu = vip->sgw_mtu - 100;
      if (selected_has_ipv6 && params.mtu < 1280)
	params.mtu = 1280;
      if (params.mtu < 576)
	params.mtu = 576;
      if (params.mtu > 1500)
	params.mtu = 1500;
      params_set = TRUE;
    }

  params.dns_ip_count = vip->attrs.num_dns;
  params.dns_ip = vip->attrs.dns;

  params.wins_ip_count = vip->attrs.num_wins;
  params.wins_ip = vip->attrs.wins;

  if (params.dns_ip_count || params.wins_ip_count)
    params_set = TRUE;

  /** Create virtual adapter. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Configuring virtual adapter %d [%s] up",
			     (int) vip->adapter_ifnum, vip->adapter_name));
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_configure_interface_up_result);
  SSH_FSM_ASYNC_CALL({
    ssh_pm_virtual_adapter_configure(pm,
				     vip->adapter_ifnum,
				     SSH_VIRTUAL_ADAPTER_STATE_UP,
				     vip->num_selected_addresses,
				     vip->selected_address,
				     (params_set ? &params : NULL),
				     ssh_pm_virtual_adapter_configure_up_cb,
				     thread);
  });
  SSH_NOTREACHED;
}

static void
ssh_pm_vip_wait_timeout_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  /* Mark that timeout occured while the thread was waiting for
     'pm->main_thread_cond'. */
  vip->timeout = 1;
  
  /* Continue VIP thread. This will remove the thread from 
     the condition variable's waiter list. */
  ssh_fsm_continue(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_configure_interface_up_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual adapter configuration completed."));

  if (vip->adapter_configured)
    {
      SSH_DEBUG(SSH_D_HIGHOK, 
		("Virtual adapter %d [%s] configured up.",
		 (int) vip->adapter_ifnum, vip->adapter_name));
      
      /* Wait until we receive an interface notification containing
         information about the virtual adapter. */
      vip->timeout = 0;
      ssh_register_timeout(&vip->timeout_struct, 5, 0, 
			   ssh_pm_vip_wait_timeout_cb, thread);

      /** Wait interface notification. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_wait_interface_up);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter configure failed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_wait_interface_up)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Waiting for virtual adapter to come online."));

  /* Is the virtual adapter already reported as an interface? */
  if (ssh_pm_find_interface_by_ifnum(pm, vip->adapter_ifnum))
    {
      /* Interface reported.  Cancel the timeout. */
      ssh_cancel_timeout(&vip->timeout_struct);

      /** Interface reported. */
      SSH_DEBUG(SSH_D_HIGHOK, ("Virtual adapter %d [%s] up",
			       (int) vip->adapter_ifnum,
			       vip->adapter_name));
      if (vip->reconfigure)
        {
          vip->add_routes_next = ssh_pm_st_vip_established;
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_routes);
        }
      else
        {
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_create_routes);
        }
      return SSH_FSM_CONTINUE;
    }

  /* Has the operation timed out? */
  if (vip->timeout)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter %d [%s] did not come online",
			     (int) vip->adapter_ifnum,
			     vip->adapter_name));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Wait for interface report. */
  SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
}

SSH_FSM_STEP(ssh_pm_st_vip_create_routes)
{
  SshPmVip vip = (SshPmVip) thread_context;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDOK, ("Creating virtual IP routes."));

  /* Create routes for subnets. */
  for (i = 0; i < vip->attrs.num_subnets; i++)
    ssh_pm_vip_create_subnet_route(vip, &vip->attrs.subnets[i]);

  vip->add_routes_next = ssh_pm_st_vip_add_name_servers;
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_routes);
  return SSH_FSM_CONTINUE;
}

void
ssh_pm_vip_route_add_success_cb(SshPm pm,
				SshInterceptorRouteError error,
				void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (error == SSH_INTERCEPTOR_ROUTE_ERROR_OK)
    vip->routes[vip->index].added = 1;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_add_routes)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshPmVipRoute route = NULL;
  SshInterceptorRouteKeyStruct key;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDOK, ("Adding virtual IP routes."));

  if (vip->add_routes)
    vip->add_routes = 0;

  for (; vip->index < vip->num_routes; vip->index++)
    {
      route = &vip->routes[vip->index];
      /* Skip invalidated routes. */
      if (!SSH_IP_DEFINED(&route->prefix))
	continue;

#ifdef _WIN32_WCE
      if (SSH_IP_IS4(&route->prefix))
#endif /* _WIN32_WCE */
        {
          /* If route matches the network part of any VIP address skip it. */
          for (i = 0; i < vip->num_selected_addresses; i++)
            if (SSH_IP_MASK_EQUAL(&route->prefix, &vip->selected_address[i]))
              break;
          if (i < vip->num_selected_addresses)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Route to %@ is not needed because "
                         "network directly connected",
                         ssh_ipaddr_render, &route->prefix));
              continue;
            }
        }

      if (route->added == 0)
	break;
      
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Route to network %@ is already added",
				   ssh_ipaddr_render, &route->prefix));
    }
  if (vip->index >= vip->num_routes)
    {
      vip->index = 0;
      SSH_FSM_SET_NEXT(vip->add_routes_next);
      return SSH_FSM_CONTINUE;
    }
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(route->added == 0);

  /** Check that the route has not been invalidated after creation. */
  if (!SSH_IP_DEFINED(&route->prefix))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Skipping invalid route %d", vip->index));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_routes);
      return SSH_FSM_CONTINUE;
    }

  /** Set route next hop. */
  for (i = 0; i < vip->num_selected_addresses; i++)
    {
      if ((SSH_IP_IS4(&route->prefix) &&
           SSH_IP_IS4(&vip->selected_address[i])) ||
          (SSH_IP_IS6(&route->prefix) &&
           SSH_IP_IS6(&vip->selected_address[i])))
        {
          ssh_pm_copy_without_mask(&route->nexthop, &vip->selected_address[i]);
          break;
        }
    }
  if (i == vip->num_selected_addresses)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Could not find route nexthop for dst %@",
                 ssh_ipaddr_render, &route->prefix));
      vip->index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  /** Add route. */
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adding route %d to network %@ via %@",
	     (int) vip->index,
             ssh_ipaddr_render, &route->prefix,
             ssh_ipaddr_render, &route->nexthop));

  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);
  SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(&key, &route->prefix);

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_routes_result);
  SSH_FSM_ASYNC_CALL({
    ssh_pm_route_add(pm,
                     &key,
                     &route->nexthop,
                     SSH_INVALID_IFNUM,
                     SSH_ROUTE_PREC_ABOVE_SYSTEM,
                     0, /* flags */
                     ssh_pm_vip_route_add_success_cb,
                     thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_add_routes_result)
{
  SshPmVip vip = (SshPmVip) thread_context;
  SshPmVipRoute route;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP route addition completed."));

  route = &vip->routes[vip->index];
  if (route->added == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to add route to network %@",
			     ssh_ipaddr_render, &route->prefix));
      vip->index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Added route to network %@",
                           ssh_ipaddr_render, &route->prefix));

  /** Route added, continue with the next one. */
  vip->index++;
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_routes);
  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_add_name_servers_cb(Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (status)
    vip->name_servers_added = 1;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_add_name_servers)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Adding name servers."));

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_name_servers_result);
  SSH_FSM_ASYNC_CALL(ssh_pm_add_name_servers(
					     vip->attrs.num_dns,
					     vip->attrs.dns,
					     vip->attrs.num_wins,
					     vip->attrs.wins,
					     ssh_pm_add_name_servers_cb,
					     thread));

  SSH_NOTREACHED;

}

SSH_FSM_STEP(ssh_pm_st_vip_add_name_servers_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Name server addition completed."));

  if (!vip->name_servers_added)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to add name servers"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Added name servers"));
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_tunnel);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_setup_tunnel)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Setting up virtual IP tunnel."));

#ifdef SSHDIST_L2TP
  if (vip->t_l2tp)
    {
      /** L2TP tunnel. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_tunnel_l2tp);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_L2TP */

  /* All done */
  vip->index = 0;
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_register);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_setup_tunnel_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

#ifdef SSHDIST_L2TP
  if (vip->t.l2tp.tunnel_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP tunnel setup failed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_L2TP */

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP tunnel setup completed."));

  vip->index = 0;
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_register);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_register)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Registering virtual IP."));

  if (ssh_pm_vip_register(vip))
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_up);
      return SSH_FSM_CONTINUE;
    }

  if (++vip->index >= 5)
    {
      SSH_DEBUG(SSH_D_FAIL, ("VIP registration failed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Retrying VIP registration after one second."));
  ssh_register_timeout(&vip->timeout_struct, 1, 0, ssh_pm_vip_wait_timeout_cb,
		       thread);
  
  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(ssh_pm_st_vip_up)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_ASSERT(vip->tunnel != NULL);

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP setup completed."));

  /* Mark vip startup completed. */
  vip->unusable = 0;

  /* Update auto-start status. */
  if (vip->tunnel->as_active)
    {
      vip->tunnel->as_active = 0;
      vip->rules->rule->side_to.as_active = 0;
      vip->rules->rule->side_to.as_up = 1;
      vip->rules->rule->side_to.as_fail_limit = 0;

      /* Check if another rule is waiting for this auto-start tunnel to
	 come up, if so signal to the main thread to reconsider the
	 auto-start rules. */
      if (vip->tunnel->as_rule_pending)
	{
	  vip->tunnel->as_rule_pending = 0;
	  pm->auto_start = 1;
	  ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
	}
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_established);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_setup_failed)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_ASSERT(vip->tunnel != NULL);

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP setup failed."));

  /* Update auto-start status. */
  if (vip->tunnel->as_active)
    {
      vip->tunnel->as_active = 0;

      if (vip->rules->rule->side_to.as_fail_limit < 16)
	vip->rules->rule->side_to.as_fail_limit++;

      vip->rules->rule->side_to.as_active = 0;
      vip->rules->rule->side_to.as_fail_retry =
        vip->rules->rule->side_to.as_fail_limit;
      vip->rules->rule->side_to.as_up = 0;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_established)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP established."));

  /* Wait that something interesting happens. */
  if ((ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
      && !vip->unusable
      && !vip->shutdown
      && !vip->reconfigure
      && !vip->add_routes
      && !vip->remove_routes
#ifdef SSHDIST_L2TP
      && (!vip->t_l2tp || vip->t.l2tp.lac_state == SSH_PM_VIP_LAC_CONNECTED)
#endif /* SSHDIST_L2TP */
      && !(vip->rule_deleted))
    SSH_FSM_CONDITION_WAIT(&vip->cond);

  /** Remove VIP routes. */
  if (vip->remove_routes)
    {
      vip->remove_routes_next = ssh_pm_st_vip_established;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_remove_routes);
    }
  /** Re-add VIP routes. */
  else if (vip->add_routes)
    {
      vip->add_routes_next = ssh_pm_st_vip_established;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_add_routes);
    }
  /** Rules have been deleted */
  else if (vip->rule_deleted)
    {
      vip->rule_deleted = 0;
      if (ssh_pm_vip_remove_deleted_rules(pm, vip))
        SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown);
      else
        SSH_FSM_SET_NEXT(ssh_pm_st_vip_established);
    }
  /** Re-configure VIP addrs and routes. */
  else if (vip->reconfigure)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_configure_interface_up);
    }
  /** Shutdown. */  
  else
    {
      for (i = 0; i < vip->num_routes; i++)
        vip->routes[i].remove = 1;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown)
{
  SshPmVip vip = (SshPmVip) thread_context;
  SshPmVipRoute route;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDOK, ("Starting virtual IP shutdown."));

  /* Mark virtual IP unusable. */
  vip->unusable = 1;

  /* Cancel destroy timeout. */
  ssh_cancel_timeout(&vip->timeout_struct);

  /* Mark all remaining routes for removal. */
  for (i = 0; i < vip->num_routes; i++)
    {
      route = &vip->routes[i];
      if (route->added == 1)
        {
          route->remove = 1;
          route->clear = 1;
        }
    }

#ifdef SSHDIST_L2TP
  if (vip->t_l2tp && vip->successful)
    {
      /** Tear down L2TP session. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_session_l2tp);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_L2TP */

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_name_servers);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_session_result)
{
  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP session shutdown completed."));

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_name_servers);
  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_remove_name_servers_cb(Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (status)
    vip->name_servers_added = 0;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_name_servers)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Removing name servers."));

  if (!vip->name_servers_added)
    {
      vip->remove_routes_next =
        ssh_pm_st_vip_shutdown_configure_interface_down;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_remove_routes);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_name_servers_result);
  SSH_FSM_ASYNC_CALL(ssh_pm_remove_name_servers(vip->attrs.num_dns,
						vip->attrs.dns,
						vip->attrs.num_wins,
						vip->attrs.wins,
						ssh_pm_remove_name_servers_cb,
						thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_name_servers_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Name server removal completed."));

  if (vip->name_servers_added)
    SSH_DEBUG(SSH_D_FAIL, ("Failed to remove name servers"));

  vip->remove_routes_next = ssh_pm_st_vip_shutdown_configure_interface_down;
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_remove_routes);
  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_vip_route_remove_success_cb(SshPm pm,
				   SshInterceptorRouteError error,
				   void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (error == SSH_INTERCEPTOR_ROUTE_ERROR_OK)
    {    
      vip->routes[vip->index].added = 0;
      vip->routes[vip->index].remove = 0;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_remove_routes)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshPmVipRoute route = NULL;
  SshInterceptorRouteKeyStruct key;

  SSH_DEBUG(SSH_D_MIDOK, ("Removing virtual IP routes."));

  if (vip->remove_routes)
    vip->remove_routes = 0;

  for (; vip->index < vip->num_routes; vip->index++)
    {
      route = &vip->routes[vip->index];
      if (route->remove == 0)
	continue;

      if (route->added == 1)
	break;

      /* Route was never successfully added, move on to next one. */
    }
  if (vip->index >= vip->num_routes)
    {
      vip->index = 0;
      SSH_FSM_SET_NEXT(vip->remove_routes_next);
      return SSH_FSM_CONTINUE;
    }
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(route->added == 1);
  SSH_ASSERT(route->remove == 1);

  /** Remove route. */
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Deleting route %d to network %@ via %@",
	     (int) vip->index,
             ssh_ipaddr_render, &route->prefix, 
             ssh_ipaddr_render, &route->nexthop));

  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);
  SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(&key, &route->prefix);

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_remove_routes_result);
  SSH_FSM_ASYNC_CALL({
    ssh_pm_route_remove(pm,
			&key,
			&route->nexthop,
                        SSH_INVALID_IFNUM,
			SSH_ROUTE_PREC_ABOVE_SYSTEM,
			SSH_INTERCEPTOR_ROUTE_FLAG_IGNORE_NONEXISTENT,
			ssh_pm_vip_route_remove_success_cb,
			thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_remove_routes_result)
{
  SshPmVip vip = (SshPmVip) thread_context;
  SshPmVipRoute route;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP route removal completed."));

  route = &vip->routes[vip->index];
  if (route->added == 1)
    SSH_DEBUG(SSH_D_FAIL, ("Failed to remove route to network %@",
			   ssh_ipaddr_render, &route->prefix));
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Removed route to network %@",
			       ssh_ipaddr_render, &route->prefix));
      if (route->clear == 1)
	{
	  SSH_IP_UNDEFINE(&route->prefix);
	  route->clear = 0;
	}
    }
  /* Continue to removing next route. */
  vip->index++;
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_remove_routes);
  return SSH_FSM_CONTINUE;
}

static void
ssh_pm_virtual_adapter_configure_down_cb(SshPm pm,
					 SshVirtualAdapterError error,
					 SshUInt32 num_adapters,
					 SshPmeVirtualAdapter adapters,
					 void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = ssh_fsm_get_tdata(thread);

  if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK)
    vip->adapter_configured = 0;
  
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_configure_interface_down)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Configuring virtual adapter down."));

  /* Destroy virtual adapter if it is created. */
  if (vip->adapter_configured)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Configuring virtual adapter %d [%s] down",
				 (int) vip->adapter_ifnum, vip->adapter_name));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_configure_interface_down_result);
      SSH_FSM_ASYNC_CALL({
	ssh_pm_virtual_adapter_configure(pm,
				      vip->adapter_ifnum,
				      SSH_VIRTUAL_ADAPTER_STATE_DOWN,
				      0, NULL, NULL,
				      ssh_pm_virtual_adapter_configure_down_cb,
				      thread);
      });
      SSH_NOTREACHED;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_sgw_route);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_configure_interface_down_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual adapter configuration completed."));

  if (!vip->adapter_configured)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL, "");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
		    "Virtual IP interface %d [%s] configured down", 
		    (int) vip->adapter_ifnum, vip->adapter_name);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
		("Failed to configure virtual IP interface %d [%s] down",
		 (int) vip->adapter_ifnum, vip->adapter_name));
    }

  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
    {
      /* Cancel any interface trigger timeouts. */ 
      ssh_cancel_timeout(&vip->timeout_struct);
      
      /* Wait until we receive an interface notification about
	 disappearing of the virtual adapter. */
      vip->timeout = 0;
      ssh_register_timeout(&vip->timeout_struct, 5, 0, 
			   ssh_pm_vip_wait_timeout_cb, thread);

      /* Wait interface notification. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_wait_interface_down);
    }
  else
    {
      /* During shutdown, dont bother waiting for adapter to go offline. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_sgw_route);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_wait_interface_down)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  
  SSH_DEBUG(SSH_D_MIDOK, ("Waiting for virtual adapter to go offline."));
  
  /* Has the virtual adapter already disappeared from interface table. */
  if (!ssh_pm_find_interface_by_ifnum(pm, vip->adapter_ifnum))
    {
      /* Interface has disappeared. Cancel the timeout. */
      ssh_cancel_timeout(&vip->timeout_struct);      
      SSH_DEBUG(SSH_D_HIGHOK, ("Virtual adapter %d [%s] down", 
			       (int) vip->adapter_ifnum,
			       vip->adapter_name)); 
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_sgw_route);
      return SSH_FSM_CONTINUE;
    }

  /* Has the operation timed out? */
  if (vip->timeout)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter %d [%s] did not go offline",
			     (int) vip->adapter_ifnum,
			     vip->adapter_name));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_sgw_route);
      return SSH_FSM_CONTINUE;
    }

  /* Wait for interface report. */
  SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
}

static void
ssh_pm_vip_sgw_route_remove_success_cb(SshPm pm, 
				       SshInterceptorRouteError error,
				       void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (error == SSH_INTERCEPTOR_ROUTE_ERROR_OK)
    vip->sgw_route_added = 0;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_sgw_route)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshInterceptorRouteKeyStruct key;
  SshUInt32 ifnum;

  SSH_DEBUG(SSH_D_MIDOK, ("Removing virtual IP SGW route."));

  if (!vip->sgw_route_added)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_wait_references);
      return SSH_FSM_CONTINUE;
    }

  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);
  SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(&key, &vip->sgw);

  /* Specify interface if SGW next hop is IPv6 link local. */
  if (SSH_IP6_IS_LINK_LOCAL(&vip->sgw_next_hop))
    ifnum = vip->sgw_ifnum;
  else
    ifnum = SSH_INVALID_IFNUM;

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_sgw_route_result);
  SSH_FSM_ASYNC_CALL({
    ssh_pm_route_remove(pm,
			&key,
			&vip->sgw_next_hop,
			ifnum,
			SSH_ROUTE_PREC_HIGHEST,
			0, /* flags */			 
			ssh_pm_vip_sgw_route_remove_success_cb,
			thread);
  });
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_sgw_route_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP SGW route removal completed."));

  if (vip->sgw_route_added)
    SSH_DEBUG(SSH_D_FAIL, ("Failed to remove host route to peer"));
  else
    SSH_DEBUG(SSH_D_HIGHOK, ("Removed host route to peer"));

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_wait_references);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_wait_references)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP context has %d references.",
			  (int) vip->refcnt));

  if (vip->refcnt > 0)
    {
      /* There are still references out. */

      /* If vip is shut down because the vip rule was deleted during
	 reconfiguration, then release references to high level rules.
	 After this the reconfigure handler (in spd_batch_st.c) will
	 delete the IPsec SAs. */
      if (pm->batch_active)
	{
	  /* Unlock and free all high-level rules. */
	  if (vip->rules)
	    {
	      SshPmVipRule vrule = vip->rules;
	      while (vrule)
		{
		  vip->rules = vrule->next;
		  SSH_PM_RULE_UNLOCK(pm, vrule->rule);
		  ssh_free(vrule);
		  vrule = vip->rules;
		}
	    }
	}

      /* Delete SAs with this RAS GW. This causes both IKE and IPsec SAs 
	 with the peer to be deleted. This also sends delete notifications 
	 for the deleted SAs. */
      else
	ssh_pm_delete_by_peer_handle(pm, vip->peer_handle, 0, NULL_FNPTR, 
				     NULL);
      
      /* Wait until all references have been freed. Dont bother waiting if
	 PM is shutting down. */
      if (ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
	{
	  SSH_FSM_CONDITION_WAIT(&vip->cond);
	  SSH_NOTREACHED;
	}
    }

#ifdef SSHDIST_L2TP
  if (vip->t_l2tp && vip->successful)
    {
      /** Cleanup L2TP tunnel. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_cleanup_l2tp);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_L2TP */

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_complete);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_complete)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshPmVirtualAdapter adapter;

  SSH_DEBUG(SSH_D_MIDOK, ("Virtual IP shutdown completed."));

  /* Release the virtual adapter: */
  adapter = ssh_pm_virtual_adapter_find_byifnum(pm, vip->adapter_ifnum);
  adapter->in_use = FALSE;

  /* Make the tunnel available for new VIPs and release the tunnel
     reference. */
  vip->tunnel->vip = NULL;
  SSH_PM_TUNNEL_DESTROY(pm, vip->tunnel);
  vip->tunnel = NULL;

  /* Unlock and free all high-level rules that have not yet been freed. */
  if (vip->rules)
    {
      SshPmVipRule vrule = vip->rules;
      while (vrule)
        {
          vip->rules = vrule->next;
          SSH_PM_RULE_UNLOCK(pm, vrule->rule);
          ssh_free(vrule);
          vrule = vip->rules;
        }
    }

  /* Free reference to peer_handle. */
  if (vip->peer_handle != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_pm_peer_handle_destroy(pm, vip->peer_handle);
      vip->peer_handle = SSH_IPSEC_INVALID_INDEX;
    }

  /* The main thread has one sub-thread less running. */
  SSH_ASSERT(pm->mt_num_sub_threads > 0);
  pm->mt_num_sub_threads--;

  /* Notify main thread about the fact that we have gone away. */
  SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

  /* There are three different ways how virtual IP threads terminate:

     1) The policy manager is shutting down
     2) User has deleted the virtual IP rule
     3) The virtual IP implementation protocol terminates the connection

     All these cases are currently handled and they do not require any
     more operations from us.  The trickiest case is the case 3.  In
     that case we notify user about the connection termination and it
     is user's responsibility to delete the high-level virtual IP
     rule. */




  return SSH_FSM_FINISH;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
