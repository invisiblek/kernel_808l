/**
   
   @copyright
   Copyright (c) 2002 - 2010, AuthenTec Oy.  All rights reserved.
   
   adapter.c
   
   This file contains the implementation of functions for the virtual
   adapter object that is layered above a real NDIS networking device
   driver.
   
*/


/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "interceptor_i.h"
#include "registry.h"
#include "kernel_timeouts.h"
#include "event.h"
#include "wan_interface.h"
#ifdef _WIN32_WCE
#include <windev.h>
#include <ndiswan.h>
#endif /* _WIN32_WCE */
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
#include "virtual_adapter_private.h"
#include "sshvnic_def.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE                 "SshInterceptorAdapter"

#ifdef _WIN32_WCE
#define QUICKSEC_LAN_PROTOCOL_NAMES      L"QSECLAN\0"
#define QUICKSEC_WAN_PROTOCOL_NAMES      L"QSECWAN\0"

#define REGVAL_PPP_DIRECTED              L"PPP\0"
#define REGVAL_TCPIP_DIRECTED            L"TCPIP\0"
#define REGVAL_PPP_EXCLUDED              L"NOT PPP\0"
#define REGVAL_TCPIP_EXCLUDED            L"NOT TCPIP\0"

#define PNAME_TCPIP    L"TcpIp\0"
#endif /* _WIN32_WCE */

/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

/* Attributes for intermediate adapter */
const ULONG 
SSH_ADAPTER_ATTRIBUTES = (NDIS_ATTRIBUTE_INTERMEDIATE_DRIVER 
                          | NDIS_ATTRIBUTE_DESERIALIZE
                          | NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT
                          | NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT
                          | NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND);

/* Time interval [secs] to check that adapter is alive */
const UINT 
SSH_ADAPTER_CHECK_FOR_HANG_INTERVAL = 60;

/* Physical address for WAN adapter (Windows NT, 2000, XP) */
const UCHAR
SSH_ADAPTER_PHYS_ADDRESS_WAN[SSH_ETHERH_ADDRLEN] = 
  {0x00,0x53,0x45,0x00,0x00,0x00};

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_send_media_status(SshNdisIMAdapter adapter);

static VOID
ssh_adapter_send_request(SshNdisIMAdapter adapter,
                         NDIS_REQUEST *request,
                         NDIS_STATUS *status);

static PNDIS_STRING
ssh_adapter_get_device_name(SshNdisIMAdapter adapter);

static VOID
ssh_adapter_set_task_offload(SshNdisIMAdapter adapter,
                             PNDIS_REQUEST set,
                             NDIS_STATUS *status);

static VOID
ssh_adapter_query_task_offload(SshNdisIMAdapter adapter,
                               PNDIS_REQUEST query,
                               NDIS_STATUS *status);

static VOID
ssh_adapter_request_reject(SshNdisIMAdapter adapter,
                           PNDIS_REQUEST request,
                           NDIS_STATUS *status);

static VOID 
ssh_adapter_request_queue(SshNdisIMAdapter adapter,
                          PNDIS_REQUEST request,
                          NDIS_STATUS *status);

static VOID
ssh_adapter_set_request_finish(SshNdisIMAdapter adapter, 
                               PNDIS_REQUEST request, 
                               NDIS_STATUS status);
static VOID
ssh_adapter_query_request_finish(SshNdisIMAdapter adapter, 
                                 PNDIS_REQUEST request, 
                                 NDIS_STATUS status);

static VOID
ssh_adapter_handle_query_mac_options_result(SshNdisIMAdapter adapter, 
                                            PNDIS_REQUEST request, 
                                            NDIS_STATUS status);

static VOID
ssh_adapter_handle_query_pnp_capabilities_result(SshNdisIMAdapter adapter, 
                                                 PNDIS_REQUEST request, 
                                                 NDIS_STATUS status);

static VOID
ssh_adapter_handle_query_mac_address_result(SshNdisIMAdapter adapter, 
                                            PNDIS_REQUEST request, 
                                            NDIS_STATUS status);

static VOID
ssh_adapter_handle_query_vlan_id_result(SshNdisIMAdapter adapter,
                                        PNDIS_REQUEST request,
                                        NDIS_STATUS status);

#ifdef _WIN32_WCE
static VOID
ssh_adapter_handle_query_wan_info_result(SshNdisIMAdapter adapter, 
                                         PNDIS_REQUEST request, 
                                         NDIS_STATUS status);
#endif /* _WIN32_WCE */

static VOID
ssh_adapter_handle_set_vlan_id_result(SshNdisIMAdapter adapter,
                                      PNDIS_REQUEST request,
                                      NDIS_STATUS status);

static VOID
ssh_adapter_handle_set_current_packet_filter(SshNdisIMAdapter adapter, 
                                             PNDIS_REQUEST request, 
                                             NDIS_STATUS status);

static VOID
ssh_adapter_handle_set_current_lookahead_result(SshNdisIMAdapter adapter, 
                                                PNDIS_REQUEST request, 
                                                NDIS_STATUS status);

static UINT
ssh_adapter_nic_get(SshNdisIMAdapter adapter, 
                    NDIS_OID oid, 
                    PVOID buf, 
                    UINT len);

static UINT
ssh_adapter_nic_set(SshNdisIMAdapter adapter, 
                    NDIS_OID oid, 
                    PVOID buf, 
                    UINT len);

static Boolean
ssh_adapter_nic_request(SshNdisIMAdapter adapter, 
                        Boolean set, 
                        NDIS_OID oid,
                        PVOID buf, 
                        UINT *len);

static VOID
ssh_adapter_nic_request_done(SshNdisIMAdapter adapter,
                             PNDIS_REQUEST request,
                             NDIS_STATUS status);

#ifdef _WIN32_WCE
static NDIS_STATUS
ssh_adapter_update_wireless(SshNdisIMAdapter adapter);

static NDIS_STATUS
ssh_adapter_update_config(SshNdisIMAdapter adapter, 
                          Boolean wan_adapter);
#endif /* _WIN32_WCE */


static void
ssh_winim_attach_adapter(SshAdapter generic_adapter,
                         void *attach_context,
                         SshAdapterAttachCompleteCb callback,
                         void *completion_context);

static void
ssh_winim_detach_adapter(SshAdapter generic_adapter,
                         void *detach_context,
                         SshAdapterDetachCompleteCb callback,
                         void *completion_context);

static void
ssh_winim_restart_adapter(SshAdapter generic_adapter,
                          void *restart_context,
                          SshAdapterRestartCompleteCb callback,
                          void *completion_context);

static void
ssh_winim_pause_adapter(SshAdapter generic_adapter,
                        void *pause_context,
                        SshAdapterPauseCompleteCb callback,
                        void *completion_context);

/*--------------------------------------------------------------------------
  MISCALLENIOUS IN-LINE FUNCTIONS
  --------------------------------------------------------------------------*/

__inline BOOLEAN 
ssh_query_success(NDIS_STATUS status, 
                  struct _QUERY_INFORMATION *query, 
                  ULONG len)
{
  return (status == NDIS_STATUS_SUCCESS 
          && query->InformationBufferLength == len);
}

__inline BOOLEAN 
ssh_set_success(NDIS_STATUS status, 
                struct _SET_INFORMATION *set, 
                ULONG len)
{
  return (status == NDIS_STATUS_SUCCESS 
          && set->InformationBufferLength == len);
}

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GENERAL FUNCTIONS FOR ADAPTER CONTROL
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_adapter_create()
  
  Creates a new SSH Adapter object by allocating memory for internal
  data structures and initializing internal attributes. 

  Arguments:
  id - Globally unique adapter identifier (0....N)
  name - the original adapter device name,
  name_len - the length of name,
  interceptor - SSH Interceptor object

  Returns:
  SshAdapter object if success, NULL otherwise.

  Notes:
  --------------------------------------------------------------------------*/
SshNdisIMAdapter
ssh_adapter_create(PCWSTR name,
                   USHORT name_len,
                   SshNdisIMInterceptor interceptor)
{
  SshNdisIMAdapter adapter;
  SshAdapterInitParamsStruct init_params;
  SshAdapterEnableFlags features;
#ifndef _WIN32_WCE
  UNICODE_STRING uc_name;
#endif /* _WIN32_WCE */

  SSH_ASSERT(name != NULL);
  SSH_ASSERT(name_len > 0);
  SSH_ASSERT(interceptor != NULL);

  /* Allocate memory for adapter object */
  adapter = ssh_calloc(1, sizeof(*adapter));
  if (adapter == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                    SSH_LOG_CRITICAL,
                    ("Failed to allocate adapter object!")); 
      return (NULL);
    }

  memset(&init_params, 0x00, sizeof(init_params));
  init_params.name = name;
  init_params.name_len = name_len;

#ifndef _WIN32_WCE
  /* Do NOT use RtlInitUnicodeString, because nobody guarantees that 'name'
     is terminated with UNICODE_NULL */
  uc_name.Buffer = (PWSTR)name;
  uc_name.Length =
  uc_name.MaximumLength = name_len;
  /* This GUID conversion will fail for non-GUID device names, but it 
     doesn't matter (because our platform independent code will 
     'automagically' use device name instead of GUID in name mappings). */
  if (!NT_SUCCESS(RtlGUIDFromString(&uc_name, &init_params.guid)))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                        ("GUID conversion failed:"),
                        (const unsigned char *)name, name_len);
    }
#endif /* _WIN32_WCE */

  /* Everything disabled in DETACHED state */

  /* Everything disabled in ATTACHING state */

  /* Features enabled in PAUSED state */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_PAUSED];
  features->flags.allow_oid_requests = 1;

  /* Features enabled in RESTARTING state */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_RESTARTING];
  features->flags.allow_initiate_oid_requests = 1;
  features->flags.allow_oid_requests = 1;
  features->flags.allow_initiate_status_indications = 1;
  features->flags.allow_status_indications = 1;  

  /* Everything enabled in RUNNING state */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_RUNNING];
  *features = init_params.feature_flags[SSH_ADAPTER_STATE_RESTARTING];
  features->flags.allow_initiate_receive_indications = 1;
  features->flags.allow_receive = 1;
  features->flags.allow_initiate_send = 1;
  features->flags.allow_send = 1;

  /* Features enabled in PAUSING state (same than restarting) */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_PAUSING];
  *features = init_params.feature_flags[SSH_ADAPTER_STATE_RESTARTING];

  if (!ssh_adapter_init_common((SshAdapter)adapter,
                               (SshInterceptor)interceptor,
                               &init_params))  
    {
      ssh_free(adapter);
      return NULL;
    }

  adapter->binding_handle = NULL;
  adapter->bind_context = NULL;
  adapter->if_description = NULL;
  adapter->if_description_len = 0;

  /* Initialize variables related to power management */
  NdisAllocateSpinLock(&adapter->power_mgmt_lock);
  adapter->pending_query_request = NULL;
  adapter->pending_set_request = NULL;
  adapter->outstanding_requests = 0;
  adapter->virtual_mp_power_state = NdisDeviceStateD0;
  adapter->underlying_mp_power_state = NdisDeviceStateD0; 

  /* Send queue which will be used when we run out of packet or buffer pool */
  NdisAllocateSpinLock(&adapter->send_wait_queue_lock);
  NdisInitializeListHead(&adapter->send_wait_queue);

  /* Initialize memory for the request list */
  NdisInitializeNPagedLookasideList(&adapter->request_list,
                                    NULL, NULL, 0,
                                    sizeof(struct SshRequestRec),
                                    'rNFS', 0);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: created", ssh_adapter_id_st_render, adapter));

  return (adapter);
}

/*--------------------------------------------------------------------------
  ssh_adapter_destroy()
  
  Destroys SSH Adapter object.

  Arguments:
  adapter - adapter object to be destroyed

  Returns:

  Notes:
  This function is called from ProtocolUnBindAdapter (handler) after binding
  between our driver and a given real network adapter is removed.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_destroy(SshNdisIMAdapter adapter)
{
  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: destroy", ssh_adapter_id_st_render, adapter));

  /* Free memory allocated for strings */
  if (adapter->name.Buffer != NULL)
    {
      ssh_free(adapter->name.Buffer);
      adapter->name.Buffer = NULL;
    }

  /* Release memory allocated for our request list */
  NdisDeleteNPagedLookasideList(&adapter->request_list);

  /* Free spin locks */
  NdisFreeSpinLock(&adapter->power_mgmt_lock);
  NdisFreeSpinLock(&adapter->send_wait_queue_lock);

  /* Free cached interface description */
  ssh_free(adapter->if_description);

  /* Close the configuration handle */
  if (adapter->config_handle != NULL)
    NdisCloseConfiguration(adapter->config_handle);

  ssh_adapter_uninit_common((SshAdapter)adapter);

  /* Finally release the memory allocated for the adapter */
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  ssh_free(adapter->vnic_interface);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  while (adapter->ip_cfg_thread_suspended)
    {
      ssh_task_resume(&adapter->interceptor->ip_cfg_thread);
      adapter->ip_cfg_thread_suspended--;
    }

  ssh_free(adapter);
}


/*--------------------------------------------------------------------------
  ssh_adapter_open()
  
  Opens the underlaying NIC and asks NDIS to start initialization of 
  SSH Adapter object.
 --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_open(SshNdisIMAdapter adapter,
                 NDIS_HANDLE bind_context,
                 PVOID system_specific1,
                 Boolean wan_adapter)
{
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  SSH_ASSERT(bind_context != NULL);
  SSH_ASSERT(system_specific1 != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: open", ssh_adapter_id_st_render, adapter));

  adapter->bind_context = bind_context;
  adapter->is_wan_adapter = wan_adapter;

#ifndef _WIN32_WCE
  /* Create I/O device for SSH PolicyManager communication */
  ssh_interceptor_ipm_device_create(adapter->interceptor);
#endif /* _WIN32_WCE */

  NdisOpenProtocolConfiguration(&status, 
                                &adapter->config_handle, 
                                system_specific1);

  if (!ssh_adapter_attach_common((SshAdapter)adapter, 
                                 ssh_winim_attach_adapter,
                                 adapter))
    return NDIS_STATUS_FAILURE;
  else
    return NDIS_STATUS_SUCCESS;
}


#ifdef _WIN32_WCE
typedef struct SshAttachFailureCleanupCtxRec
{
  SshNdisIMAdapter adapter;

  PWSTR protocol_list;

  /* Flags indicating the cleanup operations to be performed. */
  SshUInt32 close_adapter : 1;
  SshUInt32 restore_bindings : 1;
  SshUInt32 destroy_adapter : 1;
} SshAttachFailureCleanupCtxStruct, *SshAttachFailureCleanupCtx;

static void __fastcall
ssh_winim_attach_failure_cleanup(SshAttachFailureCleanupCtx ctx)
{
  SshNdisIMInterceptor interceptor;

  SSH_ASSERT(ctx != NULL);
  SSH_ASSERT(ctx->adapter != NULL);

  interceptor = (SshNdisIMInterceptor)ctx->adapter->interceptor;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Performing cleanup for adapter %@:", 
             ssh_adapter_id_st_render, ctx->adapter));

  if (ctx->close_adapter)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, (" - closing adapter"));
      ssh_adapter_close(ctx->adapter);
    }

  if (ctx->restore_bindings)
    {
      NDIS_STATUS tmp_status;

      SSH_DEBUG(SSH_D_NICETOKNOW, (" - restoring original bindings"));
      NdisBindProtocolsToAdapter(&tmp_status, 
                                 ctx->adapter->orig_name.Buffer, 
                                 ctx->protocol_list);

      ssh_free(ctx->protocol_list);
    }

  if (ctx->destroy_adapter)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, (" - destroying adapter"));
      ssh_adapter_destroy(ctx->adapter);
    }

  ssh_free(ctx);

  InterlockedDecrement(&interceptor->ref_count);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Cleanup complete."));
}

static void
ssh_winim_attach_adapter(SshAdapter generic_adapter,
                         void *restart_context,
                         SshAdapterAttachCompleteCb callback,
                         void *callback_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)generic_adapter;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  NDIS_STATUS open_status = NDIS_STATUS_SUCCESS;
  SshNdisIMInterceptor interceptor;
  NDIS_MEDIUM lan_medium_array[] = {NdisMedium802_3};
  NDIS_MEDIUM wan_medium_array[] = {NdisMediumWan};
  NDIS_PHYSICAL_MEDIUM physical_medium;
  NDIS_MEDIA_STATE media_state;
  static NDIS_STRING unbind_keyword = NDIS_STRING_CONST("Unbind");
  static NDIS_STRING disable_pm = NDIS_STRING_CONST("DisablePowerManagement");
  PNDIS_CONFIGURATION_PARAMETER config_value;
  PWSTR protocol_list = NULL;
  TCHAR	old_protocols[256] = _T("");
  DWORD old_protocols_size = 0; 
  Boolean protocol_unbind = FALSE;
  PNDIS_MEDIUM medium_array = lan_medium_array;
  UINT medium_cnt = (sizeof(lan_medium_array) / sizeof(lan_medium_array[0]));
  UINT medium_idx = 0;
  NDIS_HANDLE protocol_handle;
  SshNdisIMAdapter a;
  char *name_prefix;
  int name_number;
  SshInterceptorIfnum ifnum;
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  PVOID buf;
  UINT len;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  SSH_ASSERT(adapter->bind_context != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: attach", ssh_adapter_id_st_render, adapter));

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  protocol_handle = interceptor->protocol_handle;

  /* Select WAN configuration items as appropriate. */
  if (adapter->is_wan_adapter) 
    {
      protocol_handle = interceptor->wan_protocol_handle;
      medium_array = wan_medium_array;
      medium_cnt = (sizeof(wan_medium_array) / sizeof(wan_medium_array[0]));
    }

  /* Init adapter attributes */
  if (adapter->config_handle)
    {
      if (ssh_adapter_get_device_name(adapter) == NULL)
        goto failed;

      NdisReadConfiguration(&status, &config_value, adapter->config_handle,
                            &disable_pm, NdisParameterInteger);
      if (status == NDIS_STATUS_SUCCESS)
        {
          if (config_value->ParameterData.IntegerData)
            adapter->power_mgmt_disabled = TRUE;
        }

      /* Read the "Unbind" reserved key that can control which protocols 
         will be unbound from the adapter after it's opened. */
      NdisReadConfiguration(&status, &config_value, adapter->config_handle, 
                            &unbind_keyword, NdisParameterMultiString);
      if (status == NDIS_STATUS_SUCCESS) 
        protocol_list = config_value->ParameterData.StringData.Buffer;
    } 
  else 
    {
      /* Free previously allocated name */
      if (adapter->name.Buffer)
        ssh_free(adapter->name.Buffer);

      /* Calculate the required buffer length. */
      adapter->name.MaximumLength = 
        adapter->orig_name.Length 
          + (sizeof(WCHAR) * QUICKSEC_MINIPORT_PREFIX_LEN);
	  
      /* Allocate a buffer for the name (with a null terminator). */
      adapter->name.Buffer = 
        ssh_calloc(1, (adapter->name.MaximumLength + sizeof (WCHAR)));
      
      if (adapter->name.Buffer == NULL) 
        goto failed;
	  
      /* Initialize the buffer. */
      adapter->name.Length = (sizeof(WCHAR) * QUICKSEC_MINIPORT_PREFIX_LEN);
      NdisMoveMemory(adapter->name.Buffer, 
                     QUICKSEC_MINIPORT_PREFIX, 
                     adapter->name.Length);
      NdisMoveMemory((adapter->name.Buffer + QUICKSEC_MINIPORT_PREFIX_LEN), 
                     adapter->orig_name.Buffer, adapter->orig_name.Length);
      adapter->name.Length += adapter->orig_name.Length;
    }

  /* We should unbind other protocols from an adapter */
  if ((protocol_list == NULL) || (*protocol_list != _T('\0')))
    {
      /* We try to save current binding to registry for rebind on unload */
      NdisGetAdapterBindings(&status, adapter->orig_name.Buffer, 
                             (PUCHAR)old_protocols, sizeof(old_protocols),
                             &old_protocols_size);

      if (status != NDIS_STATUS_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Adapter %@: cannot get bindings, status=%@",
                     ssh_adapter_id_st_render, adapter,
                     ssh_ndis_status_render, &status));
          goto failed;
        }

      if (old_protocols_size > sizeof old_protocols[0] &&
          old_protocols[0] != L'\0')
        {
          SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                            ("Adapter %@: unbinding protocols:",
                             ssh_adapter_id_st_render, adapter),
                            (const unsigned char *)old_protocols, 
                            old_protocols_size);

          NdisUnbindProtocolsFromAdapter(&status, 
                                         adapter->orig_name.Buffer, 
                                         protocol_list);

          if (status != NDIS_STATUS_SUCCESS)
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Adapter %@: cannot unbind protocols, status=%@",
                         ssh_adapter_id_st_render, adapter,
                         ssh_ndis_status_render, &status));
              goto failed;
            }
        }

      protocol_unbind = TRUE;
   }

  /* Try to open the networking device below */
  ssh_event_reset(adapter->wait_event);
  NdisOpenAdapter(&status, 
                  &open_status,
                  &adapter->binding_handle,
                  &medium_idx, 
                  medium_array,
                  medium_cnt,
                  protocol_handle,
                  adapter, 
                  &adapter->orig_name, 
                  0, 
                  NULL);

  /* Wait until adapter open operation is completed */
  if (status == NDIS_STATUS_PENDING)
    {
      ssh_event_wait(1, &adapter->wait_event, NULL);
      status = adapter->result;
    }

  /* Opening the underlaying adapter has failed so return with error */
  if (status != NDIS_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@ open failed, status=%@",
                 ssh_adapter_id_st_render, adapter,
                 ssh_ndis_status_render, &status));
      goto failed;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@ open completed", ssh_adapter_id_st_render, adapter));

  /* Update adapter state, save media type */
  adapter->media = medium_array[medium_idx];

  if (adapter->media == NdisMediumWan)
    name_prefix = "wan";
  else
    name_prefix = "lan";

  if (!ssh_adapter_nic_get(adapter, OID_GEN_PHYSICAL_MEDIUM,
                           &physical_medium, sizeof physical_medium))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Failed to get physical medium type",
                 ssh_adapter_id_st_render, adapter));
    }
  else
    {
      switch (physical_medium)
        {
        case NdisPhysicalMediumWirelessLan:
        case NdisPhysicalMediumNative802_11:
          adapter->physical_media = NdisPhysicalMediumWirelessLan;
          name_prefix = "wlan";
          break;
        case NdisPhysicalMediumWirelessWan:
          adapter->physical_media = NdisPhysicalMediumWirelessWan;
          name_prefix = "wwan";
          break;
          /*
            case NdisPhysicalMediumUnspecified:
            case NdisPhysicalMediumCableModem:
            case NdisPhysicalMediumPhoneLine:
            case NdisPhysicalMediumPowerLine:
            case NdisPhysicalMediumDSL:
            case NdisPhysicalMediumFibreChannel:
            case NdisPhysicalMedium1394:
            break;
          */
        default:
          adapter->physical_media = NdisPhysicalMediumUnspecified;
          break;
        }
    }

  /* Set adapter name, consisting of a string describing the medium
     type (lan, wan etc.) followed by the number of the adapter among
     named adapters of the same medium type. */
  name_number = 0;
  for (ifnum = 0; ifnum < adapter->ifnum; ifnum++)
    {
      a = (SshNdisIMAdapter)interceptor->adapter_table[ifnum];
      if (!a->ssh_name[0])
        continue;
      if (a->media == adapter->media
          && a->physical_media == adapter->physical_media)
        name_number++;
    }
  ssh_snprintf(adapter->ssh_name, sizeof adapter->ssh_name, "%s%d",
               name_prefix, name_number);

  /* Update wireless settings. */
  if (adapter->physical_media == NdisPhysicalMediumWirelessLan)
    {
      status = ssh_adapter_update_wireless(adapter);
      if (NDIS_STATUS_SUCCESS != status)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Adapter %@: Failed to update wireless settings",
                     ssh_adapter_id_st_render, adapter));

          goto rebind_protocols;
        }
    }

  /* Update the CE bindings as appropriate. */
  status = ssh_adapter_update_config(adapter, adapter->is_wan_adapter);

  if (NDIS_STATUS_SUCCESS != status) 
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Failed to update bindings", 
                 ssh_adapter_id_st_render, adapter));

      goto rebind_protocols;
    }

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Check whether this adapter is our own virtual adapter! */
  buf = ssh_calloc(1, 256);
  if (buf == NULL)  
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate VNIC query buffer"));
    }
  else if ((len =
            ssh_adapter_nic_get(adapter, OID_SSH_QUERY_INTERFACE, buf, 256)))
    {
      if (ssh_is_virtual_adapter_interface(buf, len))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("'%s' is a QuickSec Virtual Adapter", 
                     adapter->ssh_name));

          adapter->is_vnic = 1;
          adapter->vnic_interface = buf;
          adapter->vnic_interface_size = len;
        }
      else
        {
          ssh_free(buf);
        }
    }
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  if (!ssh_adapter_nic_get(adapter, OID_GEN_MEDIA_CONNECT_STATUS,
                           &media_state, sizeof media_state) ||
      media_state == NdisMediaStateConnected)
    adapter->media_connected = TRUE;
  else
    adapter->media_connected = FALSE;

  /* 'Attach' operation is complete now. The completion callback must be
     called before NdisIMInitializeDeviceInstanceEx(). */
  if (callback)
    (*callback)(TRUE, callback_context);
  callback = NULL_FNPTR;

  /* Try to initialize our intermediate device */
  InterlockedExchange(&adapter->init_pending, 1);
  status = 
    NdisIMInitializeDeviceInstanceEx(interceptor->miniport_handle,
                                     &adapter->name,
                                     adapter);

  if (status != NDIS_STATUS_SUCCESS)
    {
      SshAttachFailureCleanupCtx ctx;

 rebind_protocols:
      InterlockedExchange(&adapter->init_pending, 0);

      SSH_DEBUG(SSH_D_FAIL,
                ("Adapter %@: initialization failed!", 
                 ssh_adapter_id_st_render, adapter));

      if (callback)
        (*callback)(FALSE, callback_context);

      InterlockedIncrement(&interceptor->ref_count);

      ctx = ssh_calloc(1, sizeof(*ctx));
      if (ctx != NULL)
        {
          ctx->adapter = adapter;
          ctx->destroy_adapter = 1;
          ctx->close_adapter = 1;

          if ((protocol_unbind != FALSE)
              && ((protocol_list != NULL) && (*protocol_list != _T('\0'))))
            {
              size_t list_size;

              ctx->restore_bindings = 1;

              list_size = (wcslen(protocol_list) + 1) * sizeof(WCHAR);

              ctx->protocol_list = ssh_calloc(1, list_size);
              if (ctx->protocol_list != NULL)
                {
                  memcpy(ctx->protocol_list, protocol_list, list_size);
                }
              else
                {
                  ctx->restore_bindings = 0;
                }
            }

          if (ssh_ndis_wrkqueue_queue_item(interceptor->work_queue,
                                           ssh_winim_attach_failure_cleanup,
                                           ctx))
            {
              return;	      
            }

          ssh_free(ctx);
        }

      InterlockedDecrement(&interceptor->ref_count);
    }
  
  return;

 failed:

  if (callback)
    (*callback)(FALSE, callback_context);
}

#else

static void
ssh_winim_attach_adapter(SshAdapter generic_adapter,
                         void *attach_context,
                         SshAdapterAttachCompleteCb callback,
                         void *callback_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)generic_adapter;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  NDIS_STATUS open_status = NDIS_STATUS_SUCCESS;
  SshNdisIMInterceptor interceptor;
  NDIS_MEDIUM lan_medium_array[] = {NdisMedium802_3, NdisMediumWan};
  PNDIS_MEDIUM medium_array = lan_medium_array;
  UINT medium_cnt = (sizeof(lan_medium_array) / sizeof(lan_medium_array[0]));
  UINT medium_idx = 0;
  NDIS_HANDLE protocol_handle;
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  PVOID buf;
  UINT len;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  SSH_ASSERT(adapter->bind_context != NULL);

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  protocol_handle = interceptor->protocol_handle;

  if (adapter->config_handle == NULL)
    goto failed;

  /* Init adapter attributes */
  if (ssh_adapter_get_device_name(adapter) == NULL)
    goto failed;

  /* Try to open the networking device below */
  ssh_event_reset(adapter->wait_event);
  NdisOpenAdapter(&status, 
                  &open_status,
                  &adapter->binding_handle,
                  &medium_idx, 
                  medium_array,
                  medium_cnt,
                  protocol_handle,
                  adapter, 
                  &adapter->orig_name, 
                  0, 
                  NULL);

  /* Wait until adapter open operation is completed */
  if (status == NDIS_STATUS_PENDING)
    {
      ssh_event_wait(1, &adapter->wait_event, NULL);
      status = adapter->result;
    }

  /* Opening the underlaying adapter has failed so return with error */
  if (status != NDIS_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("- adapter (%u) open failed", adapter->ifnum));
      goto failed;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- adapter(%d) open completed", adapter->ifnum));

  /* Update adapter state, save media type */
  adapter->media = medium_array[medium_idx];

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Check whether this adapter is our own virtual adapter! */
  buf = ssh_calloc(1, 256);
  if (buf == NULL)  
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate VNIC query buffer"));
    }
  else if ((len =
            ssh_adapter_nic_get(adapter, OID_SSH_QUERY_INTERFACE, buf, 256)))
    {
      if (ssh_is_virtual_adapter_interface(buf, len))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("'%s' is a QuickSec Virtual Adapter", 
                     adapter->ssh_name));

          adapter->is_vnic = 1;
          adapter->vnic_interface = buf;
          adapter->vnic_interface_size = len;
        }
      else
        {
          ssh_free(buf);
        }
    }
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* 'Attach' operation is complete now. The completion callback must be
     called before NdisIMInitializeDeviceInstanceEx(). */
  if (callback)
    (*callback)(TRUE, callback_context);
  callback = NULL_FNPTR;

  /* Try to initialize our intermediate device */
  InterlockedExchange(&adapter->init_pending, 1);
  status = 
    NdisIMInitializeDeviceInstanceEx(interceptor->miniport_handle,
                                     &adapter->name,
                                     adapter);
  if (status != NDIS_STATUS_SUCCESS) 
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("- adapter(%d): initialization failed!", adapter->ifnum));

      ssh_adapter_close(adapter); 
    }

  return;

 failed:
  if (callback)
    (*callback)(FALSE, callback_context);
}
#endif /* _WIN32_WCE */


/*--------------------------------------------------------------------------
  ssh_adapter_close()

  Deinitializes SSH Adapter object and then removes binding by closing the
  underlaying NIC.

  Arguments:
  adapter - adapter object

  Notes:
  This function is called from ProtocolUnbindAdapter (handler) to start
  unbind process between SSH Adapter and underlaying real network device.
  --------------------------------------------------------------------------*/
void
ssh_adapter_close(SshNdisIMAdapter adapter)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  SSH_ASSERT(SSH_GET_IRQL() == SSH_PASSIVE_LEVEL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: close", ssh_adapter_id_st_render, adapter));

  /* We should call NdisIMCancelInitializeDeviceInstance if the 
     "MiniportInitialize" haven't been called yet by NDIS library. */
  ssh_event_reset(adapter->wait_event);
  if (InterlockedExchange(&adapter->init_pending, 0) != 0)
    {
      SshNdisIMInterceptor interceptor;

      interceptor = (SshNdisIMInterceptor)adapter->interceptor;

      /* Try to cancel the initialization */
      if (NdisIMCancelInitializeDeviceInstance(
                                      interceptor->miniport_handle,
                                      &adapter->name) == NDIS_STATUS_SUCCESS)
        {
          /* Successfully cancelled the initialization */
          SSH_ASSERT(adapter->handle == NULL);
        }
      else
        {
          /* Could not cancel, so our "MiniportInitialize" will be called.
             We must wait it to finish. */
          ssh_event_wait(1, &adapter->wait_event, NULL);
        }
    }

  /* Check current state */
 check_state:
  switch (adapter->state)
    {
    case SSH_ADAPTER_STATE_RESTARTING:
      ssh_adapter_wait_until_state_transition_complete((SshAdapter)adapter);
      goto check_state;
      
    case SSH_ADAPTER_STATE_DETACHED:
    case SSH_ADAPTER_STATE_PAUSING:
      break;

    case SSH_ADAPTER_STATE_RUNNING:
      ssh_adapter_pause_common((SshAdapter)adapter,
                               SSH_ADAPTER_PAUSE_REASON_UNSPECIFIED,
                               ssh_winim_pause_adapter,
                               adapter);
    case SSH_ADAPTER_STATE_PAUSED:
      ssh_adapter_detach_common((SshAdapter)adapter, 
                                ssh_winim_detach_adapter,
                                adapter);
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@ closed", ssh_adapter_id_st_render, adapter));
}


static void
ssh_winim_detach_adapter(SshAdapter generic_adapter,
                         void *pause_context,
                         SshAdapterPauseCompleteCb callback,
                         void *callback_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)generic_adapter;
  SshNdisIMInterceptor interceptor;
  NDIS_STATUS status;

  SSH_ASSERT(adapter != NULL);
  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: detach", ssh_adapter_id_st_render, adapter));

  /* 'binding_handle' is still valid if the adapter is closed from
     non-running (paused) state. */
  if (adapter->binding_handle != NULL)
    {
      ssh_event_reset(adapter->wait_event);
      NdisCloseAdapter(&status, adapter->binding_handle);
      /* Wait until adapter close operation is completed */
      if (status == NDIS_STATUS_PENDING)
        ssh_event_wait(1, &adapter->wait_event, NULL);

      adapter->binding_handle = NULL;
    }

  /* Check if adapter handle exist */
  if (adapter->handle != NULL)
    {
      /* Deinitialize our IM device */
      status = NdisIMDeInitializeDeviceInstance(adapter->handle);
      if (status != NDIS_STATUS_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Adapter %@ deinitialize failed", 
                     ssh_adapter_id_st_render, adapter));
        }

      adapter->handle = NULL;
    }

#ifndef _WIN32_WCE
  /* Destroy the I/O device if this was the last bound adapter */
  if (ssh_adapter_find_by_state(interceptor, 
                                SSH_ADAPTER_STATE_RUNNING) == NULL)
    {
      ssh_interceptor_ipm_device_destroy(adapter->interceptor);
    }
#endif /* _WIN32_WCE */

  if (callback)
    (*callback)(callback_context);
}


/*--------------------------------------------------------------------------
  ssh_adapter_enable()
  
  Enables/Disables SSH Adapter object.

  Arguments:
  adapter - adapter object
  enable - Enable(Disable) flag

  Returns:
  NDIS_STATUS_SUCCESS - success
  NDIS_STATUS_FAILURE - otherwise. 

  Notes:
  When adapter is enabled all queued NDIS packets are sent to the
  engine for post-processing. When adapter is disabled we reject all
  incoming and outgoing NDIS packets.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_enable(SshNdisIMAdapter adapter,
                   BOOLEAN enable)
{
  SshNdisIMInterceptor interceptor;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);

  /* Update adapter state */
  adapter->enabled = enable;

  /* Refresh IP interface and routing information */
  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  SSH_IP_FORCE_REFRESH_REQUEST(interceptor, SSH_IP_REFRESH_REPORT);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: %s", 
             ssh_adapter_id_st_render, adapter, 
             (enable == TRUE ? "enable":"disable")));

  return (NDIS_STATUS_SUCCESS);
}


/*--------------------------------------------------------------------------
  ssh_adapter_initialize()
  
  Initializes SSH Adapter object so that we are ready to intercept network
  data flowing between us and underlaying network device. 

  Arguments:
  adapter - adapter object
  miniport_adapter_handle - NDIS handle of our SSH Adapter
  config_handle - NDIS handle for SSH Adapter configuration queries
  medium_array_size - size of medium array
  medium_array - medium array
  medium_index - position in medium array that describes the media type

  Returns:
  NDIS_STATUS_SUCCESS - success
  NDIS_STATUS_FAILURE - otherwise. 

  Notes:
  This function is called from our driver's MiniportInitialize (handler).
  SSH Packet Manager object is created for NDIS packet and NDIS buffer
  processing.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_initialize(SshNdisIMAdapter adapter,
                       NDIS_HANDLE miniport_adapter_handle,
                       NDIS_HANDLE config_handle,
                       UINT medium_array_size,
                       PNDIS_MEDIUM medium_array,
                       UINT *medium_index)
{
  UINT i = 0;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  PVOID buf = NULL;
  ULONG buf_size = 0L;
  SshNdisIMInterceptor interceptor;

  *medium_index = medium_array_size;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  SSH_ASSERT(miniport_adapter_handle != NULL);
  SSH_ASSERT(config_handle != NULL);
  SSH_ASSERT(medium_array_size > 0);
  SSH_ASSERT(medium_array != NULL);
  SSH_ASSERT(medium_index != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: initialize", ssh_adapter_id_st_render, adapter));

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;

  /* We assume that the power states must be D0 (fully powered), otherwise 
     we should not be here... */
  adapter->underlying_mp_power_state = NdisDeviceStateD0;
  adapter->virtual_mp_power_state = NdisDeviceStateD0;
  adapter->standing_by = FALSE;
  
  /* Check that the selected medium is the right one */
  for (i = 0; i < medium_array_size; i++)
    {
#ifndef _WIN32_WCE
      /* WAN: return NdisMedium802_3 instead of NdisMediumWan to layer the 
         driver above NDISWAN driver */
      if (adapter->media == NdisMediumWan) 
        {
          if (medium_array[i] == NdisMedium802_3) 
            {
              *medium_index = i;
              break;
            }
        } 
      else 
#endif /* _WIN32_WCE */
      if (adapter->media == medium_array[i]) 
        {
          *medium_index = i;
          break;
        }
     }

  /* Medium is not the right one so return with failure */
  if (*medium_index == medium_array_size)
    {
      status = NDIS_STATUS_UNSUPPORTED_MEDIA;
      goto init_complete;
    }

  /* Set the hard-coded physical address for WAN adapter */
  if (adapter->media == NdisMediumWan)
    {
      RtlCopyMemory(adapter->media_addr, SSH_ADAPTER_PHYS_ADDRESS_WAN, 6);
      adapter->media_addr_len = 6; 
    }

  /* Save the miniport handle. This is needed for NdisM....() operations */
  adapter->handle = miniport_adapter_handle;
  if (!ssh_adapter_restart_common((SshAdapter)adapter,
                                  ssh_winim_restart_adapter, 
                                  adapter))
    {
      adapter->handle = NULL;
      status = NDIS_STATUS_FAILURE;
    }

 init_complete:

  /* Signal that initialization is completed */
  ssh_adapter_wait_until_state_transition_complete((SshAdapter)adapter);
  InterlockedExchange(&adapter->init_pending, 0);
  ssh_event_signal(adapter->wait_event);

  return (status);
}


static void
ssh_winim_restart_adapter(SshAdapter generic_adapter, 
                          void *restart_context,
                          SshAdapterRestartCompleteCb callback,
                          void *completion_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)generic_adapter;
  SshNdisIMInterceptor interceptor;
  Boolean status = TRUE;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: setting attributes",
             ssh_adapter_id_st_render, adapter));

  /* Set the attributes for our device */
  NdisMSetAttributesEx(adapter->handle,
                       adapter,
                       SSH_ADAPTER_CHECK_FOR_HANG_INTERVAL,
                       SSH_ADAPTER_ATTRIBUTES, 
                       0);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: registering media status indication",
             ssh_adapter_id_st_render, adapter));

  /* Generate media connection status indication to upper layers. (This
     can't be done directly in the current context. See details from
     DDK decumentation) */
  ssh_kernel_timeout_register(0, 10000, 
                              ssh_adapter_send_media_status, adapter);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@ initialize done.", 
             ssh_adapter_id_st_render, adapter));

  if (callback)
    (*callback)(status, completion_context);

  if (status != FALSE)
    ssh_adapter_enable(adapter, TRUE);
}


/*--------------------------------------------------------------------------
  ssh_adapter_deinitialize()
  
  Deinitializes SSH Adapter object by removing it from the SSH Interceptor's
  adapter list and then release resources allocated for networking packet
  processing.

  Arguments:
  adapter - adapter object

  Returns:

  Notes:
  This function is called from MiniPortHalt handler. We wait until all
  NDIS_PACKET's are processed 
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_deinitialize(SshNdisIMAdapter adapter)
{
  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: deinitialize", ssh_adapter_id_st_render, adapter));

  /* Cancel the media status indication if it hasn't been delivered yet. */
  ssh_kernel_timeout_cancel(ssh_adapter_send_media_status, adapter);

  ssh_adapter_enable(adapter, FALSE);

  switch (adapter->state)
    {
    case SSH_ADAPTER_STATE_DETACHED:
    case SSH_ADAPTER_STATE_PAUSING:
    case SSH_ADAPTER_STATE_PAUSED:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@ already closed", 
                 ssh_adapter_id_st_render, adapter));
      break;

    default:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@ not closed yet", 
                 ssh_adapter_id_st_render, adapter));

      adapter->underlying_mp_power_state = NdisDeviceStateD3;
      adapter->virtual_mp_power_state = NdisDeviceStateD3;
      adapter->standing_by = TRUE;
      ssh_adapter_close(adapter);
      break;
    }


  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@ deinitialize done.", 
             ssh_adapter_id_st_render, adapter));
}


static void
ssh_winim_pause_adapter(SshAdapter generic_adapter,
                        void *pause_context,
                        SshAdapterPauseCompleteCb callback,
                        void *callback_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)generic_adapter;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Deregister SSH Virtual Adapter */
  if (adapter->va)
    {
      void *va = adapter->va;
      adapter->va = NULL;

      ssh_virtual_adapter_deregister(va);
    }
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */ 

  /* Check if underlaying device has been opened */
  if (adapter->binding_handle != NULL)
    {
      NDIS_STATUS status;

      ssh_event_reset(adapter->wait_event);
      NdisCloseAdapter(&status, adapter->binding_handle);
      /* Wait until adapter close operation is completed */
      if (status == NDIS_STATUS_PENDING)
        ssh_event_wait(1, &adapter->wait_event, NULL);

      /* Binding handle cannot be used anymore */
      adapter->binding_handle = NULL;
    }

  ssh_adapter_complete_queued_requests(adapter, NDIS_STATUS_FAILURE);

  if (callback)
    (*callback)(callback_context);
}


/*--------------------------------------------------------------------------
  FUNCTIONS FOR INTERCEPTING ADAPTER REQUESTS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_adapter_send_request()
  
  Sends NDIS OID Set/Query request to underlaying network driver.

  Arguments:
  adapter - adapter object
  request - NDIS OID Set/Query request
  status - Request result

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_send_request(SshNdisIMAdapter adapter,
                         PNDIS_REQUEST request,
                         NDIS_STATUS *status)
{
  SshRequest temp;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);
  SSH_ASSERT(status != NULL);

  temp = CONTAINING_RECORD(request, SshRequestStruct, orig_request);

  /* Send request to underlaying device */
  NdisRequest(status, adapter->binding_handle, request);

  /* Check if request has been completed and then call completion routine */ 
  if (*status != NDIS_STATUS_PENDING)
    {
      if (temp->queued == FALSE)
        temp->asynch_completion = FALSE;

      temp->request_done_cb(adapter, request, *status);
    }
}


/*--------------------------------------------------------------------------
  ssh_adapter_send_queued_requests()
  
  Sends queued (if any) NDIS OID Set/Query requests to underlaying network 
  driver. This function should be called when the power state of underlying
  miniport driver becomes D0 (i.e. fully powered).

  Arguments:
  adapter - adapter object

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_send_queued_requests(SshNdisIMAdapter adapter)
{
  PNDIS_REQUEST query_request;
  PNDIS_REQUEST set_request;
  NDIS_STATUS status;

  NdisAcquireSpinLock(&adapter->power_mgmt_lock);
  query_request = adapter->pending_query_request;
  set_request = adapter->pending_set_request;
  adapter->pending_query_request = NULL;
  adapter->pending_set_request = NULL;
  NdisReleaseSpinLock(&adapter->power_mgmt_lock);

  if (query_request)
    ssh_adapter_send_request(adapter, query_request, &status);

  if (set_request)
    ssh_adapter_send_request(adapter, set_request, &status);
}


/*--------------------------------------------------------------------------
  ssh_adapter_complete_queued_requests()
  
  Completes queued (if any) NDIS OID Set/Query requests with the specified
  error code without delevering the requests to underlaying miniport 
  driver. 

  Arguments:
  adapter - adapter object
  status - error code.

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_complete_queued_requests(SshNdisIMAdapter adapter,
                                     NDIS_STATUS status)
{
  PNDIS_REQUEST query_request;
  PNDIS_REQUEST set_request;

  NdisAcquireSpinLock(&adapter->power_mgmt_lock);
  query_request = adapter->pending_query_request;
  set_request = adapter->pending_set_request;
  adapter->pending_query_request = NULL;
  adapter->pending_set_request = NULL;
  NdisReleaseSpinLock(&adapter->power_mgmt_lock);

  if (query_request)
    {
      SSH_ASSERT(query_request->DATA.QUERY_INFORMATION.BytesWritten == 0);
      SSH_ASSERT(query_request->DATA.QUERY_INFORMATION.BytesNeeded == 0);

      ssh_adapter_query_request_finish(adapter, query_request, status);
    }

  if (set_request)
    {
      SSH_ASSERT(set_request->DATA.SET_INFORMATION.BytesRead == 0);
      SSH_ASSERT(set_request->DATA.SET_INFORMATION.BytesNeeded == 0);

      ssh_adapter_set_request_finish(adapter, set_request, status);
    }
}

/*--------------------------------------------------------------------------
  Handles the OID_PNP_QUERY_POWER request.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_query_power(SshNdisIMAdapter adapter,
                               PVOID info,
                               ULONG info_len,
                               PULONG bytes_written,
                               PULONG bytes_needed)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(info != NULL);
  SSH_ASSERT(bytes_written != NULL);
  SSH_ASSERT(bytes_needed != NULL);

  /* We are ready to switch power state */
  *bytes_written = 0;
  *bytes_needed = 0;

  /* Complete query successfully */
  return NDIS_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
  ssh_adapter_handle_query_request()
  
  Handles NDIS OID Query request.

  Arguments:
  adapter - adapter object
  request - NDIS OID Query request

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_query_request(SshNdisIMAdapter adapter, 
                                 PNDIS_REQUEST request)
{
  /* Init return value to pending because all QUERY requests that
     are propagated to underlaying device are completed
     asynchronously */
  NDIS_STATUS status = NDIS_STATUS_PENDING;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  if ((adapter->virtual_mp_power_state != NdisDeviceStateD0)
      || (adapter->standing_by == TRUE)
      || (adapter->state != SSH_ADAPTER_STATE_RUNNING))
    {
      /* Fail the request! */
      InterlockedIncrement(&adapter->outstanding_requests);
      ssh_adapter_request_reject(adapter, request, &status);
    }
  else if (adapter->underlying_mp_power_state != NdisDeviceStateD0)
    {
      InterlockedIncrement(&adapter->outstanding_requests);
#ifdef _WIN32_WCE
      /* Fail the request! */
      ssh_adapter_request_reject(adapter, request, &status);
#else /* _WIN32_WCE */
      /* Queue first request */
      ssh_adapter_request_queue(adapter, request, &status);
#endif /* _WIN32_WCE */
    }
  else
    {
      switch (request->DATA.QUERY_INFORMATION.Oid)
        {
        case OID_TCP_TASK_OFFLOAD:
          /* Handle task offloading query locally */
          ssh_adapter_query_task_offload(adapter, request, &status);
          break;

        default:
          /* Propagate request to underlaying device driver */
          InterlockedIncrement(&adapter->outstanding_requests);
          ssh_adapter_send_request(adapter, request, &status);
          break;
        }
    }

  return (status);
}


/*--------------------------------------------------------------------------
  ssh_adapter_handle_set_request()
  
  Handles NDIS OID_PNP_SET_POWER request.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_set_power(SshNdisIMAdapter adapter,
                             PVOID info,
                             ULONG info_len,
                             PULONG bytes_read,
                             PULONG bytes_needed)
{
  NDIS_DEVICE_POWER_STATE power = NdisDeviceStateD3; 
#ifdef _WIN32_WCE
  WCHAR *device;
  NDIS_DEVICE_POWER_STATE underlying_power;
#endif /* _WIN32_WCE */

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(info != NULL);
  SSH_ASSERT(bytes_read != NULL);
  SSH_ASSERT(bytes_needed != NULL);

  power = *((PNDIS_DEVICE_POWER_STATE)info);

  /* Sanity check for information buffer length */
  if (info_len == sizeof(power))
    {
      /* Update adapter's state according to the power state */ 
      if (adapter->virtual_mp_power_state != power)
        {
          SshInterceptor interceptor = adapter->interceptor;

#ifdef _WIN32_WCE
          if (adapter->physical_media == NdisPhysicalMediumWirelessLan)
            {
              device = ssh_malloc(MAX_PATH * sizeof *device);
              if (!device)
                return NDIS_STATUS_FAILURE;

              StringCchPrintfW(
                device, MAX_PATH,
                L"{98C5250D-C29A-4985-AE5F-AFE5367E5006}\\%s",
                adapter->orig_name.Buffer);

              if (power == NdisDeviceStateD0)
                underlying_power = D0;
              else
                underlying_power = D4;

              SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                ("SetDevicePower(%d), device:", (int)underlying_power),
                (const unsigned char *)device,
                wcslen(device) * sizeof *device);

              if (SetDevicePower(device, POWER_NAME, underlying_power) !=
                  ERROR_SUCCESS)
                {
                  SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                    ("SetDevicePower(%d) failed, device:",
                     (int)underlying_power),
                    (const unsigned char *)device,
                    wcslen(device) * sizeof *device);
                  ssh_free(device);
                  return NDIS_STATUS_FAILURE;
                }
              ssh_free(device);
            }
#endif /* _WIN32_WCE */

          if (power != NdisDeviceStateD0)
            adapter->standing_by = TRUE;
          else
            adapter->standing_by = FALSE;

          adapter->virtual_mp_power_state = power;

          if (power == NdisDeviceStateD3) 
            {
              ssh_interceptor_suspend_if_idle(interceptor);
            }
          else if ((power == NdisDeviceStateD0) &&
                   (interceptor->low_power_state == TRUE))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Waking up from Standby/Hibernate..."));

              ssh_interceptor_resume(interceptor);
              interceptor->low_power_state = FALSE;
            }
        }

      *bytes_read = sizeof(power);
      *bytes_needed = 0;

      return NDIS_STATUS_SUCCESS;
    }
  else
    {
      *bytes_read = 0;
      *bytes_needed = sizeof(power);

      return NDIS_STATUS_INVALID_LENGTH;
    }
}


/*--------------------------------------------------------------------------
  ssh_adapter_handle_set_request()
  
  Handles NDIS OID Set request.

  Arguments:
  adapter - adapter object
  request - NDIS OID Set request

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_set_request(SshNdisIMAdapter adapter, 
                               PNDIS_REQUEST request)
{
  /* Init return value to pending because all SET requests that
     are propagated to underlaying device are completed
     asynchronously */
  NDIS_STATUS status = NDIS_STATUS_PENDING;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  if ((adapter->virtual_mp_power_state != NdisDeviceStateD0)
      || (adapter->standing_by == TRUE)
      || (adapter->state != SSH_ADAPTER_STATE_RUNNING))
    {
      /* Fail the request! */
      InterlockedIncrement(&adapter->outstanding_requests);
      ssh_adapter_request_reject(adapter, request, &status);
    }
  else if (adapter->underlying_mp_power_state != NdisDeviceStateD0)
    {
      InterlockedIncrement(&adapter->outstanding_requests);
#ifdef _WIN32_WCE
      /* Fail the request! */
      ssh_adapter_request_reject(adapter, request, &status);
#else /* _WIN32_WCE */
      /* Queue first request */
      ssh_adapter_request_queue(adapter, request, &status);
#endif /* _WIN32_WCE */
    }
  else
    {
      switch (request->DATA.SET_INFORMATION.Oid)
        {
        case OID_TCP_TASK_OFFLOAD:
          /* Handle task offloading set request locally */
          ssh_adapter_set_task_offload(adapter, request, &status);
          break;

        default:
          /* Propagate request to underlaying device driver */
          InterlockedIncrement(&adapter->outstanding_requests);
          ssh_adapter_send_request(adapter, request, &status);
          break;
        }
    }

  return (status);
}

/*--------------------------------------------------------------------------
  ssh_adapter_set_request_done()
  
  Completion routine for NDIS OID Set request.

  Arguments:
  adapter - adapter object
  request - NDIS OID Set request
  status - Request result

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_set_request_done(SshNdisIMAdapter adapter,
                             PNDIS_REQUEST request,
                             NDIS_STATUS status)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: request(SET, oid=%@, status=%@) done",
             ssh_adapter_id_st_render, adapter, 
             ssh_ndis_oid_render, &request->DATA.SET_INFORMATION.Oid, 
             ssh_ndis_status_render, &status));

  /* Process SET operation results */
  switch (request->DATA.SET_INFORMATION.Oid)
    {
    default:
      break;

    case OID_GEN_CURRENT_PACKET_FILTER:
      ssh_adapter_handle_set_current_packet_filter(adapter, request, status);
      break;

    case OID_GEN_CURRENT_LOOKAHEAD:
      ssh_adapter_handle_set_current_lookahead_result(adapter, 
                                                      request, 
                                                      status);
      break;

    case OID_GEN_VLAN_ID:
      ssh_adapter_handle_set_vlan_id_result(adapter, request, status);
      break;
    }

  /* Finish SET request */
  ssh_adapter_set_request_finish(adapter, request, status);
}

/*--------------------------------------------------------------------------
  ssh_adapter_query_request_done()
  
  Completion routine for NDIS OID Query request.

  Arguments:
  adapter - adapter object
  request - NDIS OID Query request
  status - Request result

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_query_request_done(SshNdisIMAdapter adapter,
                               PNDIS_REQUEST request,
                               NDIS_STATUS status)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: request(QUERY, oid=%@, status=%@) done",
             ssh_adapter_id_st_render, adapter, 
             ssh_ndis_oid_render, &request->DATA.QUERY_INFORMATION.Oid,
             ssh_ndis_status_render, &status));

  /* Process QUERY results */
  switch (request->DATA.QUERY_INFORMATION.Oid)
    {
    default:
      ssh_adapter_query_request_finish(adapter, request, status);
      break;

      /* General Options */
    case OID_GEN_MAC_OPTIONS:
      ssh_adapter_handle_query_mac_options_result(adapter, 
                                                  request, 
                                                  status);
      ssh_adapter_query_request_finish(adapter, request, status);
      break;

    case OID_GEN_VLAN_ID:
      ssh_adapter_handle_query_vlan_id_result(adapter, request, status);
      ssh_adapter_query_request_finish(adapter, request, status);
      break;

      /* Plug and Play Capabilities */
    case OID_PNP_CAPABILITIES:
      ssh_adapter_handle_query_pnp_capabilities_result(adapter, 
                                                       request, 
                                                       status); 
      ssh_adapter_query_request_finish(adapter, request, status);
      break;

      /* Local MAC (hardware) address */
    case OID_802_3_CURRENT_ADDRESS:
      ssh_adapter_handle_query_mac_address_result(adapter, 
                                                  request, 
                                                  status);
      ssh_adapter_query_request_finish(adapter, request, status);
      break;
#ifdef _WIN32_WCE
    case OID_WAN_GET_INFO:
      ssh_adapter_handle_query_wan_info_result(adapter, 
                                               request, 
                                               status);
      ssh_adapter_query_request_finish(adapter, request, status);
      break;
#endif /* _WIN32_WCE */
    }
}

/*--------------------------------------------------------------------------
  FUNCTIONS FOR WAN CONNECTION CONTROL
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_adapter_wan_line_up()
  
  Establishes a new WAN connection.
  
  Arguments:
  adapter - adapter object
  buf - dial-up interface information
  len - dial-up interface information length

  Returns:

  Notes:
  The IP address information for WAN connection is retrieved from
  NDIS_WAN_LINE_UP indication information. The indication parameters 
  contains a ProtocolBuffer byte array that's structure is not known but
  it seems to contain the IP address and network mask in a fixed position.  
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_wan_line_up(SshNdisIMAdapter adapter, 
                        PNDIS_WAN_LINE_UP buf,
                        UINT len) 
{ 
  SshUInt16 copy_len;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(buf != NULL);

  /* Propage indication to upper layer

     Note:
     We must do this in correct order because upper layer fills
     the local device address field in NDIS_WAN_LINE_UP structure
     and this field is utilized when constructing media header for
     WAN packets. */

  copy_len = adapter->name.Length;
  if (copy_len > buf->DeviceName.MaximumLength)
    copy_len = buf->DeviceName.MaximumLength;

  NdisZeroMemory(buf->DeviceName.Buffer, buf->DeviceName.MaximumLength);
  NdisMoveMemory(buf->DeviceName.Buffer, adapter->name.Buffer, copy_len);
  buf->DeviceName.Length = copy_len;
  
  NdisMIndicateStatus(adapter->handle, NDIS_STATUS_WAN_LINE_UP, buf, len);
  adapter->status_indicated = 1;

  if (len >= sizeof(NDIS_WAN_LINE_UP))
    ssh_wan_line_up((SshAdapter)adapter, (PNDIS_WAN_LINE_UP)buf);
}

/*--------------------------------------------------------------------------
  ssh_adapter_wan_line_down()
  
  Removes previously established WAN connection.

  Arguments:
  adapter - adapter object
  buf - dial-up interface information
  len - dial-up interface information length

  Returns:

  Notes:
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_wan_line_down(SshNdisIMAdapter adapter, 
                          PNDIS_WAN_LINE_DOWN buf,
                          UINT len) 
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(buf != NULL);

  if (len >= sizeof(NDIS_WAN_LINE_DOWN))
    ssh_wan_line_down((SshAdapter)adapter, (PNDIS_WAN_LINE_DOWN)buf);

  /* Propagate status to upper layer */
  NdisMIndicateStatus(adapter->handle, NDIS_STATUS_WAN_LINE_DOWN, buf, len);
  adapter->status_indicated = 1;

  if (len >= sizeof(NDIS_WAN_LINE_DOWN))
    ssh_wan_line_down((SshAdapter)adapter, (PNDIS_WAN_LINE_DOWN)buf);
}

#ifdef _WIN32_WCE
void
ssh_adapter_rebind(SshAdapter gen_adapter)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)gen_adapter;
  HANDLE ndis_device;
  WCHAR *buffer = NULL;
  DWORD buffer_len;
  DWORD bytes_returned;

  SSH_DEBUG(SSH_D_LOWSTART, 
            ("Adapter %@: Rebind to TCP", ssh_adapter_id_st_render, adapter));

  /* Obtain a handle to the NDIS driver. */
  ndis_device = CreateFile(DD_NDIS_DEVICE_NAME,
                           (GENERIC_READ | GENERIC_WRITE),
                           (FILE_SHARE_READ | FILE_SHARE_WRITE),
                           NULL, OPEN_ALWAYS, 0, NULL);

  if (ndis_device == INVALID_HANDLE_VALUE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to open NDIS device"));
      goto error;
    }

  /* Determine the number of bytes to allocate for the adapter\protocol
     multi_sz. */
  buffer_len = (adapter->name.Length + sizeof(WCHAR))
                + sizeof(PNAME_TCPIP);

  /* Allocate a pre-cleared required buffer. */
  buffer = ssh_calloc(1, buffer_len);
  if (buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate input buffer"));
      goto error;
    }

  /* Deposit the adapter name. */
  memcpy(buffer, adapter->name.Buffer, adapter->name.Length);

  /* Append the protocol. */
  memcpy((buffer + wcslen(buffer) + 1),
         PNAME_TCPIP, sizeof(PNAME_TCPIP));

  /* Perform the IOCTL. */
  if (!DeviceIoControl(ndis_device, IOCTL_NDIS_REBIND_ADAPTER, buffer,
                       buffer_len, NULL, 0, &bytes_returned, NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Rebind failed (%08X)", 
                 ssh_adapter_id_st_render, adapter, GetLastError()));
    }

 error:

  if (ndis_device != INVALID_HANDLE_VALUE)
    CloseHandle(ndis_device);

  ssh_free(buffer);

}
#endif /* _WIN32_WCE */

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Retrieves the name of the adapter from the Windows registry.
  --------------------------------------------------------------------------*/
static PNDIS_STRING 
ssh_adapter_get_device_name(SshNdisIMAdapter adapter)
{
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  NDIS_STRING upper_binding = NDIS_STRING_CONST("UpperBindings");
  PNDIS_CONFIGURATION_PARAMETER config = NULL;
  PNDIS_STRING name = NULL;

  /* Release memory allocated for previous name */
  if (adapter->name.Buffer != NULL)
    ssh_free(adapter->name.Buffer);

  /* Read name from the Windows registry */
  NdisReadConfiguration(&status,
                        &config,
                        adapter->config_handle,
                        &upper_binding,
                        NdisParameterString);

  if (status != NDIS_STATUS_SUCCESS)
    return (NULL);

  /* Init adapter name using the registry entry */
  name = &config->ParameterData.StringData;
  adapter->name.Buffer = ssh_calloc(1, name->MaximumLength);
  if (adapter->name.Buffer == NULL)
    return (NULL);

  adapter->name.MaximumLength = name->MaximumLength;
  adapter->name.Length = name->Length;
  NdisMoveMemory(adapter->name.Buffer,
                 name->Buffer,
                 name->Length);

  return (&adapter->name);
}

/*--------------------------------------------------------------------------
  Fails (i.e. rejects) the given NDIS OID set/query request.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_request_reject(SshNdisIMAdapter adapter,
                           PNDIS_REQUEST request,
                           PNDIS_STATUS status)
{
  SshRequest temp = CONTAINING_RECORD(request,
                                      SshRequestStruct,
                                      orig_request);

  *status = NDIS_STATUS_FAILURE;

  temp->asynch_completion = FALSE;
  temp->request_done_cb(adapter, request, *status);
}


/*--------------------------------------------------------------------------
  Queues first request, fails others.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_request_queue(SshNdisIMAdapter adapter,
                          PNDIS_REQUEST request,
                          PNDIS_STATUS status)
{
  PNDIS_REQUEST *pending;
  SshRequest temp = CONTAINING_RECORD(request,
                                      SshRequestStruct,
                                      orig_request);

#ifndef _WIN32_WCE
  SSH_ASSERT(SSH_GET_IRQL() == SSH_DISPATCH_LEVEL);
#endif /* _WIN32_WCE */

  NdisDprAcquireSpinLock(&adapter->power_mgmt_lock);

  if (request->RequestType == NdisRequestQueryInformation)
    pending = &(adapter->pending_query_request);
  else
    pending = &(adapter->pending_set_request);

  if (*pending == NULL)
    {
      /* Queue only one query/set request */
      *pending = request;

      NdisDprReleaseSpinLock(&adapter->power_mgmt_lock);

      temp->queued = TRUE;
    }
  else
    {
      NdisDprReleaseSpinLock(&adapter->power_mgmt_lock);

      ssh_adapter_request_reject(adapter, request, status);
    }
}


/*--------------------------------------------------------------------------
  Handles the default set request result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_set_request_finish(SshNdisIMAdapter adapter, 
                               PNDIS_REQUEST request, 
                               NDIS_STATUS status)
{
  LONG requests_left;
  SshRequest temp = CONTAINING_RECORD(request, 
                                      SshRequestStruct, 
                                      orig_request);

  /* Fill the return values */
  if (temp->bytes_read_written != NULL)
    *temp->bytes_read_written = request->DATA.SET_INFORMATION.BytesRead;

  if (temp->bytes_needed != NULL)
    *temp->bytes_needed = request->DATA.SET_INFORMATION.BytesNeeded;

  if (temp->asynch_completion == TRUE)
    {
      /* Complete request with status code */
      if (adapter->handle != NULL)
        NdisMSetInformationComplete(adapter->handle, status);
    }

  /* Release memory allocated for request */
  NdisFreeToNPagedLookasideList(&adapter->request_list, temp);

  requests_left = InterlockedDecrement(&adapter->outstanding_requests);

  SSH_ASSERT(requests_left >= 0);
}

/*--------------------------------------------------------------------------
  Handles the default query request results.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_query_request_finish(SshNdisIMAdapter adapter, 
                                 PNDIS_REQUEST request, 
                                 NDIS_STATUS status)
{
  LONG requests_left;
  SshRequest temp = CONTAINING_RECORD(request, 
                                      SshRequestStruct, 
                                      orig_request);

  /* Fill the return values */
  if (temp->bytes_read_written != NULL)
    *temp->bytes_read_written = request->DATA.QUERY_INFORMATION.BytesWritten;

  if (temp->bytes_needed != NULL)
    *temp->bytes_needed = request->DATA.QUERY_INFORMATION.BytesNeeded;

  if (temp->asynch_completion == TRUE)
    {
      /* Complete request with status code */
      if (adapter->handle != NULL)
        NdisMQueryInformationComplete(adapter->handle, status);
    }

  /* Release memory allocated for request */
  NdisFreeToNPagedLookasideList(&adapter->request_list, temp);

  requests_left = InterlockedDecrement(&adapter->outstanding_requests);

  SSH_ASSERT(requests_left >= 0);
}

/*--------------------------------------------------------------------------
  Handles the TASK OFFLOAD set request.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_set_task_offload(SshNdisIMAdapter adapter,
                             PNDIS_REQUEST set,
                             NDIS_STATUS *status)
{
  SshRequest request = CONTAINING_RECORD(set, 
                                         SshRequestStruct, 
                                         orig_request);

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(set != NULL);
  SSH_ASSERT(request != NULL);
  SSH_ASSERT(status != NULL);

  if (request->bytes_read_written != NULL)
    *request->bytes_read_written = 0;

  if (request->bytes_needed != NULL)
    *request->bytes_needed = 0;

  /* Do not allow task offloading */
  *status = NDIS_STATUS_NOT_SUPPORTED;

  /* Release memory allocated for request */
  NdisFreeToNPagedLookasideList(&adapter->request_list, request);
}

/*--------------------------------------------------------------------------
  Handles the OID_PNP_SET_POWER request.
  --------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------
  Handles the TASK OFFLOAD query request.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_query_task_offload(SshNdisIMAdapter adapter,
                               PNDIS_REQUEST query,
                               NDIS_STATUS *status)
{
  SshRequest request = CONTAINING_RECORD(query, 
                                         SshRequestStruct, 
                                         orig_request);

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(query != NULL);
  SSH_ASSERT(request != NULL);
  SSH_ASSERT(status != NULL);

  if (request->bytes_read_written != NULL)
    *request->bytes_read_written = 0;

  if (request->bytes_needed != NULL)
    *request->bytes_needed = 0;

  /* Do not allow task offloading */
  *status = NDIS_STATUS_NOT_SUPPORTED;

  /* Release memory allocated for request */
  NdisFreeToNPagedLookasideList(&adapter->request_list, request);
}

/*--------------------------------------------------------------------------
  Intercepts the OID_GEN_MAC_OPTIONS query result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_query_mac_options_result(SshNdisIMAdapter adapter, 
                                            PNDIS_REQUEST request, 
                                            NDIS_STATUS status)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  /* Check that query succeeded */
  if (ssh_query_success(status, &request->DATA.QUERY_INFORMATION, 4))
    {
      ULONG *options;

      options = ((ULONG *)request->DATA.QUERY_INFORMATION.InformationBuffer);

      /* Set transfers as non-pending because we always indicate
         complete packets to upper layer */
      *options |= NDIS_MAC_OPTION_TRANSFERS_NOT_PEND; 

      /* Save adapter options so that we can then use the right memory copy
         operations in network data receive handler (ssh_driver_receive()) */
      adapter->options = *options;
    }
}


/*--------------------------------------------------------------------------
  Intercepts the OID_PNP_CAPABILITIES query result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_query_pnp_capabilities_result(SshNdisIMAdapter adapter, 
                                                 PNDIS_REQUEST request, 
                                                 NDIS_STATUS status)
{
  PNDIS_PNP_CAPABILITIES pnp_capability = NULL;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  if (ssh_query_success(status, 
                        &request->DATA.QUERY_INFORMATION, 
                        sizeof(NDIS_PNP_CAPABILITIES)))
    {
      /* Adapter wake-up not supported */
      pnp_capability = 
        (PNDIS_PNP_CAPABILITIES)
          (request->DATA.QUERY_INFORMATION.InformationBuffer); 

      pnp_capability->WakeUpCapabilities.MinLinkChangeWakeUp =
        NdisDeviceStateUnspecified;

      pnp_capability->WakeUpCapabilities.MinMagicPacketWakeUp =
        NdisDeviceStateUnspecified;

      pnp_capability->WakeUpCapabilities.MinPatternWakeUp =
        NdisDeviceStateUnspecified;
    }
}

/*--------------------------------------------------------------------------
  Intercepts the local MAC address query result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_query_mac_address_result(SshNdisIMAdapter adapter, 
                                            PNDIS_REQUEST request, 
                                            NDIS_STATUS status)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  /* Check the media type and return if WAN. We use the hard-coded physical
     address (00-53-45-00-00-00) for WAN adapter so that the IP addresses
     can then be associated correctly */
  if (adapter->media == NdisMediumWan)
    return;

  /* Check that query succeeded */
  if (ssh_query_success(status, &request->DATA.QUERY_INFORMATION, 6))
    {
      RtlCopyMemory(adapter->media_addr, 
                    request->DATA.QUERY_INFORMATION.InformationBuffer,
                    6);
      adapter->media_addr_len = 6;

      /* Notify interceptor about interface attribute changes */
      SSH_IP_REFRESH_REQUEST((SshNdisIMInterceptor)adapter->interceptor);
    }
}

/*--------------------------------------------------------------------------
  Intercepts the OID_GEN_CURRENT_PACKET_FILTER SET result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_set_current_packet_filter(SshNdisIMAdapter adapter, 
                                             PNDIS_REQUEST request, 
                                             NDIS_STATUS status)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  /* Check if set operation succeeded */
  if (ssh_set_success(status, &request->DATA.SET_INFORMATION, 4))
    {
      SshUInt32 *data;

      data = request->DATA.SET_INFORMATION.InformationBuffer;
      if ((*data) & NDIS_PACKET_TYPE_PROMISCUOUS)
        adapter->promiscuous_mode = 1;
      else
        adapter->promiscuous_mode = 0;
    }
}

/*--------------------------------------------------------------------------
  Intercepts the OID_GEN_CURRENT_LOOKAHEAD SET result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_set_current_lookahead_result(SshNdisIMAdapter adapter, 
                                                PNDIS_REQUEST request, 
                                                NDIS_STATUS status)
{
  ULONG curr_lookahead = 0L;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  curr_lookahead = *(ULONG*) request->DATA.SET_INFORMATION.InformationBuffer;

  /* Check if set operation succeeded */
  if (ssh_set_success(status, &request->DATA.SET_INFORMATION, 4))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: Current lookahead buffer size = %u",
                 ssh_adapter_id_st_render, adapter, curr_lookahead));

      /* Save the attribute value */
      if (curr_lookahead > 0)
        adapter->lookahead_size = curr_lookahead;
    }
}

/*--------------------------------------------------------------------------
  Intercepts the OID_GEN_VLAN_ID QUERY result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_query_vlan_id_result(SshNdisIMAdapter adapter, 
                                        PNDIS_REQUEST request, 
                                        NDIS_STATUS status)
{
  ULONG vlan_id;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  vlan_id =  *(ULONG*) request->DATA.QUERY_INFORMATION.InformationBuffer;

  /* Check if query operation succeeded */
  if (ssh_query_success(status, &request->DATA.QUERY_INFORMATION, 4))
    {
      vlan_id &= 0xFFF;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: VLAN ID = %u", 
                 ssh_adapter_id_st_render, adapter, vlan_id));

      /* Save the attribute value */
      adapter->vlan_id = (unsigned short)vlan_id;
      adapter->vlan_id_known = 1;
    }
}


/*--------------------------------------------------------------------------
  Intercepts the OID_GEN_VLAN_ID SET result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_set_vlan_id_result(SshNdisIMAdapter adapter, 
                                      PNDIS_REQUEST request, 
                                      NDIS_STATUS status)
{
  ULONG vlan_id;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  vlan_id =  *(ULONG*) request->DATA.QUERY_INFORMATION.InformationBuffer;

  /* Check if query operation succeeded */
  if (ssh_query_success(status, &request->DATA.QUERY_INFORMATION, 4))
    {
      vlan_id &= 0xFFF;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: VLAN ID = %d", 
                 ssh_adapter_id_st_render, adapter, vlan_id));

      /* Save the attribute value */
      adapter->vlan_id = (unsigned short)vlan_id;
      adapter->vlan_id_known = 1;
    }
}


#ifdef _WIN32_WCE
/*--------------------------------------------------------------------------
  Intercepts the OID_WAN_GET_INFO query result.
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_handle_query_wan_info_result(SshNdisIMAdapter adapter, 
                                         PNDIS_REQUEST request, 
                                         NDIS_STATUS status)
{
  PNDIS_WAN_INFO wan_info = NULL;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Parsing OID_WAN_GET_INFO response...",
             ssh_adapter_id_st_render, adapter));

  if (ssh_query_success(status, 
                        &request->DATA.QUERY_INFORMATION, 
                        sizeof(NDIS_WAN_INFO)))
    {
      wan_info = 
        (PNDIS_WAN_INFO)
          (request->DATA.QUERY_INFORMATION.InformationBuffer); 

      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@: HeaderPadding = %u, TailPadding = %u",
                 ssh_adapter_id_st_render, adapter, 
                 wan_info->HeaderPadding,
                 wan_info->TailPadding));

      adapter->wan_header_padding = (SshUInt32)wan_info->HeaderPadding;
      adapter->wan_tail_padding = (SshUInt32)wan_info->TailPadding;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@: OID_WAN_GET_INFO query failed; status = %@", 
                 ssh_adapter_id_st_render, adapter,
                 ssh_ndis_status_render, &status));
    }
}
#endif /* _WIN32_WCE */

/*--------------------------------------------------------------------------
  Performs an NDIS query request on the underlying driver, waits for it
  to complete and returns number of bytes transferred, or zero on failure.
  --------------------------------------------------------------------------*/
static UINT
ssh_adapter_nic_get(SshNdisIMAdapter adapter, 
                    NDIS_OID oid, 
                    PVOID buf, 
                    UINT len)
{
  UINT l = len;

  if (ssh_adapter_nic_request(adapter, FALSE, oid, buf, &l))
    return l;
  else
    return 0;
}

/*--------------------------------------------------------------------------
  Performs an NDIS set request on the underlying driver, waits for it
  to complete and returns number of bytes transferred, or zero on failure.
  --------------------------------------------------------------------------*/
static UINT
ssh_adapter_nic_set(SshNdisIMAdapter adapter, 
                    NDIS_OID oid, 
                    PVOID buf, 
                    UINT len)
{
  UINT l = len;

  if (ssh_adapter_nic_request(adapter, TRUE, oid, buf, &l))
    return l;
  else
    return 0;
}

/*--------------------------------------------------------------------------
  Performs an NDIS request on the underlying driver and waits for it to
  complete.
  --------------------------------------------------------------------------*/
static Boolean
ssh_adapter_nic_request(SshNdisIMAdapter adapter, 
                        Boolean set, 
                        NDIS_OID oid,
                        PVOID buf, 
                        UINT *len)
{
  SshRequest request = NULL;
  PNDIS_REQUEST ndis_request;
  struct _QUERY_INFORMATION *query_info;
  struct _SET_INFORMATION *set_info;
  NDIS_STATUS status;

  if (set)
    SSH_DEBUG_HEXDUMP(SSH_D_MIDSTART,
                      ("Adapter %@: NIC set request, oid=%@, data:",
                       ssh_adapter_id_st_render, adapter, 
                       ssh_ndis_oid_render, &oid),
                      buf, *len);
  else
    SSH_DEBUG(SSH_D_MIDSTART,
              ("Adapter %@: NIC query request: oid=%@",
               ssh_adapter_id_st_render, adapter, 
               ssh_ndis_oid_render, &oid));

  /* Allocate memory for a wrapper request */
  request = NdisAllocateFromNPagedLookasideList(&adapter->request_list);
  if (request == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Failed to allocate NIC request",
                 ssh_adapter_id_st_render, adapter));
      goto fail;
    }

  ndis_request = &request->orig_request;

  /* Fill the NDIS_REQUEST part. */
  if (set)
    {
      ndis_request->RequestType = NdisRequestSetInformation;
      set_info = &ndis_request->DATA.SET_INFORMATION;
      set_info->Oid = oid;
      set_info->InformationBuffer = buf;
      set_info->InformationBufferLength = *len;
      set_info->BytesRead = 0;
      set_info->BytesNeeded = 0;
    }
  else
    {
      ndis_request->RequestType = NdisRequestQueryInformation;
      query_info = &ndis_request->DATA.QUERY_INFORMATION;
      query_info->Oid = oid;
      query_info->InformationBuffer = buf;
      query_info->InformationBufferLength = *len;
      query_info->BytesWritten = 0;
      query_info->BytesNeeded = 0;
    }

  /* Fill the rest of the wrapper request. */
  request->request_done_cb = ssh_adapter_nic_request_done;
  request->bytes_needed = NULL;
  request->bytes_read_written = NULL;
  request->asynch_completion = TRUE;
  request->queued = FALSE;

  /* Send request to the underlying driver */
  InterlockedIncrement(&adapter->outstanding_requests);
  ssh_event_reset(adapter->wait_event);
  NdisRequest(&status, adapter->binding_handle, ndis_request);

  /* Wait until request is completed. */
  if (status == NDIS_STATUS_PENDING)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@: NIC request pending",
                 ssh_adapter_id_st_render, adapter));
      ssh_event_wait(1, &adapter->wait_event, NULL);
      status = adapter->result;
    }

  InterlockedDecrement(&adapter->outstanding_requests);

  if (status != NDIS_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@: NIC request failed, status=%@",
                 ssh_adapter_id_st_render, adapter,
                 ssh_ndis_status_render, &status));
      goto fail;
    }

  if (set)
    *len = set_info->BytesRead;
  else
    *len = query_info->BytesWritten;

  NdisFreeToNPagedLookasideList(&adapter->request_list, request);


  if (set)
    SSH_DEBUG(SSH_D_MIDOK,
              ("Adapter %@: NIC set request completed", 
               ssh_adapter_id_st_render, adapter));
  else
    SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                      ("Adapter %@: NIC query request completed, "
                       "oid %@, data:", 
                       ssh_adapter_id_st_render, adapter, 
                       ssh_ndis_oid_render, &oid),
                      buf, *len);
  return TRUE;

 fail:
  if (request)
    NdisFreeToNPagedLookasideList(&adapter->request_list, request);
  return FALSE;
}


/*--------------------------------------------------------------------------
  Callback for ssh_adapter_nic_request().
  --------------------------------------------------------------------------*/
static VOID
ssh_adapter_nic_request_done(SshNdisIMAdapter adapter,
                             PNDIS_REQUEST request,
                             NDIS_STATUS status)
{
  adapter->result = status;
  ssh_event_signal(adapter->wait_event);
}


static VOID
ssh_adapter_send_media_status(SshNdisIMAdapter adapter)
{
  NDIS_STATUS status = NDIS_STATUS_MEDIA_CONNECT;

  SSH_ASSERT(adapter != NULL);

  if (!adapter->media_connected)
    status = NDIS_STATUS_MEDIA_DISCONNECT;

  if (adapter->handle != NULL)
    {
      SSH_DEBUG(SSH_D_HIGHOK, 
                ("Adapter %@: Indicating media status, "
                 "miniport adapter handle %p, status %@",
                 ssh_adapter_id_st_render, adapter, adapter->handle, 
                 ssh_ndis_status_render, &status));
#pragma warning(disable : 6309)
      NdisMIndicateStatus(adapter->handle, status, NULL, 0);
#pragma warning(default : 6309)
      NdisMIndicateStatusComplete(adapter->handle);
    }
}


#ifndef _WIN32_WCE
static SshNdisIMAdapter
ssh_adapter_ref_by_device_guid(SshInterceptor interceptor,
                               SshRegKey driver_key,
                               unsigned char *mac_address,
                               SshUInt8 mac_address_len,
                               Boolean use_own_guid)
{
  PLIST_ENTRY entry;
  SshRegKey linkage_key;
  SshRegString guid_list;
  SshRegSize guid_list_size;
  SshNdisIMAdapter adapter = NULL;

  /* Looks quite promising that we have found the correct adapter! Next
     step is to read adapter GUIDs under the 'Linkage' subkey. */
  linkage_key = ssh_registry_key_open(driver_key, NULL, L"Linkage");
  if (linkage_key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to open 'Linkage' key"));
      return NULL;
    }

  guid_list = ssh_registry_data_get(linkage_key, L"RootDevice",
                                    &guid_list_size);

  ssh_registry_key_close(linkage_key);

  if (guid_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to read GUID list"));
      return NULL;
    }

  /* Now we have the adapter GUIDs. The last step is to check whether
     we have SshAdapter object having the same GUID (meaning that we
     are bound to this adapter). */
  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  for (entry = interceptor->adapter_list.Flink; 
       (entry != &interceptor->adapter_list) && (adapter == NULL); 
       entry = entry->Flink)
    {
      WCHAR *guid = guid_list;
      USHORT list_left = (USHORT)guid_list_size;
      SshNdisIMAdapter a;

      a = CONTAINING_RECORD(entry, SshNdisIMAdapterStruct, link);

      /* GUID list should be in multi string format, but let's not
         assume anything here. (We must be able to process also 
         corrupted registry data without crashing the OS). */
      while ((adapter == NULL)
             && (list_left > sizeof(WCHAR)))
        {
          USHORT guid_size = 0;
          PUNICODE_STRING name;

          while ((list_left >= sizeof(WCHAR)) && (guid[guid_size] != 0))
            {
              guid_size++;
              list_left -= sizeof(WCHAR);
            }

          guid_size *= sizeof(WCHAR);

          if (use_own_guid)
            name = &a->name;
          else
            name = &a->orig_name;

          /* Matching adapter contains the same GUID with '\Device\'
             prefix in adapter->name.Buffer. We can just skip the 
             prefix (i.e. 8 wide characters / 16 bytes) and then 
             perform memory compare. */
          if ((guid_size == name->Length - 16) 
              && (NdisEqualMemory(guid, &(name->Buffer[8]), guid_size)))
            {
              /* Check also the media address if requested */
              if (((mac_address == NULL) || (mac_address_len != 0))
                  || ((mac_address_len == a->media_addr_len)
                      && NdisEqualMemory(mac_address, 
                                         a->media_addr,
                                         a->media_addr_len)))
                {
                  adapter = a;
                  InterlockedIncrement(&adapter->ref_count);
                  break;
                }
            }

          guid += SSH_REG_STR_LEN(guid) + 1;

          if (list_left > sizeof(WCHAR))
            list_left -= sizeof(WCHAR);
        }
    }
  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  ssh_free(guid_list);

  return adapter;
}
#endif /* _WIN32_WCE */


SshInterceptorIfnum
ssh_adapter_ifnum_lookup(SshInterceptor interceptor,
                         unsigned char *mac_address,
                         size_t mac_address_len,
                         SshIPInterfaceID id)
{
  SshInterceptorIfnum ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
#ifndef _WIN32_WCE
  SshRegKey driver_key;
#endif /* _WIN32_WCE */
  PLIST_ENTRY entry;
  SshNdisIMAdapter adapter = NULL; 

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(id != NULL);
  /* This function must not be called at raised IRQL! */
  SSH_ASSERT(SSH_GET_IRQL() == SSH_PASSIVE_LEVEL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing adapter lookup..."));

  /* Special case for WAN (dial-up) adapters */
  if ((mac_address && (mac_address_len == SSH_ETHERH_ADDRLEN))
      && (NdisEqualMemory(mac_address,
                          SSH_ADAPTER_PHYS_ADDRESS_WAN,
                          SSH_ETHERH_ADDRLEN)))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("This seems to be a WAN adapter..."));
      goto mac_addr_lookup;
    }

#ifndef _WIN32_WCE
  if (interceptor->os_version <= SSH_OS_VERSION_W2K)
#endif /* _WIN32_WCE */
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("We can perform only MAC address lookup on this "
                 "Windows operating system"));
      goto mac_addr_lookup;
    }

#ifndef _WIN32_WCE
  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  if (IsListEmpty(&interceptor->adapter_list) == TRUE)
    {
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

      SSH_DEBUG(SSH_D_FAIL, ("Interceptor not bound to any adapters!"));
      return SSH_INTERCEPTOR_INVALID_IFNUM;
    }

  if (id->id_type == SSH_IF_ID_GUID)
    {
      SshRegKey net_adapters_key;
      unsigned char guidstr[39];

      /* Check whether we already know this GUID */
      for (entry = interceptor->adapter_list.Flink; 
           (entry != &interceptor->adapter_list) && (adapter == NULL); 
           entry = entry->Flink)
        {
          SshNdisIMAdapter a;

          a = CONTAINING_RECORD(entry, SshNdisIMAdapterStruct, link);

          /* Check also the media address if requested */
          if (NdisEqualMemory(&a->if_guid, &id->u.guid, sizeof(GUID)))
            {
              adapter = a;
              InterlockedIncrement(&adapter->ref_count);
              break;
            }
        }
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

#ifndef DEBUG_LIGHT
      if (adapter == NULL)
#endif /* DEBUG_LIGHT */
        {
          ssh_snprintf(guidstr, sizeof(guidstr), 
                       "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                       id->u.guid.Data1,
                       id->u.guid.Data2,
                       id->u.guid.Data3,
                       id->u.guid.Data4[0], id->u.guid.Data4[1], 
                       id->u.guid.Data4[2], id->u.guid.Data4[3],
                       id->u.guid.Data4[4], id->u.guid.Data4[5],
                       id->u.guid.Data4[6], id->u.guid.Data4[7]);
        }

      if (adapter != NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Interface GUID %s matches adapter '%s'; "
                     "skipping registry search.", 
                     guidstr, adapter->ssh_name));

          ifnum = adapter->ifnum;
          InterlockedDecrement(&adapter->ref_count);

          return ifnum;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Searching for GUID %s", guidstr));

      /* {4D36E972-E325-11CE-BFC1-08002BE10318} is the well-known GUID of 
         'Network Adapters' class. */
      net_adapters_key = 
        ssh_registry_key_open(HKEY_LOCAL_MACHINE, 
                              L"System\\CurrentControlSet\\Control\\Class",
                              L"{4D36E972-E325-11CE-BFC1-08002BE10318}");

      if (net_adapters_key == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to open 'Network Adapters' key"));
          return SSH_INTERCEPTOR_INVALID_IFNUM;
        }

      driver_key = 
        ssh_registry_subkey_find_by_ansi_data(net_adapters_key,
                                              L"NetCfgInstanceId",
                                              guidstr,
                                              ssh_ustrlen(guidstr),
                                              FALSE);

      ssh_registry_key_close(net_adapters_key);

      if (driver_key == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Didn't find adapter with NetCfgInstanceId '%s'",
                     guidstr));

          return SSH_INTERCEPTOR_INVALID_IFNUM;
        }

      adapter = ssh_adapter_ref_by_device_guid(interceptor, 
                                               driver_key,
                                               mac_address, 
                                               (SshUInt8)mac_address_len,
                                               FALSE);
      if (adapter)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Found match: %s <-> '%s'", guidstr, adapter->ssh_name));

          /* Cache the interface GUID to prevent unnecessary registry 
             searches. */
          adapter->if_guid = id->u.guid;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("None of the bound adapters matching interface GUID %s", 
                    guidstr));
        }
  
      ssh_registry_key_close(driver_key);
    }
  else if ((id->id_type == SSH_IF_ID_DESCRIPTION)
           && (id->u.d.description_len > 0))
    {
      SshRegKey enum_root_key;
      SshRegKey instance_key;
      SshRegPath driver;

      /* Check whether we already know this description */
      for (entry = interceptor->adapter_list.Flink; 
           (entry != &interceptor->adapter_list) && (adapter == NULL); 
           entry = entry->Flink)
        {
          SshNdisIMAdapter a;

          a = CONTAINING_RECORD(entry, SshNdisIMAdapterStruct, link);

          /* Check also the media address if requested */
          if ((a->if_description_len == id->u.d.description_len)
              && (NdisEqualMemory(a->if_description,
                                  id->u.d.description, 
                                  id->u.d.description_len)))
            {
              adapter = a;
              InterlockedIncrement(&adapter->ref_count);
              break;
            }
        }
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

      if (adapter != NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Interface description '%s' matches adapter '%s'; "
                     "skipping registry search.", 
                     id->u.d.description, adapter->ssh_name));

          ifnum = adapter->ifnum;
          InterlockedDecrement(&adapter->ref_count);
          return ifnum;
        }


      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Searching for description '%s'", id->u.d.description));

      enum_root_key = 
        ssh_registry_key_open(HKEY_LOCAL_MACHINE, NULL,
                              L"System\\CurrentControlSet\\Enum\\Root");

      if (enum_root_key == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Failed to open ...\\Enum\\Root registry key!"));
          return SSH_INTERCEPTOR_INVALID_IFNUM;
        }

      instance_key = 
        ssh_registry_subkey_find_by_ansi_data(enum_root_key,
                                              L"FriendlyName",
                                              id->u.d.description,
                                              id->u.d.description_len,
                                              TRUE);

      ssh_registry_key_close(enum_root_key);

      if (instance_key == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Didn't find adapter with description '%s'",
                     id->u.d.description));

          return SSH_INTERCEPTOR_INVALID_IFNUM;
        }

      /* Found an adapter instance matching the given description. Value 
         'Driver' contains a link to corresponding entry under key
         HKLM\System\CurrentControlSet\Control\Class. */
      driver = ssh_registry_data_get(instance_key, L"Driver", NULL);

      ssh_registry_key_close(instance_key);

      if (driver == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to read 'Driver' value"));

          return SSH_INTERCEPTOR_INVALID_IFNUM;
        }

      /* We have the link now. Let's open the correct registry key under
         ...CurrentControlSet\Control\Class.  */
      driver_key =         
        ssh_registry_key_open(HKEY_LOCAL_MACHINE, 
                              L"System\\CurrentControlSet\\Control\\Class",
                              driver);

      ssh_free(driver);

      if (driver_key == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to open 'Driver' key"));
          return SSH_INTERCEPTOR_INVALID_IFNUM;
        }

      adapter = ssh_adapter_ref_by_device_guid(interceptor, driver_key,
                                               mac_address, 
                                               (SshUInt8)mac_address_len,
                                               TRUE);

      if (adapter)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Found match: %s <-> '%s'", 
                    id->u.d.description, adapter->ssh_name));

          /* Cache the interface description to prevent unnecessary 
             registry searches. */
          ssh_free(adapter->if_description);

          adapter->if_description = ssh_malloc(id->u.d.description_len);
          if (adapter->if_description)
            {
              RtlCopyMemory(adapter->if_description,
                            id->u.d.description, 
                            id->u.d.description_len);

              adapter->if_description_len = 
                (SshUInt16)id->u.d.description_len;
            }
          else
            {
              adapter->if_description_len = 0;
            }
        }
      else
        {
          SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                            ("None of the bound adapters matching "
                             "interface description:"), 
                            id->u.d.description, id->u.d.description_len);
        }

      ssh_registry_key_close(driver_key);
    }
  else
    {
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);
    }
#endif /* _WIN32_WCE */

 mac_addr_lookup:

  if ((adapter == NULL) && (mac_address) && (mac_address_len))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Searching for adapter having media address:"),
                        mac_address, mac_address_len);

      ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
      for (entry = interceptor->adapter_list.Flink; 
           (entry != &interceptor->adapter_list) && (adapter == NULL); 
           entry = entry->Flink)
        {
          SshNdisIMAdapter a;

          a = CONTAINING_RECORD(entry, SshNdisIMAdapterStruct, link);

          /* Check also the media address if requested */
          if ((mac_address_len == a->media_addr_len)
               && RtlEqualMemory(mac_address, 
                                 a->media_addr,
                                 a->media_addr_len))
            {
              adapter = a;
              InterlockedIncrement(&adapter->ref_count);
              break;
            }
        }
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

      if (adapter != NULL)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                            ("Adapter '%s' is having media address:", 
                            adapter->ssh_name), 
                            mac_address, mac_address_len);
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Didn't find any bound adapter matching the "
                     "search criteria."));
        }
    }

  if (adapter)
    {
      ifnum = adapter->ifnum;
      InterlockedDecrement(&adapter->ref_count);
    }

  return ifnum;
}


SshNdisIMAdapter
ssh_adapter_find_by_name(SshNdisIMInterceptor interceptor,
                         PNDIS_STRING name)
{
  SshAdapter adapter = NULL;
  PLIST_ENTRY entry;

  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  entry = interceptor->adapter_list.Flink;
  while (entry != &interceptor->adapter_list)
    {
      adapter = CONTAINING_RECORD(entry, SshAdapterStruct, link);

      if ((adapter->orig_name.Length == name->Length) 
          && (memcmp(adapter->orig_name.Buffer, 
                     name->Buffer, name->Length) == 0))
        break;

      entry = entry->Flink;
      adapter = NULL;
    }
  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  return (SshNdisIMAdapter)adapter;
}


SshNdisIMAdapter
ssh_adapter_find_by_state(SshNdisIMInterceptor interceptor,
                          UINT state)
{
  PLIST_ENTRY i = NULL;
  SshNdisIMAdapter adapter = NULL;

  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  for (i = interceptor->adapter_list.Flink; 
       i != &interceptor->adapter_list; 
       i = i->Flink)
    {
      adapter = CONTAINING_RECORD(i, SshNdisIMAdapterStruct, link);
      if (adapter != NULL && adapter->state == state)
        break;

      adapter = NULL;
    }
  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  return (adapter);
}


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

static SshRegKey
ssh_adapter_open_tcpip_config(SshNdisIMAdapter adapter)
{
  SshRegKey adapter_key = NULL;
#ifdef _WIN32_WCE
  SshRegKey comm_key;
  SshRegKey device_key;

  /* Open the comm key. */
  comm_key = ssh_registry_key_open(HKEY_LOCAL_MACHINE, NULL, L"Comm");

  if (comm_key == NULL) 
    return NULL;

  /* Open the device key. */
  device_key = ssh_registry_key_open(comm_key, NULL, adapter->name.Buffer);

  if (device_key) 
    {
      /* Open the adapter's tcp parameter key. */
      adapter_key = ssh_registry_key_open(device_key, NULL, L"Parms\\TcpIp");

      /* Close the device key. */
      ssh_registry_key_close(device_key);
    }

  /* Close the comm key. */
  ssh_registry_key_close(comm_key);
#else
  UNICODE_STRING adapter_name;
  SshRegKey tcp_if_key;
  SshUInt32 offset;

  /* Open TCP/IP interfaces key */
  tcp_if_key = 
    ssh_registry_key_open(HKEY_LOCAL_MACHINE, NULL,
      L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");
  
  if (tcp_if_key == NULL)
    return NULL;

  /* Adapter->orig_name contains the interface name we are interested.
     We just need to "remove" the "\DEVICE\" prefix. */
  offset = 16; /* skip eight UNICODE characters from the beginning */
  adapter_name.Buffer = 
    (WCHAR *)(((char *)adapter->orig_name.Buffer) + offset);
  adapter_name.Length = adapter->orig_name.Length - offset;
  adapter_name.MaximumLength = adapter->orig_name.MaximumLength - offset;

  adapter_key = ssh_registry_key_open_unicode(tcp_if_key, NULL, 
                                              &adapter_name);

  ssh_registry_key_close(tcp_if_key);
#endif /* _WIN32_WCE */

  return (adapter_key);
}


#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */ 


#ifdef _WIN32_WCE
NDIS_STATUS
ssh_adapter_update_wireless(SshNdisIMAdapter adapter)
{
  NDIS_STATUS  status = NDIS_STATUS_FAILURE;
  SshRegKey power_state_key = NULL;
  SshRegKey comm_key = NULL;
  SshRegKey bound_adapter_key = NULL; 
  SshRegKey adapter_key = NULL;
  WCHAR *power_state_value = NULL;
  DWORD power_state, wireless;
  Boolean power_state_set = FALSE;
  Boolean adapter_key_created = FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Updating wireless settings...",
             ssh_adapter_id_st_render, adapter));

  /* Copy boot power state, if any, from the underlying adapter. */

  power_state_key = ssh_registry_key_open(
    HKEY_LOCAL_MACHINE, NULL,
    L"System\\CurrentControlSet\\Control\\Power\\State");
  if (power_state_key == NULL)
    goto failed;

  power_state_value = ssh_malloc(MAX_PATH * sizeof *power_state_value);
  if (!power_state_value)
    goto failed;

  StringCchPrintfW(
    power_state_value, MAX_PATH,
    L"{98C5250D-C29A-4985-AE5F-AFE5367E5006}\\%s",
    adapter->orig_name.Buffer);

  if (ssh_registry_dword_get(power_state_key, power_state_value, &power_state))
    {
      StringCchPrintfW(
        power_state_value, MAX_PATH,
        L"{98C5250D-C29A-4985-AE5F-AFE5367E5006}\\%s",
        adapter->name.Buffer);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: - setting power state to %d...",
                 ssh_adapter_id_st_render, adapter, (int)power_state));

      if (!ssh_registry_dword_set(
            power_state_key, power_state_value, power_state))
        goto failed;
      power_state_set = TRUE;
    }

  /* Copy wireless flag, if any, from the underlying adapter. */

  comm_key = ssh_registry_key_open(HKEY_LOCAL_MACHINE, NULL, L"Comm");
  if (comm_key == NULL)
    goto failed;

  bound_adapter_key = ssh_registry_key_open_unicode(
    comm_key, NULL, &adapter->orig_name);
  if (bound_adapter_key == NULL)
    goto failed;

  if (ssh_registry_dword_get(bound_adapter_key, L"Wireless", &wireless))
    {
      adapter_key = ssh_registry_key_open_unicode(
        comm_key, NULL, &adapter->name);
      if (adapter_key == NULL)
        {
          adapter_key = ssh_registry_key_create_unicode(
            comm_key, &adapter->name);
          if (adapter_key == NULL)
            goto failed;
          adapter_key_created = TRUE;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: - setting Wireless flag...",
                 ssh_adapter_id_st_render, adapter));

      if (!ssh_registry_dword_set(adapter_key, L"Wireless", wireless))
        goto failed;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Finished updating wireless settings.",
             ssh_adapter_id_st_render, adapter));

  status = STATUS_SUCCESS;
  goto done;

 failed:
  SSH_DEBUG(SSH_D_FAIL, 
            ("Adapter %@: Failed to update wireless settings!",
             ssh_adapter_id_st_render, adapter));

  if (adapter_key_created)
    {
      ssh_registry_key_close(adapter_key);
      ssh_registry_key_delete_unicode(comm_key, &adapter->name);
      adapter_key = NULL;
    }

  if (power_state_set)
    ssh_registry_value_delete(power_state_key, power_state_value);

 done:
  if (adapter_key)
    ssh_registry_key_close(adapter_key);

  if (bound_adapter_key)
    ssh_registry_key_close(bound_adapter_key);    

  if (comm_key)
    ssh_registry_key_close(comm_key);

  if (power_state_value)
    ssh_free(power_state_value);

  if (power_state_key)
    ssh_registry_key_close(power_state_key);

  return status;
}

NDIS_STATUS
ssh_adapter_update_config(SshNdisIMAdapter adapter, Boolean wan_adapter)
{
  NDIS_STATUS  status = NDIS_STATUS_FAILURE;
  WCHAR *upper_bind;
  WCHAR qs_lan[] = QUICKSEC_LAN_PROTOCOL_NAMES;
  WCHAR qs_wan[] = QUICKSEC_WAN_PROTOCOL_NAMES;
  SshRegSize data_size;
  SshRegKey comm_key = NULL;
  SshRegKey adapter_key = NULL;
  SshRegKey params_key = NULL;
  SshRegKey tcpip_key = NULL;
  SshRegKey bound_adapter_key = NULL; 
  SshRegKey bound_params_key = NULL;
  Boolean adapter_key_created = FALSE;
  Boolean params_key_created = FALSE;
  SshRegDWord dw_value = 0;

  /* Following code is workaround about fact that CE requires 
     HKLM\Comm\QSEC\<InstanceName>\Parms registry key with DWORD values 
     named BusNumber and BusType - so we have to create them if they 
     don't exist. We manage also situation when there is an UpperBind 
     definition in underlaying miniport - in such case we copy it to 
     IM virtual miniport. Because ProtocolBindAdapeter can be called 
     inside NDIS HKLM\Comm enumeration we can't add key to HKLM\Comm so 
     IM miniport instance key must be created with prefix (which move IM 
     miniport instance key to prefix subkey. */

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Updating registry...",
             ssh_adapter_id_st_render, adapter));

  /* HKLM\Comm\QSEC\<InstanceName>\Parms */
  comm_key = ssh_registry_key_open(HKEY_LOCAL_MACHINE, NULL, L"Comm");
  if (comm_key == NULL)
    goto failed;

  adapter_key = ssh_registry_key_open_unicode(comm_key, NULL, &adapter->name);
  if (adapter_key == NULL)
    {
      adapter_key = ssh_registry_key_create_unicode(comm_key, &adapter->name);
      if (adapter_key == NULL)
        goto failed;

      adapter_key_created = TRUE;
    }

  params_key = ssh_registry_key_open(adapter_key, NULL, L"Parms");
  if (params_key == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@: - creating 'Parms' key...",
                 ssh_adapter_id_st_render, adapter));

      params_key = ssh_registry_key_create(adapter_key, L"Parms");
      if (params_key == NULL)
        goto failed;

      params_key_created = TRUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: - setting 'BusNumber' and 'BusType'...",
             ssh_adapter_id_st_render, adapter));

  /* Set parameters */
  ssh_registry_dword_set(params_key, L"BusNumber", 0);
  ssh_registry_dword_set(params_key, L"BusType", 0);

  /* Create TcpIp key if it doesn't exist yet */
  tcpip_key = ssh_registry_key_open(params_key, NULL, L"TcpIp");
  if (tcpip_key == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@: - creating 'TcpIp' key...",
                 ssh_adapter_id_st_render, adapter));

      tcpip_key = ssh_registry_key_create(params_key, L"TcpIp");
      if (tcpip_key == NULL)
        goto failed;
    }
  ssh_registry_key_close(tcpip_key);
  tcpip_key = NULL;

  /* HKLM\Comm\<InstanceName>\Parms */
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                    ("Adapter %@: - opening underlying miniport's "
                     "registry key...",
                     ssh_adapter_id_st_render, adapter),
                    (const unsigned char *)adapter->orig_name.Buffer, 
                    adapter->orig_name.Length);

  bound_adapter_key = ssh_registry_key_open_unicode(comm_key, NULL, 
                                                   &adapter->orig_name);
  if (bound_adapter_key == NULL)
    goto failed;

  bound_params_key = ssh_registry_key_open(bound_adapter_key, 
                                           NULL, L"Parms");
  if (bound_params_key == NULL)
    {
      bound_params_key = ssh_registry_key_create(bound_adapter_key,
                                                 L"Parms");
      if (bound_params_key == NULL)
        goto failed;
    }

  /* Check if the UpperBind value of the undelying miniport is already
     updated by us and in that case just return. */
  upper_bind = ssh_registry_data_get(bound_params_key,
                                     L"UpperBind", &data_size);
  if (upper_bind)
    {
      if ((data_size == sizeof qs_lan &&
           !memcmp(upper_bind, qs_lan, data_size)) ||
          (data_size == sizeof qs_wan &&
           !memcmp(upper_bind, qs_wan, data_size)))
        {
          ssh_free(upper_bind);
          status = NDIS_STATUS_SUCCESS;
          goto done;
        }
    }

  /* Save original protocol binding for rebind on unload */
  if (upper_bind != NULL && data_size > 0) 
    {
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                        ("Adapter %@: - saving original UpperBind...",
                         ssh_adapter_id_st_render, adapter),
                        (const unsigned char *)upper_bind, 
                        data_size);

      ssh_registry_multi_string_set(bound_params_key,
                                    L"OriginalUpperBind", 
                                    upper_bind, 
                                    data_size);
    }

  /* Allow underlying miniport to bind only to QuickSec */
  if (wan_adapter) 
    ssh_registry_multi_string_set(bound_params_key, L"UpperBind", 
                                  qs_wan, sizeof qs_wan);
  else
    ssh_registry_multi_string_set(bound_params_key, L"UpperBind", 
                                  qs_lan, sizeof qs_lan);

  /* Get parameters */
  if (ssh_registry_dword_get(bound_params_key, 
                             L"DisablePowerManagement", 
                             &dw_value))
    {
      if (dw_value)
        adapter->power_mgmt_disabled = TRUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Finished updating registry.",
             ssh_adapter_id_st_render, adapter));

  status = STATUS_SUCCESS;
  goto done;

 failed:
  SSH_DEBUG(SSH_D_FAIL, 
            ("Adapter %@: Failed to update registry!",
             ssh_adapter_id_st_render, adapter));

  if (params_key_created)
    {
      ssh_registry_key_close(params_key);
      ssh_registry_key_delete(adapter_key, L"Parms");
      params_key = NULL;
    }

  if (adapter_key_created)
    {
      ssh_registry_key_close(adapter_key);
      ssh_registry_key_delete_unicode(comm_key, &adapter->name);
      adapter_key = NULL;
    }

 done:
  if (bound_params_key)
    ssh_registry_key_close(bound_params_key);

  if (bound_adapter_key)
    ssh_registry_key_close(bound_adapter_key);    

  if (params_key)
    ssh_registry_key_close(params_key);

  if (adapter_key)
    ssh_registry_key_close(adapter_key);

  if (comm_key)
    ssh_registry_key_close(comm_key);

  return status;
}
#endif /* _WIN32_WCE */
