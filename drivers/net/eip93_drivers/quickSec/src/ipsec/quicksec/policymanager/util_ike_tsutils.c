/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004,2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 09:39 Jan 24 2005 kivinen
 *        Last Modification : 09:46 Jan 24 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.4
 *        
 *
 *        Description       : IKEv2 Traffic selector utility functions
 *
 *
 *        $Log: util_ike_tsutils.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:30:47  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sad_ike.h"

#define SSH_DEBUG_MODULE "SshPmIkev2TsUtil"

/* The maximum number of TS payloads that will be stored in the freelist. */
#define SSH_PM_MAX_TS_PAYLOADS (4 * SSH_PM_MAX_IKE_SA_NEGOTIATIONS + 5)

/***********************************************************************/
/* 			Internal functions. 			       */
/***********************************************************************/

/* Allocate new traffic selector. */
SshIkev2PayloadTS
ssh_ikev2_ts_allocate_new(SshSADHandle sad_handle)
{
  SshIkev2PayloadTS ts;




  ts = ssh_calloc(1, sizeof(*ts));
  if (ts == NULL)
    return ts;
  /* Preallocate some items. */



  ts->number_of_items_allocated = SSH_IKEV2_TS_ITEMS_PREALLOC;
  ts->items = ssh_calloc(ts->number_of_items_allocated, sizeof(*(ts->items)));
  if (ts->items == NULL)
    ts->number_of_items_allocated = 0;
  return ts;
}

/* Free traffic selector, it must not be in the free list
   anymore. */
void
ssh_ikev2_ts_destroy(SshSADHandle sad_handle, SshIkev2PayloadTS ts)
{



  if (ts->items != NULL)
    ssh_free(ts->items);
  ts->items = NULL;
  ssh_free(ts);
}

/* Init free list of traffic selectors. Return TRUE if
   successfull. */
Boolean
ssh_ikev2_ts_freelist_create(SshSADHandle sad_handle)
{
  SshIkev2PayloadTS ts;
  SshUInt32 i;

  sad_handle->ts_free_list =
    ssh_adt_create_generic(SSH_ADT_LIST,
			   SSH_ADT_HEADER,
			   SSH_ADT_OFFSET_OF(SshIkev2PayloadTSStruct,
					     free_list_header),
			   SSH_ADT_ARGS_END);
  if (sad_handle->ts_free_list == NULL)
    { 
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating server_list"));
      return FALSE;
    }

  for (i = 0; i < SSH_PM_MAX_TS_PAYLOADS; i++)
    {
      ts = ssh_ikev2_ts_allocate_new(sad_handle);
      if (ts != NULL)
	ssh_adt_insert(sad_handle->ts_free_list, ts);
    }
  
  return TRUE;
}

/* Destroy free list of traffic selectors.  */
void
ssh_ikev2_ts_freelist_destroy(SshSADHandle sad_handle)
{
  if (sad_handle->ts_free_list)
    {
      SshIkev2PayloadTS ts;
      SshADTHandle h;

      while ((h = ssh_adt_enumerate_start(sad_handle->ts_free_list)) !=
	     SSH_ADT_INVALID)
	{
	  ts = ssh_adt_get(sad_handle->ts_free_list, h);
	  SSH_ASSERT(ts != NULL);
	  ssh_adt_detach_object(sad_handle->ts_free_list, ts);
	  ssh_ikev2_ts_destroy(sad_handle, ts);
	}
      SSH_ASSERT(ssh_adt_num_objects(sad_handle->ts_free_list) == 0);
      ssh_adt_destroy(sad_handle->ts_free_list);
    }
  sad_handle->ts_free_list = NULL;
}

/***********************************************************************/
/* 			External functions. 			       */
/***********************************************************************/

/* Allocate traffic selector. The initial traffic selector
   is empty. This will take it from the free list in SAD, or
   return NULL if no entries available. */
SshIkev2PayloadTS
ssh_ikev2_ts_allocate(SshSADHandle sad_handle)
{
  SshIkev2PayloadTS ts;

  ts = NULL;
  if (ssh_adt_num_objects(sad_handle->ts_free_list) > 0)
    ts = ssh_adt_detach_from(sad_handle->ts_free_list, SSH_ADT_BEGINNING);
  if (ts == NULL)
    ts = ssh_ikev2_ts_allocate_new(sad_handle);
  if (ts == NULL)
    return NULL;
  ts->ref_cnt = 1;
  ts->number_of_items_used = 0;
  return ts;
}

/* Free traffic selector. This will return it back to the
   free list if this was last reference*/
void
ssh_ikev2_ts_free(SshSADHandle sad_handle,
		  SshIkev2PayloadTS ts)
{
  size_t num_objects;
  SSH_ASSERT(ts->ref_cnt != 0);

  /* Decrement reference count, and check whether we still have references. */
  ts->ref_cnt--;
  if (ts->ref_cnt != 0)
    {
      /* Yes. */
      return;
    }
  /* No references, free or move it to free list. */

  num_objects = ssh_adt_num_objects(sad_handle->ts_free_list);

  if (num_objects > SSH_PM_MAX_TS_PAYLOADS)
    ssh_ikev2_ts_destroy(sad_handle, ts);
  else
    ssh_adt_insert(sad_handle->ts_free_list, ts);
  return;
}

/* Truncate number of traffic selector items to configured maximum.
 */
void ssh_pm_ts_max_enforce(SshSADHandle sad_handle, SshIkev2PayloadTS *ts)
{
  if (*ts)
    {
      while ((*ts)->number_of_items_used > 
	    SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS)
	{
	  /* Remove last item. */
	  ssh_ikev2_ts_item_delete(*ts,
				   (*ts)->number_of_items_used - 1);
	}
    }
}


/* Public routines for traffic selector manipulation from the 
   policy manager API. */

SshIkev2PayloadTS ssh_pm_ts_allocate(SshPm pm)
{
  if (pm->sad_handle == NULL)
    return NULL;

  return ssh_ikev2_ts_allocate(pm->sad_handle);
}

void ssh_pm_ts_free(SshPm pm, SshIkev2PayloadTS ts)
{
  if (pm->sad_handle == NULL)
    return;

  ssh_ikev2_ts_free(pm->sad_handle, ts);
}

Boolean
ssh_pm_ts_item_add(SshPm pm,
		   SshIkev2PayloadTS ts,
		   SshInetIPProtocolID proto,
		   SshIpAddr start_address,
		   SshIpAddr end_address,
		   SshUInt16 start_port,
		   SshUInt16 end_port)
{
  SshIkev2Error ike_error;

  if (pm->sad_handle == NULL)
    return FALSE;
  
  ike_error = ssh_ikev2_ts_item_add(ts, proto, 
				    start_address, end_address,
				    start_port, end_port);
  
  return (ike_error == SSH_IKEV2_ERROR_OK) ? TRUE : FALSE;
}
