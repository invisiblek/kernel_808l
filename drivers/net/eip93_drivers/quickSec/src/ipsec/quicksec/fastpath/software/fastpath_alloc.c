/*
  fastpath_alloc.c

  Copyright:
    Copyright (c) 7 SFNT Finland Oy.
        All rights reserved.


  Description:

  Fastpath allocation/deallocation.

  Relevant defines.

    FASTPATH_PROVIDES_FLOW : If set the flow table allocation is not provided 
    by this module, it must be provided by the accelerated fastpath. 

    FASTPATH_PROVIDES_TRD : If set the transform table allocation is not 
    provided by this module, it must be provided by the accelerated fastpath. 

    FASTPATH_PROVIDES_NH : If set the next hop table allocation is not 
    provided by this module, it must be provided by the accelerated fastpath. 
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_accel.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathAlloc"

#ifdef SSH_IPSEC_PREALLOCATE_TABLES

#ifndef FASTPATH_PROVIDES_FLOW

#define SSH_ENGINE_FLOW_D_TABLE_ROOT_SIZE \
((SSH_ENGINE_FLOW_TABLE_SIZE + SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE - 1) \
 / (SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE))

#define SSH_ENGINE_FLOW_HASH_ROOT_SIZE \
((SSH_ENGINE_FLOW_ID_HASH_SIZE + SSH_ENGINE_FLOW_HASH_BLOCK_SIZE - 1) \
 / (SSH_ENGINE_FLOW_HASH_BLOCK_SIZE))

static SshFastpathFlowData ssh_fastpath_flow_data_table_root
                                        [SSH_ENGINE_FLOW_D_TABLE_ROOT_SIZE];

static SshFastpathFlowDataStruct ssh_fastpath_flow_data_table
                                        [SSH_ENGINE_FLOW_D_TABLE_ROOT_SIZE]
                                        [SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE];

static SshUInt32 *ssh_fastpath_flow_forward_hash_root
                                        [SSH_ENGINE_FLOW_HASH_ROOT_SIZE];
static SshUInt32 *ssh_fastpath_flow_reverse_hash_root
                                        [SSH_ENGINE_FLOW_HASH_ROOT_SIZE];

static SshUInt32 ssh_fastpath_flow_forward_hash[SSH_ENGINE_FLOW_HASH_ROOT_SIZE]
                                             [SSH_ENGINE_FLOW_HASH_BLOCK_SIZE];

static SshUInt32 ssh_fastpath_flow_reverse_hash
                                        [SSH_ENGINE_FLOW_HASH_ROOT_SIZE]
                                        [SSH_ENGINE_FLOW_HASH_BLOCK_SIZE];
#endif /* !FASTPATH_PROVIDES_FLOW */

#ifndef FASTPATH_PROVIDES_NH
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

#define SSH_ENGINE_NH_D_TABLE_ROOT_SIZE \
((SSH_ENGINE_NEXT_HOP_HASH_SIZE + SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE - 1) \
 / (SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE))

static SshFastpathNextHopData ssh_fastpath_next_hop_data_table_root[
                                        SSH_ENGINE_NH_D_TABLE_ROOT_SIZE];

static SshFastpathNextHopDataStruct ssh_fastpath_next_hop_data_table
                                        [SSH_ENGINE_NH_D_TABLE_ROOT_SIZE]
                                        [SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE];

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* !FASTPATH_PROVIDES_NH */

#ifndef FASTPATH_PROVIDES_TRD

#define SSH_ENGINE_TR_D_TABLE_ROOT_SIZE    \
((SSH_ENGINE_TRANSFORM_TABLE_SIZE         \
  + SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE - 1)  \
 / (SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE))

static SshFastpathTransformData ssh_fastpath_transform_data_table_root[
                                        SSH_ENGINE_TR_D_TABLE_ROOT_SIZE];

static SshFastpathTransformDataStruct ssh_fastpath_transform_data_table
                                [SSH_ENGINE_TR_D_TABLE_ROOT_SIZE]
                                [SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE];
#endif /* !FASTPATH_PROVIDES_TRD */

static SshFastpathFragEntryStruct ssh_fastpath_fragment_table[
                                        SSH_ENGINE_FRAGMENT_TABLE_SIZE];
static SshFastpathFragEntryStruct *ssh_fastpath_fragment_hash[
                                        SSH_ENGINE_FRAGMENT_HASH_SIZE];

#ifdef SSHDIST_IPSEC_TRANSFORM

#define SSH_ENGINE_TRANSFORM_CONTEXTS_ROOT_SIZE         \
((SSH_ENGINE_MAX_TRANSFORM_CONTEXTS                     \
  + SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE - 1)       \
 / (SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE))

static SshFastpathTransformContext ssh_fastpath_tc_table_root[
                                SSH_ENGINE_TRANSFORM_CONTEXTS_ROOT_SIZE];

static SshFastpathTransformContextStruct ssh_fastpath_tc_table
                                [SSH_ENGINE_TRANSFORM_CONTEXTS_ROOT_SIZE]
                                [SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE];
#endif /* SSHDIST_IPSEC_TRANSFORM */
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */


SshFastpath ssh_fastpath_alloc(SshEngine engine)
{
#ifdef SSHDIST_IPSEC_TRANSFORM
  SshFastpathTransformContext tc;
#endif /* SSHDIST_IPSEC_TRANSFORM */
  SshFastpath fastpath;
  SshUInt32 i, j;

  if ((fastpath = ssh_calloc(1, sizeof(*fastpath))) == NULL)
    goto fail;
  fastpath->engine = engine;
  fastpath->num_cpus = ssh_kernel_num_cpus();
  SSH_ASSERT(fastpath->num_cpus > 0);

  /* Allocate/assign memory for the various tables. */
  fastpath->flow_table_size = SSH_ENGINE_FLOW_TABLE_SIZE;
  fastpath->flow_id_hash_size = SSH_ENGINE_FLOW_ID_HASH_SIZE;
  fastpath->transform_table_size = SSH_ENGINE_TRANSFORM_TABLE_SIZE;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  fastpath->next_hop_hash_size = SSH_ENGINE_NEXT_HOP_HASH_SIZE;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
#ifndef FASTPATH_PROVIDES_FLOW
  fastpath->flow_data_table_root = ssh_fastpath_flow_data_table_root;
  for (i = 0; i < SSH_ENGINE_FLOW_D_TABLE_ROOT_SIZE; i++)
    {
      fastpath->flow_data_table_root[i] = 
	&ssh_fastpath_flow_data_table[i][0];
    }

  /* Initialize 2d flow hash table */
  fastpath->flow_forward_hash_root = ssh_fastpath_flow_forward_hash_root;
  fastpath->flow_reverse_hash_root = ssh_fastpath_flow_reverse_hash_root;
  for (i = 0; i < SSH_ENGINE_FLOW_HASH_ROOT_SIZE; i++)
    {
      fastpath->flow_forward_hash_root[i] = 
	&ssh_fastpath_flow_forward_hash[i][0];
      fastpath->flow_reverse_hash_root[i] = 
	&ssh_fastpath_flow_reverse_hash[i][0];
    }
#endif /* !FASTPATH_PROVIDES_FLOW */

#ifndef FASTPATH_PROVIDES_NH
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  fastpath->next_hop_data_table_root = ssh_fastpath_next_hop_data_table_root;
  for (i = 0; i < SSH_ENGINE_NH_D_TABLE_ROOT_SIZE; i++)
    {
      fastpath->next_hop_data_table_root[i] = 
	&ssh_fastpath_next_hop_data_table[i][0];
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* !FASTPATH_PROVIDES_NH */

#ifndef FASTPATH_PROVIDES_TRD
  fastpath->transform_data_table_root = 
    ssh_fastpath_transform_data_table_root;
  for (i = 0; i < SSH_ENGINE_TR_D_TABLE_ROOT_SIZE; i++)
    {
      fastpath->transform_data_table_root[i] = 
	&ssh_fastpath_transform_data_table[i][0];
    }
#endif /* !FASTPATH_PROVIDES_TRD */

  fastpath->frag_table = ssh_fastpath_fragment_table;
  fastpath->frag_hash = ssh_fastpath_fragment_hash;

#ifdef SSHDIST_IPSEC_TRANSFORM
  fastpath->tc_table_root = ssh_fastpath_tc_table_root;
  for (i = 0; i < SSH_ENGINE_TRANSFORM_CONTEXTS_ROOT_SIZE; i++)
    {
      fastpath->tc_table_root[i] = &ssh_fastpath_tc_table[i][0];
    }
#endif /* SSHDIST_IPSEC_TRANSFORM */


#else /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifndef FASTPATH_PROVIDES_FLOW
  fastpath->flow_data_table_root = 
    (SshFastpathFlowData*)ssh_engine_calloc_2d_table(engine,
                                          fastpath->flow_table_size,
                                          SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE,
                                          sizeof(SshFastpathFlowDataStruct));
  if (fastpath->flow_data_table_root == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of flow table failed (size %u)",
			      (unsigned int) fastpath->flow_table_size));
      goto fail;
    }

  fastpath->flow_forward_hash_root =
    (SshUInt32**)ssh_engine_calloc_2d_table(engine,
                                            fastpath->flow_id_hash_size,
                                            SSH_ENGINE_FLOW_HASH_BLOCK_SIZE,
                                            sizeof(SshUInt32));

  fastpath->flow_reverse_hash_root =
    (SshUInt32**)ssh_engine_calloc_2d_table(engine,
                                            fastpath->flow_id_hash_size,
                                            SSH_ENGINE_FLOW_HASH_BLOCK_SIZE,
                                            sizeof(SshUInt32));

  if (fastpath->flow_forward_hash_root == NULL
      || fastpath->flow_reverse_hash_root == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of flow id hash tables failed"));
      goto fail;
    }
#endif /* !FASTPATH_PROVIDES_FLOW */

#ifndef FASTPATH_PROVIDES_NH
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  fastpath->next_hop_data_table_root =
    (SshFastpathNextHopData*)
    ssh_engine_calloc_2d_table(engine,
                               fastpath->next_hop_hash_size,
                               SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE,
                               sizeof(SshFastpathNextHopDataStruct));

  if (fastpath->next_hop_data_table_root == NULL)
    goto fail;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* !FASTPATH_PROVIDES_NH */

#ifndef FASTPATH_PROVIDES_TRD
  fastpath->transform_data_table_root =
    (SshFastpathTransformData*)ssh_engine_calloc_2d_table
    (engine, fastpath->transform_table_size,
     SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE,
     sizeof(SshFastpathTransformDataStruct));

  if (fastpath->transform_data_table_root == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of transform table failed (size %u)",
			      (unsigned int) fastpath->transform_table_size));
      goto fail;
    }
#endif /* !FASTPATH_PROVIDES_TRD */

  fastpath->frag_table = ssh_calloc_flags(SSH_ENGINE_FRAGMENT_TABLE_SIZE,
					  sizeof(fastpath->frag_table[0]),
					  SSH_KERNEL_ALLOC_WAIT);
  fastpath->frag_hash = ssh_calloc_flags(SSH_ENGINE_FRAGMENT_HASH_SIZE,
					 sizeof(fastpath->frag_hash[0]),
					 SSH_KERNEL_ALLOC_WAIT);
  
  if (fastpath->frag_table == NULL || fastpath->frag_hash == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of fragmentation tables failed"));
      goto fail;
    }

#ifdef SSHDIST_IPSEC_TRANSFORM
  fastpath->tc_table_root =
    (SshFastpathTransformContext*)
    ssh_engine_calloc_2d_table(engine,
                               SSH_ENGINE_MAX_TRANSFORM_CONTEXTS,
                               SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE,
                               sizeof(SshFastpathTransformContextStruct));

  if (fastpath->tc_table_root == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of transform context table failed"));
      goto fail;
    }
#endif /* SSHDIST_IPSEC_TRANSFORM */
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

  fastpath->frag_lock = ssh_kernel_mutex_alloc();
  if (fastpath->frag_lock == NULL)
    goto fail;

  if (!ssh_kernel_rw_mutex_init(fastpath->flow_id_hash_table_lock))
    goto fail;
  fastpath->flow_id_hash_table_lock_initialized = TRUE;

#ifdef SSH_IPSEC_STATISTICS
  fastpath->stats = ssh_calloc_flags(fastpath->num_cpus,
				     sizeof(SshFastpathGlobalStatsStruct),
				     SSH_KERNEL_ALLOC_WAIT);
  if (fastpath->stats == NULL)
    goto fail;
  if (!ssh_kernel_critical_section_init(fastpath->stats_critical_section))
    goto fail;
  fastpath->stats_critical_section_initialized = TRUE;
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSHDIST_IPSEC_TRANSFORM
  fastpath->tc_lock = ssh_kernel_mutex_alloc();
  if (fastpath->tc_lock == NULL)
    goto fail;

  if (!ssh_kernel_critical_section_init(fastpath->tc_critical_section))
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocating critical sections failed"));
      goto fail;
    }
  fastpath->tc_critical_section_initialized = TRUE;

  fastpath->tc_hash = ssh_calloc_flags(fastpath->num_cpus + 1, 
				       sizeof(SshUInt32 *),
				       SSH_KERNEL_ALLOC_WAIT);
  if (fastpath->tc_hash == NULL)
    goto fail;
  
  for (i = 0; i < fastpath->num_cpus + 1; i++)
    {
#ifndef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
      if (i < fastpath->num_cpus)
	{
	  fastpath->tc_hash[i] = NULL;
	  continue;
	}
#endif /* !SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

      fastpath->tc_hash[i] = 
	ssh_calloc_flags(SSH_ENGINE_TRANSFORM_CONTEXT_HASH_SIZE,
			 sizeof(SshUInt32), SSH_KERNEL_ALLOC_WAIT);
      if (fastpath->tc_hash[i] == NULL)
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("allocation of transform context hash table failed"));
	  goto fail;
	}
    }

  /* Initialize transform context hash and table. */
  fastpath->tc_head = ssh_calloc_flags(fastpath->num_cpus + 1, 
				       sizeof(SshUInt32), 
				       SSH_KERNEL_ALLOC_WAIT);
  fastpath->tc_tail = ssh_calloc_flags(fastpath->num_cpus + 1, 
				       sizeof(SshUInt32),
				       SSH_KERNEL_ALLOC_WAIT);

  if (!fastpath->tc_head || !fastpath->tc_tail)
    goto fail;
  for (i = 0; i < fastpath->num_cpus + 1; i++)
    {
      fastpath->tc_head[i] = SSH_IPSEC_INVALID_INDEX;
      fastpath->tc_tail[i] = SSH_IPSEC_INVALID_INDEX;

#ifndef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
      if (i < fastpath->num_cpus)
	continue;
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

      for (j = 0; j < SSH_ENGINE_TRANSFORM_CONTEXT_HASH_SIZE; j++)
	fastpath->tc_hash[i][j] = SSH_IPSEC_INVALID_INDEX;
    }

  for (i = 0; i < SSH_ENGINE_MAX_TRANSFORM_CONTEXTS; i++)
    {
      tc = SSH_FASTPATH_GET_TRC(fastpath, i);
      /* Initialize the transform context with data that will never match. */
      memset(tc, 0, sizeof(*tc));
      tc->self_index = i;

#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
      tc->cpu = i % fastpath->num_cpus; /* So that they go to different CPU
					 hash tables. */
#else /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
      tc->cpu = fastpath->num_cpus;
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
      SSH_PUT_32BIT(tc->keymat, i); /* So that they hash to different slots. */
      
      /* Put the context on the LRU list of transform contexts. */
      ssh_fastpath_tc_lru_insert_tail(fastpath, tc);
      
      /* Insert tc into the hash table. */
      ssh_fastpath_tc_hash_insert(fastpath, tc);
    }
#endif /* SSHDIST_IPSEC_TRANSFORM */

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  fastpath->ipcomp_lock = ssh_kernel_mutex_alloc();
  if (fastpath->ipcomp_lock == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate ipcomp lock"));
      goto fail;
    }
    
  fastpath->ipcomp_buf = ssh_calloc_flags(1, 
					  sizeof (SshFastpathIpcompListStruct),
					  SSH_KERNEL_ALLOC_WAIT);
  if (fastpath->ipcomp_buf == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate ipcomp buf"));
      goto fail;
    }
  if (!ssh_fastpath_ipcomp_buffer_list_init(fastpath->ipcomp_buf))
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Failed to allocate enough buffers for IPComp!"));
      goto fail;
    }
#ifdef SSHDIST_ZLIB
  fastpath->zlib_buf = ssh_calloc_flags(1, 
					sizeof (SshFastpathIpcompListStruct),
					SSH_KERNEL_ALLOC_WAIT);
  if (fastpath->zlib_buf == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate zlib buf"));
      goto fail;
    }
  
  if (!ssh_fastpath_ipcomp_zlib_buffer_init(fastpath->zlib_buf,
                                            fastpath->num_cpus))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate enough space for"
	            " zlib library"));
      goto fail;
    }
  if (!ssh_fastpath_ipcomp_zlib_context_allocate(fastpath))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate enough space for "
	            "zlib compression context"));
      goto fail;
    }
#endif /* SSHDIST_ZLIB */








#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */
  return fastpath;

 fail:
  if (fastpath) 
    ssh_fastpath_free(fastpath);
  return NULL;
}


void ssh_fastpath_free(SshFastpath fastpath)
{
  SshUInt32 i;
#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE





#ifdef SSHDIST_ZLIB
  if (fastpath->zlib_context)
    ssh_fastpath_ipcomp_zlib_context_free(fastpath);

  if (fastpath->zlib_buf)
    ssh_fastpath_ipcomp_buffer_list_free(fastpath->zlib_buf);

  ssh_free(fastpath->zlib_buf);
#endif /* SSHDIST_ZLIB */
  if (fastpath->ipcomp_buf)
    ssh_fastpath_ipcomp_buffer_list_free(fastpath->ipcomp_buf);

  ssh_free(fastpath->ipcomp_buf);

  if (fastpath->ipcomp_lock)
    ssh_kernel_mutex_free(fastpath->ipcomp_lock);
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
#ifndef FASTPATH_PROVIDES_FLOW
  ssh_engine_free_2d_table(fastpath->engine,
			   (void**)fastpath->flow_data_table_root,
                           fastpath->flow_table_size,
                           SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE);
  ssh_engine_free_2d_table(fastpath->engine,
			   (void**)fastpath->flow_forward_hash_root,
                           fastpath->flow_id_hash_size,
                           SSH_ENGINE_FLOW_HASH_BLOCK_SIZE);
  ssh_engine_free_2d_table(fastpath->engine,
			   (void**)fastpath->flow_reverse_hash_root,
                           fastpath->flow_id_hash_size,
                           SSH_ENGINE_FLOW_HASH_BLOCK_SIZE);
#endif /* !FASTPATH_PROVIDES_FLOW */

#ifndef FASTPATH_PROVIDES_NH
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ssh_engine_free_2d_table(fastpath->engine,
			   (void**)fastpath->next_hop_data_table_root,
                           fastpath->next_hop_hash_size,
                           SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE);
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* !FASTPATH_PROVIDES_NH */

#ifndef FASTPATH_PROVIDES_TRD
  ssh_engine_free_2d_table(fastpath->engine, 
			   (void**)fastpath->transform_data_table_root,
                           fastpath->transform_table_size,
                           SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE);
#endif /* !FASTPATH_PROVIDES_TRD */

  ssh_free(fastpath->frag_table);
  ssh_free(fastpath->frag_hash);

#ifdef SSHDIST_IPSEC_TRANSFORM
  ssh_engine_free_2d_table(fastpath->engine, 
			   (void**)fastpath->tc_table_root,
                           SSH_ENGINE_MAX_TRANSFORM_CONTEXTS,
                           SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE);
#endif /* SSHDIST_IPSEC_TRANSFORM */
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

#ifdef SSHDIST_IPSEC_TRANSFORM
  if (fastpath->tc_head)
    ssh_free(fastpath->tc_head);
  fastpath->tc_head = NULL;

  if (fastpath->tc_tail)
    ssh_free(fastpath->tc_tail);
  fastpath->tc_tail = NULL;

  if (fastpath->tc_lock)
    ssh_kernel_mutex_free(fastpath->tc_lock);
  fastpath->tc_lock = NULL;

  if (fastpath->tc_hash)
    {
      for (i = 0 ; i < fastpath->num_cpus + 1; i++)
	{
	  if (fastpath->tc_hash[i])
	    ssh_free(fastpath->tc_hash[i]);
	}
      ssh_free(fastpath->tc_hash);
    }
  if (fastpath->tc_critical_section_initialized)
    ssh_kernel_critical_section_uninit(fastpath->tc_critical_section);
#endif /* SSHDIST_IPSEC_TRANSFORM */

  if (fastpath->frag_lock)
    ssh_kernel_mutex_free(fastpath->frag_lock);
  fastpath->frag_lock = NULL;

  if (fastpath->flow_id_hash_table_lock_initialized)
  ssh_kernel_rw_mutex_uninit(fastpath->flow_id_hash_table_lock);

#ifdef SSH_IPSEC_STATISTICS
  if (fastpath->stats_critical_section_initialized)
    ssh_kernel_critical_section_uninit(fastpath->stats_critical_section);
  
  if (fastpath->stats)
    ssh_free(fastpath->stats);
#endif /* SSH_IPSEC_STATISTICS */

  ssh_free(fastpath);
}
