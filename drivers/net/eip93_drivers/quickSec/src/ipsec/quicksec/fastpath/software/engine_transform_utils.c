/*
 * engine_transform_utils.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Miscellaneous utility functions used by transforms and/or other
 * parts of the code.  These functions are frequently used and likely
 * to remain in the processor cache.
 *
 */ 

#include "sshincludes.h"
#include "engine_internal.h"

#ifdef SSHDIST_IPSEC_TRANSFORM
#include "hmac.h"
#ifdef SSHDIST_CRYPT_DES
#include "des.h"
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#include "rijndael.h"
#ifdef SSHDIST_CRYPT_MODE_GCM
#include "mode-gcm.h"
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_BLOWFISH
#ifdef SSH_IPSEC_CRYPT_EXT1_BLOWFISH
#include "blowfish.h"
#endif /* SSH_IPSEC_CRYPT_EXT1_BLOWFISH */
#endif /* SSHDIST_CRYPT_BLOWFISH */





#ifdef SSHDIST_CRYPT_MD5
#include "md5.h"
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
#include "sha.h"
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
#include "sha256.h"
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
#include "sha512.h"
#endif /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_XCBCMAC
#include "xcbc-mac.h"
#endif /* SSHDIST_CRYPT_XCBCMAC */
#ifdef SSH_IPSEC_TCPENCAP
#include "engine_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */
#ifdef SSHDIST_IPSEC_IPCOMP 
#include "engine_ipcomp_glue.h"
#endif /* SSHDIST_IPSEC_IPCOMP */

#include "fastpath_swi.h"


#define SSH_DEBUG_MODULE "SshEngineFastpathTransformUtils"

#ifdef SSHDIST_CRYPT_DES
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_3des_cbc_def =
{
  "3des-cbc",
  0,
  8,
  {24, 24, 24},
  ssh_des3_ctxsize, ssh_des3_init, ssh_des3_init_with_key_check, ssh_des3_cbc,
  ssh_des3_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
};

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_des_cbc_def =
{
  "des-cbc",
  0,
  8,
  {8, 8, 8},
  ssh_des_ctxsize, ssh_des_init, ssh_des_init_with_key_check, ssh_des_cbc,
  ssh_des_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
};
#endif /* SSHDIST_CRYPT_DES */

#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_cbc_def =
{
  "aes128-cbc",
  0,
  16,
  {16, 16, 16},
  ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_init, ssh_rijndael_cbc,
  ssh_rijndael_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
};

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_ctr_def =
{
  "aes128-ctr",
  0,
  16,
  {16, 16, 16},
  ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_init, ssh_rijndael_ctr,
  ssh_rijndael_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
};

#ifdef SSHDIST_CRYPT_MODE_GCM
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_gcm_def =
{
  "aes128-gcm",
  0,
  16,
  {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
  ssh_gcm_aes_table_256_ctxsize, 
  ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init, 
#else /* SSH_IPSEC_SMALL */
  ssh_gcm_aes_table_4k_ctxsize, 
  ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init, 
#endif /* SSH_IPSEC_SMALL */
  ssh_gcm_transform,
  NULL_FNPTR, TRUE, 
  16, ssh_gcm_reset, ssh_gcm_update, ssh_gcm_final, NULL_FNPTR
};

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_gcm_64_def =
{
  "aes128-gcm-8",
  0,
  16,
  {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
  ssh_gcm_aes_table_256_ctxsize, 
  ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init, 
#else /* SSH_IPSEC_SMALL */
  ssh_gcm_aes_table_4k_ctxsize, 
  ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init, 
#endif /* SSH_IPSEC_SMALL */
  ssh_gcm_transform,
  NULL_FNPTR, TRUE, 
  8, ssh_gcm_reset, ssh_gcm_update, ssh_gcm_64_final, NULL_FNPTR
};

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_null_auth_aes128_gmac_def =
{
  "aes128-gmac",
  0,
  16,
  {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
  ssh_gcm_aes_table_256_ctxsize, 
  ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init, 
#else /* SSH_IPSEC_SMALL */
  ssh_gcm_aes_table_4k_ctxsize, 
  ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init, 
#endif /* SSH_IPSEC_SMALL */
  ssh_gcm_update_and_copy,
  NULL_FNPTR, TRUE, 
  16, ssh_gcm_reset, ssh_gcm_update, ssh_gcm_final, NULL_FNPTR
};
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */


#ifdef SSHDIST_CRYPT_BLOWFISH
#ifdef SSH_IPSEC_CRYPT_EXT1_BLOWFISH
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_blowfish_cbc_def =
{
  "blowfish128-cbc",
  0,
  8,
  {16, 16, 16},
  ssh_blowfish_ctxsize, ssh_blowfish_init, ssh_blowfish_init, ssh_blowfish_cbc,
  NULL_FNPTR, FALSE, 0, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
};
#endif /* SSH_IPSEC_CRYPT_EXT1_BLOWFISH */
#endif /* SSHDIST_CRYPT_BLOWFISH */
















#ifdef SSHDIST_CRYPT_MD5
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_md5_96_def =
{
  "hmac-md5-96",
  0,
  12,
  FALSE,
  &ssh_hash_md5_def,
  ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit, 
  ssh_hmac_start, ssh_hmac_update,
  ssh_hmac_96_final, NULL_FNPTR,
  NULL_FNPTR,
};

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_md5_96_def =
{
  TRUE, &ssh_fastpath_hash_hmac_md5_96_def, NULL
};
#endif /* SSHDIST_CRYPT_MD5 */

#ifdef SSHDIST_CRYPT_SHA
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha1_96_def =
{
  "hmac-sha1-96",
  0,
  12,
  FALSE,
  &ssh_hash_sha_def,
  ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit, 
  ssh_hmac_start, ssh_hmac_update,
  ssh_hmac_96_final, NULL_FNPTR,
  NULL_FNPTR,
};

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha1_96_def =
{
  TRUE, &ssh_fastpath_hash_hmac_sha1_96_def, NULL
};
#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha256_128_def =
{
  "hmac-sha256-128",
  0,
  16,
  FALSE,
  &ssh_hash_sha256_def,
  ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit, 
  ssh_hmac_start, ssh_hmac_update,
  ssh_hmac_128_final, NULL_FNPTR,
  NULL_FNPTR,
};

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha256_128_def =
{
  TRUE, &ssh_fastpath_hash_hmac_sha256_128_def, NULL
};
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha384_192_def =
{
  "hmac-sha384-192",
  0,
  24,
  FALSE,
  &ssh_hash_sha384_def,
  ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit, 
  ssh_hmac_start, ssh_hmac_update,
  ssh_hmac_192_final, NULL_FNPTR,
  NULL_FNPTR,
};

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha384_192_def =
{
  TRUE, &ssh_fastpath_hash_hmac_sha384_192_def, NULL
};

SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha512_256_def =
{
  "hmac-sha512-256",
  0,
  32,
  FALSE,
  &ssh_hash_sha512_def,
  ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit, 
  ssh_hmac_start, ssh_hmac_update,
  ssh_hmac_256_final, NULL_FNPTR,
  NULL_FNPTR,
};

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha512_256_def =
{
  TRUE, &ssh_fastpath_hash_hmac_sha512_256_def, NULL
};
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA_IN_TEXT
SshCipherMacBaseDefStruct ssh_ciphermac_base_aes_def =
{ 16, ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_uninit, 
  ssh_rijndael_cbc_mac };

SSH_RODATA_IN_TEXT
SshCipherMacDefStruct ssh_fastpath_cipher_xcbc_aes_96_def =
{
  "xcbcmac-aes-96",
  FALSE, 12, { 16, 16, 16 },
  &ssh_ciphermac_base_aes_def,
  ssh_xcbcmac_ctxsize,
  ssh_xcbcmac_init,
  ssh_xcbcmac_uninit,
  ssh_xcbcmac_start,
  ssh_xcbcmac_update,
  ssh_xcbcmac_96_final,
};

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_xcbc_aes_96_def =
{
  FALSE, NULL, &ssh_fastpath_cipher_xcbc_aes_96_def
};
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */


#ifdef SSHDIST_IPSEC_IPCOMP 
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE












#ifdef SSHDIST_ZLIB
SSH_RODATA_IN_TEXT
SshCompressDefStruct ssh_fastpath_compress_deflate =
{
  "deflate",
  ssh_compression_deflate_maxbuf, 
  ssh_compression_deflate_get_context,
  ssh_compression_deflate_release_context,
  ssh_compression_deflate_transform
};

#endif /* SSHDIST_ZLIB */
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef DEBUG_HEAVY
int
fastpath_compute_tc_lru_list_size(SshFastpath fastpath, unsigned int cpu)
{
  SshUInt32 lru;
  int count;
  SshFastpathTransformContext tc;

  SSH_ASSERT(cpu <= fastpath->num_cpus);

  for (count = 0, lru = fastpath->tc_head[cpu]; 
       lru != SSH_IPSEC_INVALID_INDEX; 
       tc = SSH_FASTPATH_GET_TRC(fastpath, lru), 
         lru = tc->lru_next)
      count++;

  return count;
}
#endif /* DEBUG_HEAVY */

/* Removes the given transform context from the LRU list of transform 
   contexts. */
void ssh_fastpath_tc_lru_remove(SshFastpath fastpath, 
			      SshFastpathTransformContext tc)
{
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Removing tc=%p on CPU=%d from the LRU list", 
		       tc, tc->cpu));

#ifdef DEBUG_HEAVY
  SSH_DEBUG(SSH_D_MY + 10, ("LRU list on CPU %d has %d elements",
			    tc->cpu, 
			    fastpath_compute_tc_lru_list_size(fastpath, 
							      tc->cpu)));
#endif /* DEBUG_HEAVY */
  
  /* Transform level hardware accelerators are not on the LRU list. */
  SSH_ASSERT(tc->transform_accel == NULL);

  if (tc->lru_prev != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, tc->lru_prev);
      tc2->lru_next = tc->lru_next;
    }
  else
    {
      SSH_ASSERT(tc->self_index == fastpath->tc_head[tc->cpu]);
      fastpath->tc_head[tc->cpu] = tc->lru_next;
    }
  if (tc->lru_next != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, tc->lru_next);
      tc2->lru_prev = tc->lru_prev;
    }
  else
    {
      SSH_ASSERT(tc->self_index == fastpath->tc_tail[tc->cpu]);
      fastpath->tc_tail[tc->cpu] = tc->lru_prev;
    }
}

/* Adds the given transform context at the head of the LRU list of
   transform contexts.  */
void ssh_fastpath_tc_lru_insert(SshFastpath fastpath,
			      SshFastpathTransformContext tc)
{
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Adding tc=%p on CPU=%d to the LRU list", 
		       tc, tc->cpu));

  /* Transform level hardware accelerators are not on the LRU list. */
  SSH_ASSERT(tc->transform_accel == NULL);

  tc->lru_prev = SSH_IPSEC_INVALID_INDEX;
  tc->lru_next = fastpath->tc_head[tc->cpu];
  if (fastpath->tc_head[tc->cpu] != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, fastpath->tc_head[tc->cpu]);
      tc2->lru_prev = tc->self_index;
    }
  fastpath->tc_head[tc->cpu] = tc->self_index;
  if (fastpath->tc_tail[tc->cpu] == SSH_IPSEC_INVALID_INDEX)
    fastpath->tc_tail[tc->cpu] = tc->self_index;
}

/* Adds the given transform context at the tail of the LRU list.  This
   means that it will be a preferred candidate for reuse.  This
   function is also called from initialization code. */
void ssh_fastpath_tc_lru_insert_tail(SshFastpath fastpath,
                                   SshFastpathTransformContext tc)
{
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Adding tc=%p on CPU=%d to the tail of the LRU list", 
		       tc, tc->cpu));
  
  /* Transform level hardware accelerators are not on the LRU list. */
  SSH_ASSERT(tc->transform_accel == NULL);
  
  tc->lru_next = SSH_IPSEC_INVALID_INDEX;
  tc->lru_prev = fastpath->tc_tail[tc->cpu];
  if (fastpath->tc_tail[tc->cpu] != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, fastpath->tc_tail[tc->cpu]);
      tc2->lru_next = tc->self_index;
    }
  fastpath->tc_tail[tc->cpu] = tc->self_index;
  if (fastpath->tc_head[tc->cpu] == SSH_IPSEC_INVALID_INDEX)
    fastpath->tc_head[tc->cpu] = tc->self_index;
}

/* Macro for calculating hashvalue for a transform context. */
#define SSH_FASTPATH_TC_HASH(keymat, esp_spi, ah_spi)               \
  ((SSH_GET_32BIT((keymat)) ^                                       \
   SSH_GET_32BIT((keymat) + SSH_IPSEC_MAX_ESP_KEY_BITS / 8) ^       \
    (esp_spi) ^ (ah_spi)) % SSH_ENGINE_TRANSFORM_CONTEXT_HASH_SIZE)

#define SSH_FASTPATH_TRANSFORM_CONTEXT_HASH(tc) \
  SSH_FASTPATH_TC_HASH((tc)->keymat, (tc)->esp_spi, (tc)->ah_spi)

/* Removes tc from the hash table.  The tc must be in the table. */
void ssh_fastpath_tc_hash_remove(SshFastpath fastpath,
				 SshFastpathTransformContext tc)
{
  SshUInt32 hashvalue, *tc_indexp;
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Removing tc=%p on CPU=%d from the hash list", 
		       tc, tc->cpu));

  hashvalue = SSH_FASTPATH_TRANSFORM_CONTEXT_HASH(tc);
  for (tc_indexp = &fastpath->tc_hash[tc->cpu][hashvalue];
       *tc_indexp != SSH_IPSEC_INVALID_INDEX && *tc_indexp != tc->self_index;
       tc_indexp = &tc2->hash_next)
    tc2 = SSH_FASTPATH_GET_TRC(fastpath, *tc_indexp);
  SSH_ASSERT(*tc_indexp == tc->self_index);
  *tc_indexp = tc->hash_next;
}

/* Adds the tc to the hash table.  This funtion is also called from
   initialization code. */
void ssh_fastpath_tc_hash_insert(SshFastpath fastpath,
				 SshFastpathTransformContext tc)
{
  SshUInt32 hashvalue;
#ifdef DEBUG_LIGHT
  SshUInt32 tc_index;
  SshFastpathTransformContext tc2;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_MY, ("Adding tc=%p on CPU=%d to the hash list", 
		       tc, tc->cpu));

  /* Compute hash slot index for it. */
  hashvalue = SSH_FASTPATH_TRANSFORM_CONTEXT_HASH(tc);

#ifdef DEBUG_LIGHT
  /* Sanity check that it is not already in the hash table. */
  for (tc_index = fastpath->tc_hash[tc->cpu][hashvalue];
       tc_index != SSH_IPSEC_INVALID_INDEX;
       tc_index = tc2->hash_next)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
      SSH_ASSERT(tc != tc2);
    }
#endif /* DEBUG_LIGHT */

  /* Add the transform context in the hash list in the slot. */
  tc->hash_next = fastpath->tc_hash[tc->cpu][hashvalue];
  fastpath->tc_hash[tc->cpu][hashvalue] = tc->self_index;
}

const SshCipherDefStruct * fastpath_get_cipher_def(SshEngineTransformRun trr,
						   SshUInt32 transform,
						   const char **name)
{
  const char *ciphername = NULL;
  const SshCipherDefStruct *cipher;

  ciphername = "none";
  cipher = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_RIJNDAEL is undefined */
    }
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_CRYPT_AES)
    {
      ciphername = "aes-cbc";
      cipher = &ssh_fastpath_aes128_cbc_def;
      SSH_ASSERT(trr->cipher_key_size);
    }
  else if (transform & SSH_PM_CRYPT_AES_CTR)
    {
      ciphername = "aes-ctr";
      cipher = &ssh_fastpath_aes128_ctr_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#ifdef SSHDIST_CRYPT_MODE_GCM
  else if (transform & SSH_PM_CRYPT_AES_GCM)
    {
      ciphername = "aes-gcm";
      cipher = &ssh_fastpath_aes128_gcm_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_8)
    {
      ciphername = "aes-gcm-64";
      cipher = &ssh_fastpath_aes128_gcm_64_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
    {
      ciphername = "null-auth-aes-gmac";
      cipher = &ssh_fastpath_null_auth_aes128_gmac_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_DES
  else if (transform & SSH_PM_CRYPT_3DES)
    {
      ciphername = "3des-cbc";
      cipher = &ssh_fastpath_3des_cbc_def;
      SSH_ASSERT(trr->cipher_key_size == 24);
    }
  else if (transform & SSH_PM_CRYPT_DES)
    {
      ciphername = "des-cbc";
      cipher = &ssh_fastpath_des_cbc_def;
      SSH_ASSERT(trr->cipher_key_size == 8);
    }
#endif /* SSHDIST_CRYPT_DES */
  else if (transform & SSH_PM_CRYPT_EXT1)
    {
#ifdef SSHDIST_CRYPT_BLOWFISH
#ifdef SSH_IPSEC_CRYPT_EXT1_BLOWFISH
      ciphername = "blowfish-cbc";
      cipher = &ssh_fastpath_blowfish_cbc_def;
      SSH_ASSERT(trr->cipher_key_size);
#endif /* SSH_IPSEC_CRYPT_EXT1_BLOWFISH */
#endif /* SSHDIST_CRYPT_BLOWFISH */
      if (cipher == NULL)
        {
          ssh_warning("EXT1 cipher not configured");
          return NULL;
        }
    }
  else if (transform & SSH_PM_CRYPT_EXT2)
    {







      if (cipher == NULL)
        {
          ssh_warning("EXT2 cipher not configured");
          return NULL;
        }
    }
  else
    {
      /* No cipher configured. */
      SSH_ASSERT(trr->cipher_key_size == 0);
    }

  if (name)
    *name = ciphername;

  return cipher;
}

const SshMacDefStruct * fastpath_get_mac_def(SshEngineTransformRun trr,
					     SshUInt32 transform,
					     const char **name)
{
  const char *macname = NULL;
  const SshMacDefStruct *mac;

  macname = "none";
  mac = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_MD5 is undefined */
    }
#ifdef SSHDIST_CRYPT_MD5
  else if (transform & SSH_PM_MAC_HMAC_MD5)
    {
      macname = "hmac-md5-96";
      mac = &ssh_fastpath_hmac_md5_96_def;
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
  else if (transform & SSH_PM_MAC_HMAC_SHA1)
    {
      macname = "hmac-sha1-96";
      mac = &ssh_fastpath_hmac_sha1_96_def;
      SSH_ASSERT(trr->mac_key_size == 20);
    }
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 32)
    {
      macname = "hmac-sha256-128";
      mac = &ssh_fastpath_hmac_sha256_128_def;
    }
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 48)
    {
      macname = "hmac-sha384-192";
      mac = &ssh_fastpath_hmac_sha384_192_def;
    }
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 64)
    {
      macname = "hmac-sha512-256";
      mac = &ssh_fastpath_hmac_sha512_256_def;
    }
#endif /* SSHDIST_CRYPT_SHA512 */
  else if ((transform & SSH_PM_MAC_HMAC_SHA2))
    {
      SSH_ASSERT(0); /* Unsupported sha2 key size requested... */
    }
#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_MAC_XCBC_AES)
    {
      macname = "xcbc-aes-96";
      mac = &ssh_fastpath_xcbc_aes_96_def;
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */
  else if (transform & SSH_PM_MAC_EXT1)
    {
      ssh_warning("EXT1 MAC not yet supported");
      return NULL;
    }
  else if (transform & SSH_PM_MAC_EXT2)
    {
      ssh_warning("EXT2 MAC not yet supported");
      return NULL;
    }
  else
    {
      /* No MAC configured. */
      SSH_ASSERT(trr->mac_key_size == 0);
    }
  
  if (name)
    *name = macname;
  return mac;
  
}

#ifdef SSHDIST_IPSEC_IPCOMP
/* Notation on distdefines: 

   SSHDIST_IPSEC_COMPRESSION_* indicates if a particular compression 
   algorithm may be used by the system.

   SSHDIST_IPSEC_COMPRESS_* or SSHDIST_ZLIB indicates if a software 
   implementation of a particular compression algorithm is present. 

   It may be so that a compression algorithm may only be used in hardware. */

static const
SshCompressDefStruct * fastpath_get_compress_def(SshEngineTransformRun trr,
						 SshUInt32 transform,
						 const char **name)
{
  const char *compress_name = NULL;
  const SshCompressDefStruct *compress; 

  compress_name = "none";
  compress = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_IPSEC_COMPRESSION_LZS is undefined */
    }
#ifdef SSHDIST_IPSEC_COMPRESSION_LZS
  else if (transform & SSH_PM_COMPRESS_LZS)
    {
      compress_name = "lzs";





    } 
#endif /*SSHDIST_IPSEC_COMPRESSION_LZS */
#ifdef SSHDIST_IPSEC_COMPRESSION_DEFLATE
  else if (transform & SSH_PM_COMPRESS_DEFLATE)
    {
      compress_name = "deflate";
#ifdef SSHDIST_ZLIB
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
      compress = &ssh_fastpath_compress_deflate;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_ZLIB */
    }
#endif /* SSHDIST_IPSEC_COMPRESSION_DEFLATE */
  else
    {
       /* No compression algorithm negotiated */
    }

  if (name)
    *name = compress_name;
  return compress; 
}
#endif  /* SSHDIST_IPSEC_IPCOMP */

/* Initialize the transform context 'tc'. The crypto contexts in 'tc' have
   already been initialized when this is called. */
void
ssh_fastpath_init_transform_context(SshFastpath fastpath,
				    SshFastpathTransformContext tc,
				    SshEngineTransformRun trr,
				    SshUInt32 transform,
				    Boolean for_output,
				    Boolean inner_is_ipv6,
				    Boolean outer_is_ipv6)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Entered tc=%p, self_index=%d", tc,
			  (int) tc->self_index));

  /* Initialize tc. */
  tc->transform = transform;
  memcpy(tc->keymat, trr->mykeymat, sizeof(tc->keymat));
  tc->ah_spi = trr->myspis[SSH_PME_SPI_AH_IN];
  tc->esp_spi = trr->myspis[SSH_PME_SPI_ESP_IN];
#ifdef SSHDIST_IPSEC_IPCOMP
  tc->ipcomp_cpi = (SshUInt16)trr->myspis[SSH_PME_SPI_IPCOMP_IN];
#endif /* SSHDIST_IPSEC_IPCOMP */

  tc->ipv6 = (outer_is_ipv6 ? 1 : 0);
  tc->for_output = (for_output ? 1 : 0);
  tc->tr_index = trr->tr_index;

  /* Are we using counter mode? Currently AES CTR or AES GCM are the only 
     counter mode ciphers. */
  tc->counter_mode = (transform & 
		      (SSH_PM_CRYPT_AES_CTR |
                       SSH_PM_CRYPT_NULL_AUTH_AES_GMAC |
                       SSH_PM_CRYPT_AES_GCM |
                       SSH_PM_CRYPT_AES_GCM_8)) ? TRUE : FALSE;

  /*  If using counter mode, at this point we assume the nonce size
      is 4 bytes and we store the nonce as a SshUInt32. */
  if (tc->counter_mode)
    {
      SSH_ASSERT(trr->cipher_nonce_size == 4);
      tc->cipher_nonce = SSH_GET_32BIT(trr->mykeymat + trr->cipher_key_size);
    }
  
  /* Determine cipher IV length. */
  tc->cipher_iv_len = trr->cipher_iv_size;

  /* Determine cipher block length and MAC digest length. */
  if (tc->cipher)
    tc->cipher_block_len = (SshUInt8) tc->cipher->block_length;
  else
    tc->cipher_block_len = 0;

  if (tc->mac)
    tc->icv_len = tc->mac->hmac ? tc->mac->hash->digest_length :
                              tc->mac->cipher->digest_length;
  else if (tc->cipher && tc->cipher->is_auth_cipher)
#ifdef SSH_IPSEC_AH
    if (transform & SSH_PM_IPSEC_AH)
      tc->icv_len = tc->cipher->digest_length + tc->cipher_iv_len;
    else
#endif /* SSH_IPSEC_AH */
      tc->icv_len = (SshUInt8)tc->cipher->digest_length;
  else 
    tc->icv_len = 0;

  tc->iphdrlen = outer_is_ipv6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN;

  /* Resolve IP's next header. */
  if (transform & SSH_PM_IPSEC_NATT)
    tc->ip_nh = SSH_IPPROTO_UDP;
  else if (transform & SSH_PM_IPSEC_AH)
    tc->ip_nh = SSH_IPPROTO_AH;
  else if (transform & SSH_PM_IPSEC_ESP)
    tc->ip_nh = SSH_IPPROTO_ESP;
  else if (transform & SSH_PM_IPSEC_IPCOMP)
    tc->ip_nh = SSH_IPPROTO_IPPCP;
  else if (transform & SSH_PM_IPSEC_L2TP)
    tc->ip_nh = SSH_IPPROTO_UDP;
  else
    tc->ip_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;

  if (transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP))
    {
      tc->prefix_at_0 = 1;
      tc->natt_ofs = outer_is_ipv6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN;
    }
  else
    {
      tc->prefix_at_0 = 0;
      tc->natt_ofs = 0;
    }
  tc->natt_len = 0;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    tc->natt_len = 8;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSH_IPSEC_AH
  tc->ah_ofs = tc->natt_ofs + tc->natt_len;

  /* Resolve AH's next header. */
  if (transform & SSH_PM_IPSEC_ESP)
    tc->ah_nh = SSH_IPPROTO_ESP;
  else if (transform & SSH_PM_IPSEC_IPCOMP)
    tc->ah_nh = SSH_IPPROTO_IPPCP;
  else if (transform & SSH_PM_IPSEC_L2TP)
    tc->ah_nh = SSH_IPPROTO_UDP;
  else if (transform & SSH_PM_IPSEC_TUNNEL)
    tc->ah_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;
  else
    tc->ah_nh = 0;              /* Copy from original IP header. */
#endif /* SSH_IPSEC_AH */

  tc->esp_ofs = tc->natt_ofs + tc->natt_len;

#ifdef SSH_IPSEC_AH
  /* Add AH len to esp ofs. */
  if (transform & SSH_PM_IPSEC_AH)
    {
      if (tc->ipv6)
        {
          /* Should be 64 bit aligned */




          tc->ah_hdr_pad_len = (12 + tc->icv_len) % 8;
          if (tc->ah_hdr_pad_len != 0)
            tc->ah_hdr_pad_len = 8 - tc->ah_hdr_pad_len;
        }
      else
        {
          /* Should be 32 bit aligned */




          tc->ah_hdr_pad_len = (12 + tc->icv_len) % 4;
          if (tc->ah_hdr_pad_len != 0)
            tc->ah_hdr_pad_len = 4 - tc->ah_hdr_pad_len;
        }
      
      tc->esp_ofs += 12 + tc->icv_len + tc->ah_hdr_pad_len;
    }
#endif /* SSH_IPSEC_AH */

  /* Resolve ESP's next header. */
  if (transform & SSH_PM_IPSEC_IPCOMP)
    tc->esp_nh = SSH_IPPROTO_IPPCP;
  else if (transform & SSH_PM_IPSEC_L2TP)
    tc->esp_nh = SSH_IPPROTO_UDP;
  else if (transform & SSH_PM_IPSEC_TUNNEL)
    tc->esp_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;
  else
    tc->esp_nh = 0;             /* Copy from original IP header. */

  if (transform & SSH_PM_IPSEC_ESP)
      tc->esp_len = 8 + tc->cipher_iv_len;
  else
    tc->esp_len = 0;

#ifdef SSHDIST_IPSEC_IPCOMP 
   /* Resolve IPCOMP's next header */
  if (transform & SSH_PM_IPSEC_IPCOMP)
    {
      if (transform & SSH_PM_IPSEC_L2TP)
        tc->ipcomp_nh = SSH_IPPROTO_UDP;
      else if (transform & SSH_PM_IPSEC_TUNNEL)
        tc->ipcomp_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;
      else
        tc->ipcomp_nh = 0;             /* Copy from original IP header. */

      tc->ipcomp_ofs = tc->esp_ofs + tc->esp_len;
      tc->prefix_len = tc->ipcomp_ofs + 4;
    }
  else
#endif /* SSHDIST_IPSEC_IPCOMP */
    tc->prefix_len = tc->esp_ofs + tc->esp_len;

#ifdef SSHDIST_L2TP
  if (transform & SSH_PM_IPSEC_L2TP)
    {
      tc->l2tp_ofs = tc->prefix_len;
      tc->prefix_len += SSH_UDP_HEADER_LEN + 8 + 1;
      if (trr->l2tp_flags & SSH_ENGINE_L2TP_SEQ)
        tc->prefix_len += 4;
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_ACFC) == 0)
        tc->prefix_len += 2;
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_PFC) == 0)
        tc->prefix_len++;
    }
#endif /* SSHDIST_L2TP */
  SSH_ASSERT(tc->prefix_len <= SSH_ENGINE_MAX_TRANSFORM_PREFIX);

  tc->trailer_len = (transform & SSH_PM_IPSEC_ESP) ? 2 : 0;
  if ((transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH)) ==
      SSH_PM_IPSEC_ESP)
    tc->trailer_len += tc->icv_len;

#ifdef SSH_IPSEC_TCPENCAP
  if (trr->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
    tc->tcp_encaps_len = SSH_TCPH_HDRLEN + SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN;
  else
    tc->tcp_encaps_len = 0;
#endif /* SSH_IPSEC_TCPENCAP */

  /* Counter mode is really a stream cipher and does not require padding
     to the cipher block length */
   tc->pad_boundary = (tc->counter_mode == 1) ? 0 : tc->cipher_block_len;

  if (tc->pad_boundary < 4)
    tc->pad_boundary = 4;
}

/* This function allocate new cypto contexts for the transform 'tc' from the
   information contained in 'trr' and sets the crypto contexts to 'tc'.
   Returns TRUE on success and FALSE on failure. */
Boolean
fastpath_alloc_crypto_transform_context(SshFastpath fastpath,
					SshFastpathTransformContext tc,
					SshEngineTransformRun trr,
					SshEnginePacketContext pc,
					Boolean for_output,
					Boolean inner_is_ipv6,
					Boolean outer_is_ipv6)
{
  SshEngine engine = fastpath->engine;
  SshUInt32 transform;
  SshUInt32 requested_ops, provided_ops;
  SshHWAccel transform_accel, encmac_accel, enc_accel, mac_accel;
  unsigned char esp_iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  const char *ciphername = NULL, *macname = NULL, *ipcompname = NULL;
  const SshCipherDefStruct *cipher;
  const SshMacDefStruct *mac;
  void *cipher_context, *mac_context;
#ifdef SSHDIST_IPSEC_IPCOMP
  const SshCompressDefStruct *compress;
#endif /* SSHDIST_IPSEC_IPCOMP */
  SshCryptoStatus status;
  Boolean counter_mode;
  size_t esp_ivlen;

  transform = pc->transform;

 SSH_DEBUG(SSH_D_MIDOK, ("Allocating new transform context"));

 /* We now try to obtain hardware acceleration contexts for the
    transforms.  First we convert the internal representation of
    algorithm names to the format used by the current hardware acceleration
    API, and and then try to obtain acceleration contexts of various
    kinds.  If we don't get acceleration contexts, then we try to allocate
    software contexts.  We don't modify the transform context in any
    way until we have allocated the required contexts; this way we know
    that when we destroy the old context, initializing the new one will
    succeed. */

 /* Determine the cipher and mac algorithm to use. */
 cipher = fastpath_get_cipher_def(trr, transform, &ciphername);
 mac = fastpath_get_mac_def(trr, transform, &macname);

 /* Check that the cipher and mac were found. */
 if (((transform & SSH_PM_CRYPT_MASK) && 
      ((transform & SSH_PM_CRYPT_MASK) != SSH_PM_CRYPT_NULL)) && !cipher)
   {
     SSH_DEBUG(SSH_D_FAIL, ("Cipher algorithm not found, transform=0x%x", 
			    (unsigned int) transform));
     return FALSE;
   }
 if (cipher && cipher->is_auth_cipher)
   {
     if (mac)
       {
	 SSH_DEBUG(SSH_D_FAIL, ("Cannot use mac algorithm with combined "
				"cipher, transform=0x%x",
				(unsigned int) transform));
	 return FALSE;
       }
   }
 else if ((transform & SSH_PM_MAC_MASK) && !mac)
   {
     SSH_DEBUG(SSH_D_FAIL, ("Mac algorithm not found, transform=0x%x", 
			    (unsigned int) transform));
     return FALSE;
   } 
 
#ifdef SSHDIST_IPSEC_IPCOMP
 compress = fastpath_get_compress_def(trr, transform, &ipcompname);
 if ((transform & SSH_PM_IPSEC_IPCOMP) && !strcmp(ipcompname, "none"))
   {
     SSH_DEBUG(SSH_D_FAIL, ("Compression algorithm not found, "
			    "transform=0x%x",(unsigned int)transform));
     return FALSE;
   }
#endif /* SSHDIST_IPSEC_IPCOMP */
 
  /* Sanity check key lengths. */
  SSH_ASSERT(trr->cipher_key_size + trr->cipher_nonce_size <=
             SSH_IPSEC_MAX_ESP_KEY_BITS / 8);
  SSH_ASSERT(trr->mac_key_size <= SSH_IPSEC_MAX_MAC_KEY_BITS / 8);

  /* Initialize the context variables to NULL so that we can easily free
     the already allocated ones on error. */
  transform_accel = NULL;
  encmac_accel = NULL;
  enc_accel = NULL;
  mac_accel = NULL;
  cipher_context = NULL;
  mac_context = NULL;

  /* If using counter mode, we need to give the cipher nonce to the
     hardware acceleration context. Do this via the 'esp_iv' parameter.
     For cbc mode the 'esp_iv' parameter is unused. */
  SSH_ASSERT(trr->cipher_nonce_size <= SSH_CIPHER_MAX_BLOCK_SIZE);
  memset(esp_iv, 0, SSH_CIPHER_MAX_BLOCK_SIZE);
  esp_ivlen = trr->cipher_nonce_size;
  if (esp_ivlen)
    memcpy(esp_iv, trr->mykeymat + trr->cipher_key_size, esp_ivlen);

  /* Construct flags for combined transform acceleration. */
  if (for_output)
    requested_ops = SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE;
  else
    requested_ops = SSH_HWACCEL_COMBINED_FLAG_DECAPSULATE;
#ifdef SSH_IPSEC_AH
  if (transform & SSH_PM_IPSEC_AH)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_AH;
#endif /* SSH_IPSEC_AH */
  if (transform & SSH_PM_IPSEC_ESP)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_ESP;
#ifdef SSHDIST_IPSEC_IPCOMP
  if (transform & SSH_PM_IPSEC_IPCOMP)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_IPCOMP;
#endif /* SSHDIST_IPSEC_IPCOMP */
  if (transform & SSH_PM_IPSEC_TUNNEL)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_IPIP;
  if (outer_is_ipv6)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_REQUIRE_IPV6;
  if (transform & SSH_PM_IPSEC_LONGSEQ)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_LONGSEQ;
  if (transform & SSH_PM_IPSEC_ANTIREPLAY)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_NATT;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  if (trr->df_bit_processing == SSH_ENGINE_DF_CLEAR)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_DF_CLEAR;
  else if (trr->df_bit_processing == SSH_ENGINE_DF_SET)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_DF_SET;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocating a combined transform context"));

  /* Allocate a "combined" transform acceleration context.  Note that
     the API does not allow initializing the sequence number; this is
     because some acceleration hardware devices do not allow
     retrieving or setting the sequence numbers.  Consequently, when
     combined transform acceleration devices are in use, the number of
     transform contexts should be configured in ipsec_params.h to be
     twice the maximum number of tunnels plus some for rekeying. */
#ifdef SSHDIST_L2TP
  if (transform & SSH_PM_IPSEC_L2TP ||
      pc->flags & SSH_ENGINE_FLOW_D_IGNORE_L2TP)
    transform_accel = NULL;
  else
#endif /* SSHDIST_L2TP */
    transform_accel =
      ssh_hwaccel_alloc_combined(engine->interceptor,
                                 requested_ops,
				 &provided_ops,
                                 trr->myspis[SSH_PME_SPI_AH_IN],
                                 (transform & SSH_PM_IPSEC_AH) ?
                                 macname : NULL,
                                 trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                                 trr->mac_key_size,
                                 trr->myspis[SSH_PME_SPI_ESP_IN],
                                 (transform & SSH_PM_IPSEC_AH) ? NULL :
                                 macname,
                                 ciphername,
                                 trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                                 trr->mac_key_size,
                                 trr->mykeymat,
                                 trr->cipher_key_size,
                                 esp_iv, esp_ivlen,
                                 trr->myspis[SSH_PME_SPI_IPCOMP_IN],
                                 ipcompname,
                                 &trr->local_addr, &trr->gw_addr,
                                 trr->mycount_low,
                                 trr->mycount_high,
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
				 trr->remote_port,
				 trr->natt_oa_l, trr->natt_oa_r
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
				 0, NULL, NULL
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
				 );
  if ((requested_ops & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY) &&
      !(provided_ops & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY))
    {
      tc->accel_unsupported_mask |= SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY;
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Set unsupported_mask for those parts that we can compensate on
     software. */
  if ((requested_ops & SSH_HWACCEL_COMBINED_FLAG_NATT) &&
      !(provided_ops & SSH_HWACCEL_COMBINED_FLAG_NATT))
    {
      tc->accel_unsupported_mask |= SSH_HWACCEL_COMBINED_FLAG_NATT;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSHDIST_IPSEC_IPCOMP
  if (transform_accel && (requested_ops & SSH_HWACCEL_COMBINED_FLAG_IPCOMP
        && !(provided_ops & SSH_HWACCEL_COMBINED_FLAG_IPCOMP)))
    {
      /* IPCOMP was requested but we could not allocate combined
	 transform with it. Do everything in software for now */
      SSH_DEBUG(SSH_D_HIGHOK, ("IPCOMP negotiated but failed to allocate "
			       "combined transform accelerator"));
      ssh_hwaccel_free_combined(transform_accel);
      transform_accel = NULL;
    }
  /* If the IPCOMP support is not compiled into software as well then 
     fail the operation */
  if (!transform_accel && (transform & SSH_PM_IPSEC_IPCOMP) && !compress)
    {
     SSH_DEBUG(SSH_D_FAIL, ("Compression algorithm not found, "
			    "transform=0x%x",(unsigned int)transform));
     return FALSE;
    }
#endif /* SSHDIST_IPSEC_IPCOMP */
  /* Try getting hardware acceleration for both encryption and MAC
     computation. The HWAccel API is broken for IPSec level acceleration
     with AH and must be disabled. */
  if (!transform_accel && mac && cipher &&
      ((transform & SSH_PM_IPSEC_AH) == 0))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Allocating a IPsec Encryption/MAC transform context"));
      encmac_accel =
	ssh_hwaccel_alloc_ipsec(engine->interceptor,
				for_output, ciphername, trr->mykeymat,
				trr->cipher_key_size,
				esp_iv, esp_ivlen,
				FALSE,
				macname,
				trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
				trr->mac_key_size);
    }
  else
    {
      encmac_accel = NULL;
    }
  /* If getting hardware acceleration for the whole thing failed, try
     getting it for the encryption part only. */
  if (!transform_accel && !encmac_accel && cipher)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Allocating a IPsec Encryption transform context"));
      enc_accel =
	ssh_hwaccel_alloc_ipsec(engine->interceptor,
				for_output, ciphername, trr->mykeymat,
				trr->cipher_key_size,
				esp_iv, esp_ivlen,
				FALSE, NULL, NULL, 0);
    }
  else
    {
      enc_accel = NULL;
    }

  /* If getting hardware acceleration for the encryption part failed, try
     getting it for the MAC part only. The HWAccel API is broken for IPSec
     level acceleration  with AH and must be disabled. */
  if (!transform_accel && !encmac_accel && !enc_accel && mac &&
      ((transform & SSH_PM_IPSEC_AH) == 0))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Allocating a IPsec MAC transform context"));
      mac_accel =
	ssh_hwaccel_alloc_ipsec(engine->interceptor,
				for_output, NULL, NULL, 0, NULL, 0,
				FALSE,
				macname,
				trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
				trr->mac_key_size);
    }
  else
    {
      mac_accel = NULL;
    }

#ifdef DEBUG_LIGHT
  if (transform_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using transform-level acceleration"));
  if (encmac_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using encryption+mac acceleration"));
  if (enc_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using acceleration for encryption"));
  if (mac_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using acceleration for MAC"));
  if (!transform_accel && !encmac_accel && !enc_accel && !mac_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using software crypto"));
#endif /* DEBUG_LIGHT */

  /* Allocate software encryption context if we need one and can't do
     the encryption in hardware. */
  if (!transform_accel && !encmac_accel && !enc_accel && cipher)
    {
      cipher_context = ssh_malloc((*cipher->ctxsize)());
      if (!cipher_context)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate cipher context"));
	  goto error;
        }

      /* Are we using counter mode? Currently AES CTR and AES GCM are the only
         counter mode ciphers. */
      counter_mode = (transform & 
		      (SSH_PM_CRYPT_AES_CTR |
                       SSH_PM_CRYPT_NULL_AUTH_AES_GMAC |
                       SSH_PM_CRYPT_AES_GCM |
                       SSH_PM_CRYPT_AES_GCM_8)) ? TRUE : FALSE;
     
      /* For counter mode encryption is the same as decryption. */
      status = (*cipher->init)(cipher_context,
                               trr->mykeymat, trr->cipher_key_size,
                               counter_mode &&
			       (transform & (SSH_PM_CRYPT_AES_CTR |
					     SSH_PM_CRYPT_NULL_AUTH_AES_GMAC))
			       ? TRUE : for_output);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cipher initialization failed: %d", status));
          goto error;
        }
    }
  else
    cipher_context = NULL;

  /* Allocate software MAC context if we need one and can't do the
     MAC computation in hardware. */
  if (!transform_accel && !encmac_accel && !mac_accel && mac)
    {
      if (mac->hmac)
	mac_context = ssh_malloc((*mac->hash->ctxsize)(mac->hash->hash_def));
      else
	mac_context =
	  ssh_malloc((*mac->cipher->ctxsize)(mac->cipher->cipher_def));

      if (!mac_context)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate MAC context"));
          goto error;
        }

      if (mac->hmac)
	status = 
	  (*mac->hash->init)(mac_context,
			     trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
			     trr->mac_key_size,
			     mac->hash->hash_def);
      else
	status = 
	  (*mac->cipher->init)(mac_context,
			       trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
			       trr->mac_key_size,
			       mac->cipher->cipher_def);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC initialization failed: %d", status));
          goto error;
        }
    }
  else
    mac_context = NULL;

  /* We now know that creating the new tc will be successful.  Free old
     contexts. */
  if (tc->transform_accel)
    ssh_hwaccel_free_combined(tc->transform_accel);
  if (tc->encmac_accel)
    ssh_hwaccel_free(tc->encmac_accel);
  if (tc->enc_accel)
    ssh_hwaccel_free(tc->enc_accel);
  if (tc->mac_accel)
    ssh_hwaccel_free(tc->mac_accel);
  if (tc->cipher_context)
    {
      if (tc->cipher->uninit)
	(*tc->cipher->uninit)(tc->cipher_context);
      ssh_free(tc->cipher_context);
    }
  if (tc->mac_context)
    {
      if (tc->mac->hash && tc->mac->hash->uninit)
	(*tc->mac->hash->uninit)(tc->mac_context);
      else if (tc->mac->cipher && tc->mac->cipher->uninit)
	(*tc->mac->cipher->uninit)(tc->mac_context);

      ssh_free(tc->mac_context);
    }
  tc->transform_accel = transform_accel;
  tc->encmac_accel = encmac_accel;
  tc->enc_accel = enc_accel;
  tc->mac_accel = mac_accel;
  tc->cipher = cipher;
  tc->cipher_context = cipher_context;
  tc->mac = mac;
  tc->mac_context = mac_context;
#ifdef SSHDIST_IPSEC_IPCOMP
  tc->compress = compress;
#endif /* SSHDIST_IPSEC_IPCOMP */
  /* This statistic measures the total number of times a crypto context has
     been allocated (in software or using hardware acceleration). */
#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].total_transform_contexts++;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */

  return TRUE;

 error:
  /* An error occurred while allocating the new cipher/mac contexts. */
  if (transform_accel)
    ssh_hwaccel_free_combined(transform_accel);
  if (encmac_accel)
    ssh_hwaccel_free(encmac_accel);
  if (enc_accel)
    ssh_hwaccel_free(enc_accel);
  if (mac_accel)
    ssh_hwaccel_free(mac_accel);
  if (cipher_context)
    {
      if (cipher->uninit)
	(*cipher->uninit)(cipher_context);
      ssh_free(cipher_context);
    }
  if (mac_context)
    {
      if (mac->hash && mac->hash->uninit)
	(*mac->hash->uninit)(mac_context);
      else if (mac->cipher && mac->cipher->uninit)
	(*mac->cipher->uninit)(mac_context);

      ssh_free(mac_context);
    }
  return FALSE;
}

/* Allocates a transform context for the transform.  This maintains a
   cache of recently used encryption context (a simple hash table is
   used to find the appropriate context efficiently).  This also keeps
   the context on an LRU list, and if the context is not found, the
   least recently used entry is taken from the LRU list.  Entries that
   are currently being used are not on the LRU list.  Also, entries
   that are assigned transform-level hardware acceleration contexts
   are not on the LRU list (such contexts must live for the full
   lifetime of the SA).  This returns the allocated transform context,
   or NULL if all transform contexts are currently in use. */
SshFastpathTransformContext
ssh_fastpath_get_transform_context(SshFastpath fastpath,
				   SshEngineTransformRun trr,
				   SshEnginePacketContext pc,
				   Boolean for_output,
				   Boolean inner_is_ipv6,
				   Boolean outer_is_ipv6)
{
  SshFastpathTransformContext tc;
  SshUInt32 hashvalue, tc_index;
#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  unsigned int cpu;
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

#ifndef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      ssh_warning("ssh_fastpath_get_transform_context: AH not compiled in");
      return NULL;
    }
#endif /* SSH_IPSEC_AH */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Searching for a transform context"));

  /* We use the xor of the first four bytes of encryption and MAC keys as
     the hash value for transform contexts.  The hash value is never given
     out, and the hash should normally be a good distinguisher (especially
     for automatically negotiated keys).  We use both keys because some
     transforms don't have both encryption and authentication. */
  hashvalue = SSH_FASTPATH_TC_HASH(trr->mykeymat, 
				   trr->myspis[SSH_PME_SPI_ESP_IN],
				   trr->myspis[SSH_PME_SPI_AH_IN]);

#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  /* First search the hash list on the local CPU */
  ssh_kernel_critical_section_start(fastpath->tc_critical_section);

  cpu = ssh_kernel_get_cpu();
  SSH_ASSERT(cpu < fastpath->num_cpus);

  SSH_DEBUG(SSH_D_LOWOK, ("Searching for an available transform context "
			  "on the local hash list CPU=%d", cpu));

  /* Iterate over the hash list to verify whether we have a suitable context
     already available. */
  for (tc_index = fastpath->tc_hash[cpu][hashvalue];
       tc_index != SSH_IPSEC_INVALID_INDEX;
       tc_index = tc->hash_next)
    {
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
      /* Verify that the key material and SPIs really do match. */
      if (tc->destroy_pending ||
	  tc->tr_index != trr->tr_index ||
	  tc->transform != pc->transform ||
	  tc->esp_spi != trr->myspis[SSH_PME_SPI_ESP_IN] ||
          tc->ah_spi != trr->myspis[SSH_PME_SPI_AH_IN] ||
          memcmp(tc->keymat, trr->mykeymat, sizeof(tc->keymat)) != 0 ||
          tc->ipv6 != outer_is_ipv6 || tc->for_output != for_output)
	  continue;

      /* Only contexts with transform level hardware acceleration can be used 
	 by more than one concurrent thread. */
      SSH_ASSERT(tc->cpu == cpu && tc->transform_accel == NULL);
      if (tc->refcnt > 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Skipping inuse transform"));
          continue;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Found a suitable cached transform context"));

      /* Remove the context from the hash and LRU list. */
      ssh_fastpath_tc_lru_remove(fastpath, tc);
      ssh_fastpath_tc_hash_remove(fastpath, tc);
      tc->refcnt++;
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);
      goto found;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Searching the LRU list for a transform context "
			  "on the local CPU=%d", cpu));

  /* Try getting one from the LRU on the local CPU.  Note that the LRU does 
     not contain contexts that are in use or that have transform-level 
     acceleration, so if we get one from the LRU, it is always one that 
     we can use. */
  tc_index = fastpath->tc_tail[cpu];
  if (tc_index != SSH_IPSEC_INVALID_INDEX)
    {
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
      SSH_ASSERT(tc->refcnt == 0);

      /* Allocate new crypto contexts for 'tc' */
      if (!fastpath_alloc_crypto_transform_context(fastpath, tc, trr, pc, 
						 for_output,
						 inner_is_ipv6, 
						 outer_is_ipv6))
	{
	  ssh_kernel_critical_section_end(fastpath->tc_critical_section);
	  goto failed;
	}

      SSH_ASSERT(tc->cpu == cpu && tc->transform_accel == NULL);
      /* Remove the old transform context from the hash and LRU list */
      ssh_fastpath_tc_lru_remove(fastpath, tc);
      ssh_fastpath_tc_hash_remove(fastpath, tc);
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);

      /* Initialize the transform context */
      ssh_fastpath_init_transform_context(fastpath, tc, trr, pc->transform, 
					for_output, inner_is_ipv6, 
					outer_is_ipv6);
      tc->refcnt++;
      goto found;
    }

  ssh_kernel_critical_section_end(fastpath->tc_critical_section);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

  /* Now try the shared hash list, we need to take a lock */
  ssh_kernel_mutex_lock(fastpath->tc_lock);

  SSH_DEBUG(SSH_D_LOWOK, ("Searching for an available transform context "
			  "on the shared hash list"));

  /* Iterate over the hash list to verify whether we have a suitable context
     already available. */
  for (tc_index = fastpath->tc_hash[fastpath->num_cpus][hashvalue];
       tc_index != SSH_IPSEC_INVALID_INDEX;
       tc_index = tc->hash_next)
    {
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);

      SSH_DEBUG(SSH_D_MY, ("Considering tc=%p", tc));

      /* Verify that the key material and SPIs really do match.
         Skip contexts that are currently being used by another thread. */
      if (tc->destroy_pending ||
	  tc->tr_index != trr->tr_index ||
	  tc->transform != pc->transform ||
	  tc->esp_spi != trr->myspis[SSH_PME_SPI_ESP_IN] ||
          tc->ah_spi != trr->myspis[SSH_PME_SPI_AH_IN] ||
          memcmp(tc->keymat, trr->mykeymat, sizeof(tc->keymat)) != 0 ||
          tc->ipv6 != outer_is_ipv6 || tc->for_output != for_output)
	  continue;

      /* Only contexts with transform level hardware acceleration can be used 
	 by more than one concurrent thread. */
      if (tc->refcnt > 0 && tc->transform_accel == NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Skipping inuse transform"));
          continue;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Found a suitable cached transform "
				   "context"));

      SSH_ASSERT(tc->cpu == fastpath->num_cpus);

      if (tc->transform_accel == NULL)
	ssh_fastpath_tc_lru_remove(fastpath, tc);
#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
      tc->cpu = ssh_kernel_get_cpu();
      ssh_fastpath_tc_hash_remove(fastpath, tc);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

      tc->refcnt++;
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      goto found;
    }

  SSH_DEBUG(SSH_D_LOWOK, 
	    ("Searching the shared LRU list for a transform context "));

  /* Try getting one from the LRU.  Note that the LRU does not contain
     contexts that are in use or that have transform-level acceleration,
     so if we get one from the LRU, it is always one that we can use. */
  tc_index = fastpath->tc_tail[fastpath->num_cpus];
  if (tc_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of transform contexts"));
      SSH_DEBUG(SSH_D_FAIL,
                ("Check SSH_ENGINE_MAX_TRANSFORM_CONTEXTS (now %d)",
                 SSH_ENGINE_MAX_TRANSFORM_CONTEXTS));
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      goto failed;
    }

  /* Got a transform context from the LRU. */
  tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
  SSH_ASSERT(tc->refcnt == 0);

  /* Remove the old tc from the hash and LRU list. */
  ssh_fastpath_tc_lru_remove(fastpath, tc);
  ssh_fastpath_tc_hash_remove(fastpath, tc);

  /* Allocate new crypto contexts for 'tc' */
  if (!fastpath_alloc_crypto_transform_context(fastpath, tc, trr, 
					       pc, for_output,
					       inner_is_ipv6, outer_is_ipv6))
    {
      ssh_fastpath_tc_hash_insert(fastpath, tc);
      ssh_fastpath_tc_lru_insert_tail(fastpath, tc);
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      goto failed;
    }
  
  SSH_ASSERT(tc->cpu == fastpath->num_cpus);

  /* Initialize the transform context */
  ssh_fastpath_init_transform_context(fastpath, tc, trr, 
				      pc->transform, for_output,
				      inner_is_ipv6, outer_is_ipv6);
  
#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  tc->cpu = ssh_kernel_get_cpu();
#else /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
  ssh_fastpath_tc_hash_insert(fastpath, tc);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

  tc->refcnt++;
  ssh_kernel_mutex_unlock(fastpath->tc_lock);
  
 found:
#ifdef SSH_IPSEC_STATISTICS
  /* This statistic measures the number of active crypto contexts.*/
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].active_transform_contexts++;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */
#ifdef SSHDIST_IPSEC_IPCOMP
  if (tc->transform & SSH_PM_IPSEC_IPCOMP
      && !tc->transform_accel 
      && tc->compress)
    {
      if ((tc->compression_context = (*tc->compress->get_context)(fastpath,
								  for_output))
	  == NULL)
        {
          ssh_fastpath_release_transform_context(fastpath, tc);
          goto failed;
        }
    }
#endif /* SSHDIST_IPSEC_IPCOMP */

  return tc;

   failed:
  SSH_DEBUG(SSH_D_FAIL, ("Failed to get transform context"));
#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].out_of_transform_contexts++;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */
  return NULL;
}


/* Destroys the transform context immediately.  When this is called, the
   transform context must not be in the hash table or on the LRU list. */
void ssh_fastpath_destroy_tc_now(SshFastpath fastpath,
				 SshFastpathTransformContext tc)
{
  ssh_kernel_mutex_assert_is_locked(fastpath->tc_lock);
  SSH_ASSERT(tc->refcnt == 0);
  SSH_ASSERT(tc->cpu == fastpath->num_cpus);

  /* Free and clear any hardware acceleration contexts. */
  if (tc->transform_accel)
    {
      ssh_hwaccel_free_combined(tc->transform_accel);
      tc->transform_accel = NULL;
    }
  if (tc->encmac_accel)
    {
      ssh_hwaccel_free(tc->encmac_accel);
      tc->encmac_accel = NULL;
    }
  if (tc->enc_accel)
    {
      ssh_hwaccel_free(tc->enc_accel);
      tc->enc_accel = NULL;
    }
  if (tc->mac_accel)
    {
      ssh_hwaccel_free(tc->mac_accel);
      tc->mac_accel = NULL;
    }

  /* Free and clear any cipher/mac contexts. */
  if (tc->cipher_context)
    {
      if (tc->cipher->uninit)
	(*tc->cipher->uninit)(tc->cipher_context);
      ssh_free(tc->cipher_context);
      tc->cipher_context = NULL;
    }
  if (tc->mac_context)
    {
      if (tc->mac->hash && tc->mac->hash->uninit)
	(*tc->mac->hash->uninit)(tc->mac_context);
      else if (tc->mac->cipher && tc->mac->cipher->uninit)
	(*tc->mac->cipher->uninit)(tc->mac_context);
      
      ssh_free(tc->mac_context);
      tc->mac_context = NULL;
    }

  /* Randomize its location in the hash table, so that we don't get
     excessively long lists. */
  tc->transform = 0; /* Invalid transform value */
  memset(tc->keymat, 0, sizeof(tc->keymat));
  SSH_PUT_32BIT(tc->keymat, tc->self_index);

  /* Add it into the hash table. */
  ssh_fastpath_tc_hash_insert(fastpath, tc);

  /* Add it onto the LRU list (at the tail of the list, because this is
     a preferred candidate for reuse).  Note that it can no longer have
     a transform-level acceleration, so it will always go on the LRU. */
  ssh_fastpath_tc_lru_insert_tail(fastpath, tc);

  /* Deletion is now completed */
  tc->destroy_pending = 0;
}

/* Returns the transform context to the system for reuse.  The
   transform context is returned to the cache of available contexts,
   and may be reused if another packet is received for the same
   security association.  All allocated contexts must be released
   after they have been used.  This marks the context as not in use,
   and puts it at the head of the LRU list. */

void ssh_fastpath_release_transform_context(SshFastpath fastpath,
					    SshFastpathTransformContext tc)
{
  SSH_DEBUG(SSH_D_MY, ("Releasing transform context tc=%p allocated from "
		       "CPU=%d", tc, tc->cpu));
  
  /* This statistic measures the number of available crypto contexts.*/
#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].active_transform_contexts--;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSHDIST_IPSEC_IPCOMP 
  if (tc->compress && tc->compression_context)
    {
      (*tc->compress->release_context)(fastpath,
                                      tc->compression_context);
      tc->compression_context = NULL;
    }
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  ssh_kernel_critical_section_start(fastpath->tc_critical_section);

  SSH_ASSERT(tc->refcnt == 1);
  tc->refcnt--;

  SSH_DEBUG(SSH_D_MY, ("Currently executing CPU is %d",
		       ssh_kernel_get_cpu()));

  /* Put the transform back to the local CPU list if it came from the same
     CPU as it was allocated from. */
  if (tc->cpu == ssh_kernel_get_cpu())
    {
      SSH_DEBUG(SSH_D_MY, ("Returning transform context tc=%p to local CPU "
			   "list", tc));

      SSH_ASSERT(tc->transform_accel == NULL);
      ssh_fastpath_tc_lru_insert(fastpath, tc);
      ssh_fastpath_tc_hash_insert(fastpath, tc);
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);
    }
  else
    {
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);
      ssh_kernel_mutex_lock(fastpath->tc_lock);

      tc->cpu = fastpath->num_cpus;
      ssh_fastpath_tc_lru_insert(fastpath, tc);
      ssh_fastpath_tc_hash_insert(fastpath, tc);
      
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
    }
  return;
#else /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

  ssh_kernel_mutex_lock(fastpath->tc_lock);

  SSH_ASSERT(tc->cpu == fastpath->num_cpus);
  SSH_ASSERT(tc->refcnt != 0);
  if (--tc->refcnt > 0)
    {
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      return;
    }
  
  if (tc->destroy_pending)
    {
      /* Remove the transform context from the hash table. */
      ssh_fastpath_tc_hash_remove(fastpath, tc);
      
      /* The transform was in active use when this function was
         called.  Therefore it can not be on the LRU list. */
      
      /* Destroy the transform context immediately. */
      ssh_fastpath_destroy_tc_now(fastpath, tc);
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      return;
    }

  /* Put the transform back to the shared CPU list */
  if (tc->transform_accel == NULL)
    ssh_fastpath_tc_lru_insert(fastpath, tc);

  ssh_kernel_mutex_unlock(fastpath->tc_lock);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
}


/* Updates the transform context for the given SA, if any.  This
   should be called whenever the IP addresses or NAT-T remote port in a 
   security association changes. The new addresses and remote NAT-T port
   are provided by 'local_ip', 'remote_ip', and 'remote_natt_port'. 
   The remaining paraters are provided to look up the correct transform 
   context. */
void
ssh_fastpath_update_sa_tc(SshFastpath fastpath, SshUInt32 transform,
			  const unsigned char *keymat,
			  SshUInt32 ah_spi, SshUInt32 esp_spi,
			  Boolean for_output, Boolean ipv6,
			  SshIpAddr local_ip, SshIpAddr remote_ip,
			  SshUInt16 remote_port)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Update SA transform context with AH SPI=0x%08lx, "
			  "ESP SPI=0x%08lx, transform=0x%x, for_output=%d", 
			  (unsigned long) ah_spi,
			  (unsigned long) esp_spi,
			  (unsigned int) transform, for_output));
  
  SSH_DEBUG(SSH_D_LOWOK, ("Local IP=%@, Remote IP=%@, NATT remote port=%d",
			  ssh_ipaddr_render, local_ip,
			  ssh_ipaddr_render, remote_ip, remote_port));







  ssh_fastpath_destroy_sa_tc(fastpath, transform, keymat,
			     ah_spi, esp_spi, for_output, ipv6);
}  


/* Destroys the transform context for the given SA, if any.  This
   should be called whenever a security association might become
   invalid (i.e., when a transform is destroyed, when the outbound
   direction is rekeyed, when rekeyed inbound SA expires, or when old
   rekeyed inbound SA is still valid when a new inbound rekey
   occurs). */
void
ssh_fastpath_destroy_sa_tc(SshFastpath fastpath, SshUInt32 transform,
			   const unsigned char *keymat,
			   SshUInt32 ah_spi, SshUInt32 esp_spi,
			   Boolean for_output, Boolean ipv6)
{
#ifndef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  SshUInt32 hashvalue, tc_index, *tc_indexp;
  SshFastpathTransformContext tc;
  unsigned int cpu = fastpath->num_cpus;

  SSH_DEBUG(SSH_D_LOWOK, ("Destroy SA transform context with AH SPI=%x, "
			  "ESP SPI=%x, transform=%x, for_output=%d", 
			  ah_spi, esp_spi, transform, for_output));

#ifdef SSHDIST_L2TP
  /* Destroy first the IPSec SA context protecting L2TP control
     traffic.  After that we destroy the L2TP version of the
     transform. */
  if (transform & SSH_PM_IPSEC_L2TP)
    ssh_fastpath_destroy_sa_tc(fastpath, transform & ~SSH_PM_IPSEC_L2TP,
			       keymat, ah_spi, esp_spi, for_output, ipv6);
#endif /* SSHDIST_L2TP */

  ssh_kernel_mutex_lock(fastpath->tc_lock);

  /* Compute hash slot index. */
  hashvalue = SSH_FASTPATH_TC_HASH(keymat, esp_spi, ah_spi);

  /* Iterate over the hash list to verify whether we have a suitable
     context already available. */
  for (tc_indexp = &fastpath->tc_hash[cpu][hashvalue];
       *tc_indexp != SSH_IPSEC_INVALID_INDEX; )
    {
      tc_index = *tc_indexp;
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);

      /* Verify that the key material and SPIs really match and that
         the transform context is not already deleted. */
      if (memcmp(tc->keymat, keymat, sizeof(tc->keymat)) != 0 ||
          tc->esp_spi != esp_spi || tc->ah_spi != ah_spi ||
          tc->transform != transform ||
          tc->ipv6 != ipv6 || tc->for_output != for_output ||
          tc->destroy_pending)
        {
          /* Move ahead in the list. */
          tc_indexp = &tc->hash_next;
          continue;
        }

      /* Destroy the transform context if it has no references (or destroy
         it when the last reference goes away). */
      SSH_DEBUG(SSH_D_MIDOK, ("Destroying tc %d on SA deletion",
                              (int)tc_index));

      /* Mark the transform context as deleted. */
      tc->destroy_pending = 1;

      /* If it has no references, destroy it now.  Otherwise it will
         get destroyed later. */
      if (tc->refcnt == 0)
        {
          /* Remove the transform context from the hash table. */
          *tc_indexp = tc->hash_next;

          /* Remove the transform context from the LRU list (unless it
             uses transform-level acceleration, in which case it is
             not on the list at all). */          
	  if (tc->transform_accel == NULL)
            ssh_fastpath_tc_lru_remove(fastpath, tc);

          /* Destroy the transform context now. */
          ssh_fastpath_destroy_tc_now(fastpath, tc);
        }
      else
        {
          /* The transform has references.  Move ahead in the list. */
          tc_indexp = &tc->hash_next;
        }
    }
  ssh_kernel_mutex_unlock(fastpath->tc_lock);
#endif /* !SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
}

/* Handles AAD (additional authentication data) for combined
   ciphers. Can only be called for combined ciphers. */
Boolean ssh_ipsec_esp_process_aad(SshInterceptorPacket pp,
                                  const SshCipherDefStruct *cipher,
                                  void *cipher_context,
                                  size_t offset, size_t aad_len,
				  Boolean longseq_flag,
				  SshUInt32 longseq_high)
{
  unsigned char aad[24];
  SSH_ASSERT(aad_len <= 20);

  if (longseq_flag)
    {
      ssh_interceptor_packet_copyout(pp, offset, aad + 4, aad_len);
      SSH_PUT_32BIT(aad, SSH_GET_32BIT(aad + 4));
      SSH_PUT_32BIT(aad + 4, longseq_high);
      aad_len += 4;
    }
  else
    {
      ssh_interceptor_packet_copyout(pp, offset, aad, aad_len);
    }

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("AAD:"), aad, aad_len);
  cipher->reset(cipher_context);
  cipher->update(cipher_context, aad, aad_len);
  return TRUE;
}

/* Performs the blocked transform identified by `cipher' on a range of the
   packet. This does modify the buffer chain. The packet may consist of an
   arbitrary chain of blocks. This function can be called concurrently for
   different packets. This return TRUE if successfull and FALSE in case of
   error. If error occurs then the pp is already freed. */

Boolean ssh_ipsec_esp_transform_chain(SshInterceptorPacket pp,
                                      const SshCipherDefStruct *cipher,
                                      void *cipher_context,
                                      Boolean counter_mode,
                                      SshUInt32 nonce,
                                      size_t block_len,
                                      size_t iv_len,
                                      size_t offset, size_t crypt_len)
{
  unsigned char partial_block[SSH_CIPHER_MAX_BLOCK_SIZE];
  unsigned char iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  size_t partial_bytes, seglen, len;
  unsigned char *seg;
  unsigned char *prev_block_start[SSH_CIPHER_MAX_BLOCK_SIZE];
  size_t prev_block_bytes[SSH_CIPHER_MAX_BLOCK_SIZE];
  SshUInt32 num_prev, i;
  SshCryptoStatus status;

  if (counter_mode == FALSE)
    SSH_ASSERT(crypt_len % block_len == 0);

  /* If using counter mode we need to set the initial counter block here */
  if (counter_mode)
    {
      SSH_ASSERT(iv_len <= SSH_CIPHER_MAX_BLOCK_SIZE);
      SSH_ASSERT(iv_len <= crypt_len);

      memset(iv, 0, sizeof(iv));
      SSH_PUT_32BIT(iv, nonce);

      ssh_interceptor_packet_copyout(pp, offset, iv + 4, iv_len);

      offset += iv_len;
      crypt_len -= iv_len;

      /* Initialize the lowest order word of the counter to 1 */
      SSH_PUT_32BIT(iv + 4 + iv_len, 1);

      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, 
                        ("Initial counter"), iv, iv_len + 8);
    }
  else
    {
      memset(iv, 0, sizeof(iv));
    }

  SSH_DEBUG(SSH_D_LOWSTART,
            ("(de)ciphering packet offset %zd length %zd blocksize %zd",
             offset, crypt_len, block_len));

  /* Loop over all segments of the packet.  Initialize to a state where there
     is no data left over from previous segments. */
  num_prev = 0;
  partial_bytes = 0;
  ssh_interceptor_packet_reset_iteration(pp, offset, crypt_len);
  while (ssh_interceptor_packet_next_iteration(pp, &seg, &seglen))
    {
      if (seglen == 0)
        continue;

      /* If we have a partial block, complete it first. */
      if (partial_bytes > 0)
        {
          /* Add bytes to complete the partial block. */
          SSH_ASSERT(partial_bytes < block_len);
          len = block_len - partial_bytes;
          if (len > seglen)
            len = seglen;
          prev_block_start[num_prev] = seg;
          prev_block_bytes[num_prev] = len;
          num_prev++;
          SSH_ASSERT(num_prev <= SSH_CIPHER_MAX_BLOCK_SIZE);
          SSH_ASSERT(partial_bytes + len <= sizeof(partial_block));
          memcpy(partial_block + partial_bytes, seg, len);
          partial_bytes += len;
          seg += len;
          seglen -= len;

          /* If block still not complete, move to next segment. */
          if (partial_bytes != block_len)
            {
              SSH_ASSERT(partial_bytes < block_len && seglen == 0);
              continue;
            }

          /* Transform the split block in the separate buffer. */
          status = (*cipher->transform)(cipher_context, partial_block, 
					partial_block,
					partial_bytes, iv);

	  if (status != SSH_CRYPTO_OK)
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("Cipher transform failed: %d", status));
	      ssh_interceptor_packet_free(pp);
	      return FALSE;
	    }
	      
          /* Copy data back into the original buffers. */
          len = 0;
          for (i = 0; i < num_prev; i++)
            {
              memcpy(prev_block_start[i], partial_block + len,
                     prev_block_bytes[i]);
              len += prev_block_bytes[i];
            }
          SSH_ASSERT(len == partial_bytes && partial_bytes == block_len);
          num_prev = 0;
          partial_bytes = 0;
        }

      /* Process full blocks. */
      len = seglen & ~(block_len - 1);

      status = (*cipher->transform)(cipher_context, seg, seg, len, iv);
      if (status != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Cipher transform failed: %d", status));
	  ssh_interceptor_packet_free(pp);
	  return FALSE;
	}

      seg += len;
      seglen -= len;
      if (seglen == 0)
        continue;

      /* Process any remaining data. */
      if (seglen > 0)
        {
          SSH_ASSERT(seglen < block_len && seglen <= sizeof(partial_block));
          memcpy(partial_block, seg, seglen);
          partial_bytes = seglen;
          prev_block_start[0] = seg;
          prev_block_bytes[0] = seglen;
          num_prev = 1;
        }
    }
  if (seg != NULL)
    {
      /* Error occurred while iterating, pp is already freed. */
      return FALSE;
    }

  if (counter_mode && partial_bytes)
    {
      status = (*cipher->transform)(cipher_context, partial_block, 
				    partial_block,
				    partial_bytes, iv);

      if (status != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Cipher transform failed: %d", status));
	  ssh_interceptor_packet_free(pp);
	  return FALSE;
	}

      /* Copy data back into the original buffers. */
      len = 0;
      for (i = 0; i < num_prev; i++)
	{
	  memcpy(prev_block_start[i], partial_block + len,
		 prev_block_bytes[i]);
	  len += prev_block_bytes[i];
	}
    }
  return TRUE;
}

/* Computes ESP MAC over the specified byte range of the packet.  This stores
   the MAC in `icv'.  This returns TRUE on success, and FALSE on error, in
   which case `pp' has been freed. */

Boolean ssh_fastpath_mac_add_range(SshInterceptorPacket pp,
                                 size_t ofs, size_t len,
                                 void (*mac_update)(void *context, 
                                                    const unsigned char *buf, 
                                                    size_t len),
                                 void *mac_context)
{
  const unsigned char *seg;
  size_t seglen;

  /* Iterate all segments of the packet. */
  ssh_interceptor_packet_reset_iteration(pp, ofs, len);
  while (ssh_interceptor_packet_next_iteration_read(pp, &seg, &seglen))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("adding %zd bytes to MAC:", seglen),
                        seg, seglen);
      (*mac_update)(mac_context, seg, seglen);
    }
  if (seg != NULL)
    {
      /* Mac failed */
      SSH_DEBUG(SSH_D_ERROR, ("Iteration failed calculating ESP MAC"));
      return FALSE;
    }
  return TRUE;
}

#ifdef SSH_IPSEC_AH

/* Updates the mac by adding the IPv4 header, including options.  This
   will consider all mutable options as zero, and will replace mutable
   but predictable options by their final values for the purposes of
   updating the mac. */

void ssh_fastpath_mac_add_ah_header4(SshInterceptorPacket pp, size_t hlen,
                                   void (*mac_update)(void *context, 
                                                      const unsigned char *buf,
                                                      size_t len),
                                   void *mac_context, SshInt16 len_delta,
                                   SshUInt8 forced_ipproto)
{
  unsigned char copy[SSH_IPH4_MAX_HEADER_LEN];
  SshUInt16 i, opttype, optlen, offset, len;
  SshIpAddrStruct ipaddr;

  /* Copy the header and clear mutable fields. */
  SSH_ASSERT(hlen <= SSH_IPH4_MAX_HEADER_LEN);
  ssh_interceptor_packet_copyout(pp, 0, copy, hlen);
  SSH_ASSERT(hlen == 4 * SSH_IPH4_HLEN(copy));
  SSH_IPH4_SET_TOS(copy, 0);
  SSH_IPH4_SET_FRAGOFF(copy, 0); /* Includes flags */
  SSH_IPH4_SET_TTL(copy, 0);
  SSH_IPH4_SET_CHECKSUM(copy, 0);
  len = SSH_IPH4_LEN(copy);
  SSH_IPH4_SET_LEN(copy, len + len_delta);
  SSH_IPH4_SET_PROTO(copy, forced_ipproto);

  /* Process options, if any.  This may update DST in the IP header.
     Mutable options are zeroed. */
  for (i = SSH_IPH4_HDRLEN; i < hlen; i += optlen)
    {
      opttype = copy[i];
      if (opttype == SSH_IPOPT_EOL ||
          opttype == SSH_IPOPT_NOP)
        optlen = 1;
      else
        optlen = copy[i + 1];
      if (optlen > hlen - i || optlen < 1)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("bad ip option length %d encountered opt %d offset %d",
                     optlen, opttype, i));
          break;
        }
      switch (opttype)
        {
        case SSH_IPOPT_EOL: /* End of option list */
          goto end_of_options;

        case SSH_IPOPT_NOP: /* No operation */
        case SSH_IPOPT_BSO: /* Basic security option */
        case SSH_IPOPT_ESO: /* Extended security option */
        case SSH_IPOPT_CIPSO: /* Commercial ip security option? */
        case SSH_IPOPT_ROUTERALERT: /* Router alert */
        case SSH_IPOPT_SNDMULTIDEST: /* Sender directed
                                        multi-destination delivery */
        case SSH_IPOPT_SATID: /* SATNET stream identifier */
          /* These options are immutable in transit, and are kept for
             the purposes of ICV computation. */
          break;

        case SSH_IPOPT_LSRR: /* Loose source route */
        case SSH_IPOPT_SSRR: /* Strict source route */
          /* Need to take the last address and store it in dst.  The option
             itself is zeroed. */
          offset = copy[i + 2];
          if (offset < 4 || optlen < 3)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("source route ptr too small: %d at %d of %d",
                         copy[i + 2], i + 2, optlen));
              break;
            }
          offset--;
          if (offset + 4 <= optlen)
            {
              /* At least one address left (i.e., at least 4 bytes left. */
              offset += ((optlen - offset - 4) / 4) * 4;
              SSH_IP4_DECODE(&ipaddr, copy + i + offset);
              SSH_IPH4_SET_DST(&ipaddr, copy);
              SSH_DEBUG(SSH_D_HIGHOK, ("replaced dst from source route"));
            }
          /* Zero the source route option.  Note that in IPv4, the entire
             option is zeroed. */
          SSH_DEBUG(SSH_D_HIGHOK, ("zeroing route option (%d)", opttype));
          memset(copy + i, 0, optlen);
          break;

        case SSH_IPOPT_RR:   /* record route */
        case SSH_IPOPT_TS:   /* timestamp */
          memset(copy + i, 0, optlen);
          break;

        default:
          /* All other options are assumed mutable and are zeroed. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("unknown option %d len %d zeroed", opttype, optlen));
          memset(copy + i, 0, optlen);
          break;
        }
    }
 end_of_options:

  /* Update the MAC. */
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("header computed in icv as follows:"), copy, hlen);

  (*mac_update)(mac_context, copy, hlen);
}


#if defined (WITH_IPV6)

/* Same for IPv6.  `pp' and `hlen' are computed by the routine itself
   from `pc'. */

void ssh_fastpath_mac_add_ah_header6(SshEnginePacketContext pc,
                                   void (*mac_update)(void *context, 
                                                      const unsigned char *buf,
                                                      size_t len),
                                   void *mac_context, SshInt16 len_delta,
                                   SshUInt8 forced_ipproto)
{
  unsigned char buf[256+2];     /* This is long enough to hold the
                                   maximum length option + its type +
                                   its length fields. */
  SshInterceptorPacket pp = pc->pp;
  size_t hlen = pc->hdrlen;
  SshUInt16 offset, next, header_length, header_offset, option_length;
  SshUInt32 n_addrs, n_segs, i;

  ssh_interceptor_packet_copyout(pp, 0, buf, SSH_IPH6_HDRLEN);
  /* Clear the mutable fields. */
  SSH_IPH6_SET_CLASS(buf, 0);
  SSH_IPH6_SET_FLOW(buf, 0);
  SSH_IPH6_SET_HL(buf, 0);
  /* Copy the final destination into the header.  Note that because of
     routing headers it may be different from the one in the first
     IPv6 header. */
  SSH_IPH6_SET_DST(&pc->dst, buf);

  /* Update the MAC. */
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("Header computed in ICV as follows:"),
                    buf, SSH_IPH6_HDRLEN);

  (*mac_update)(mac_context, buf, SSH_IPH6_HDRLEN);

  /* Traverse the extension headers. */
  next = SSH_IPH6_NH(buf);
  offset = SSH_IPH6_HDRLEN;
  while (offset < hlen)
    switch (next)
      {
      case 0:                   /* hop-by-hop header */
      case SSH_IPPROTO_IPV6OPTS:
        /* The length has already been checked in
           `engine_fastpath.c'. */
        ssh_interceptor_packet_copyout(pp, offset, buf,
                                       SSH_IP6_EXT_COMMON_HDRLEN);
        next = SSH_IP6_EXT_COMMON_NH(buf);

        header_length = SSH_IP6_EXT_COMMON_LENB(buf);
        SSH_ASSERT(offset + header_length <= hlen);

        /* Update the common part of this extension header to ICV. */
        SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                          ("Common part of the ext hdr to ICV as follows:"),
                          buf, SSH_IP6_EXT_COMMON_HDRLEN);

        (*mac_update)(mac_context, buf, SSH_IP6_EXT_COMMON_HDRLEN);

        /* Scan through options. */
        header_offset = 2;
        while (header_offset < header_length)
          {
            SshUInt8 type;
            int n = (header_offset + 2 <= header_length) ? 2 : 1;

            /* Copy out the option header. */
            ssh_interceptor_packet_copyout(pp, offset + header_offset, buf, n);
            type = SSH_GET_8BIT(buf);
            if (type == 0)
              {
                /* A Pad1 option. */
                SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                  ("Adding option Pad1:"),
                                  buf, 1);

		(*mac_update)(mac_context, buf, 1);

                header_offset++;
                continue;
              }

            if (n == 1)
              {
                /* The extension header is too short to contain this
                   option. */
              too_short_option:
                SSH_DEBUG(SSH_D_ERROR,
                          ("The options ext hdr is too short to contain "
                           "all of its options."));
                ssh_engine_send_icmp_error(
                                pc->engine, pc,
                                SSH_ICMP6_TYPE_PARAMPROB,
                                SSH_ICMP6_CODE_PARAMPROB_HEADER,
                                offset + SSH_IP6_EXT_COMMON_OFS_LEN);
                return;
              }

            /* Fetch the option. */
            option_length = 2 + SSH_GET_8BIT(buf + 1);
            if (header_offset + option_length > header_length)
              goto too_short_option;
            ssh_interceptor_packet_copyout(pp, offset + header_offset,
                                           buf, option_length);

            /* Can the option data change en-route? */
            if (type & 0x20)
              {
                /* Yes it can. */
                SSH_DEBUG(SSH_D_HIGHOK, ("Zeroing option %d", type));
                memset(buf + 2, 0, option_length - 2);
              }

            /* Update MAC. */
            SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                              ("Adding option %d:", type),
                              buf, option_length);

	    (*mac_update)(mac_context, buf, option_length);

            /* Move forward to next option. */
            header_offset += option_length;
          }








        SSH_ASSERT(header_offset == header_length);
        offset += header_length;
        break;

      case SSH_IPPROTO_IPV6ROUTE:
        /* The length and validity of the routing header has been
           checked in `fastpath.c' */
        ssh_interceptor_packet_copyout(pp, offset, buf,
                                       SSH_IP6_EXT_ROUTING_HDRLEN);

        next = SSH_IP6_EXT_ROUTING_NH(buf);
        header_length = SSH_IP6_EXT_ROUTING_LENB(buf);
        i = SSH_IP6_EXT_ROUTING_LEN(buf);
        n_addrs = i >> 1;
        n_segs = SSH_IP6_EXT_ROUTING_SEGMENTS(buf);

        /* Should have already been checked in `fastpath.c'. */
        SSH_ASSERT(SSH_IP6_EXT_ROUTING_TYPE(buf) == 0);
        SSH_ASSERT((i & 0x1) == 0);
        SSH_ASSERT(n_segs <= n_addrs);
        SSH_ASSERT(offset + header_length <= hlen);

        /* Count the MAC of the beginning of the header.  At the final
           destination, the Segments Left is 0. */
        SSH_IP6_EXT_ROUTING_SET_SEGMENTS(buf, 0);
        /* Copy the "Reserved" field. */
        ssh_interceptor_packet_copyout(pp, offset + 4, buf + 4, 4);
        SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                          ("Adding beginning of the routing header:"),
                          buf, 8);
	(*mac_update)(mac_context, buf, 8);

        /* Count the MAC values of the addresses. */
        for (i = 0; i < n_addrs - n_segs; i++)
          {
            SSH_ASSERT(8 + i * 16 + 16 <= header_length);
            ssh_interceptor_packet_copyout(pp, offset + 8 + i * 16,
                                           buf, 16);
            SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                              ("Adding address from the routing header:"),
                              buf, 16);
	    (*mac_update)(mac_context, buf, 16);
          }
        if (n_segs > 0)
          {
            /* The i:th address is the destination address at the IP
               header. */
            ssh_interceptor_packet_copyout(pp, SSH_IPH6_OFS_DST,
                                           buf, 16);
            SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                              ("Adding address from the routing header:"),
                              buf, 16);
	    (*mac_update)(mac_context, buf, 16);

            for (; i < n_addrs - 1; i++)
              {
                SSH_ASSERT(8 + i * 16 + 16 <= header_length);
                ssh_interceptor_packet_copyout(pp, offset + 8 + i * 16,
                                               buf, 16);
                SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                  ("Adding address from the routing header:"),
                                  buf, 16);
		(*mac_update)(mac_context, buf, 16);
              }
          }
        /* Move to the next extension header. */
        offset += header_length;
        break;

      default:
        /* This shouldn't happen. */
        SSH_NOTREACHED;
        break;
      }
  SSH_ASSERT(offset == hlen);
}

#endif /* (WITH_IPV6) */
#endif /* SSH_IPSEC_AH */
#endif /* SSHDIST_IPSEC_TRANSFORM */
