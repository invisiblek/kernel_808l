/*

  macs.c

  Copyright:
        Copyright (c) 2002, 2003 SFNT Finland Oy.
	All rights reserved.

  Mac functions used by SSH Crypto Library.

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "sshmac_i.h"
#ifdef SSHDIST_CRYPT_MD5
#include "md5.h"
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
#include "sha.h"
#endif /* SSHDIST_CRYPT_SHA */
#include "macs.h"

typedef struct
{
  const SshHashDefStruct *hash_def;
  void *hash_context;
  unsigned char *key;
  size_t keylen;
} SshKdkMacCtx;


size_t
ssh_kdk_mac_ctxsize(const SshHashDefStruct *hash_def)
{
  return
    sizeof(SshKdkMacCtx) +
    (*hash_def->ctxsize)();
}

SshCryptoStatus
ssh_kdk_mac_init(void *context, const unsigned char *key, size_t keylen,
                 const SshHashDefStruct *hash_def)
{
  SshKdkMacCtx *created = context;

  created->hash_context = (unsigned char *)created + sizeof(SshKdkMacCtx);
  created->key = (unsigned char *)created->hash_context +
    (*hash_def->ctxsize)();
  created->keylen = keylen;

  /* Copy key. */
  memcpy(created->key, key, keylen);

  if (hash_def->init &&
      (*hash_def->init)(created->hash_context) != SSH_CRYPTO_OK)
    return SSH_CRYPTO_NO_MEMORY;

  /* Remember the hash function. */
  created->hash_def = (SshHashDefStruct *) hash_def;
  return SSH_CRYPTO_OK;
}

void ssh_kdk_mac_uninit(void *context)
{
  SshKdkMacCtx *ctx = context;

  if (ctx->hash_def->uninit)
    (*ctx->hash_def->uninit)(ctx->hash_context);
}

void ssh_kdk_mac_start(void *context)
{
  SshKdkMacCtx *ctx = context;
  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->key, ctx->keylen);
}

void ssh_kdk_mac_update(void *context, const unsigned char *buf,
                        size_t len)
{
  SshKdkMacCtx *ctx = context;
  (*ctx->hash_def->update)(ctx->hash_context, buf, len);
}

SshCryptoStatus
ssh_kdk_mac_final(void *context, unsigned char *digest)
{
  SshKdkMacCtx *ctx = context;
  (*ctx->hash_def->update)(ctx->hash_context, ctx->key, ctx->keylen);
  return (*ctx->hash_def->final)(ctx->hash_context, digest);
}

SshCryptoStatus
ssh_kdk_mac_of_buffer(void *context, const unsigned char *buf,
                           size_t len, unsigned char *digest)
{
  ssh_kdk_mac_start(context);
  ssh_kdk_mac_update(context, buf, len);
  return ssh_kdk_mac_final(context, digest);
}

/* macs.c */
