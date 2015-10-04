/*
  File: dump-other.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                  All rights reserved.

  Description:
        Functions to output structured object other than certificates,
        plain public and private keys, or certificate lists (on
        certtools).
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshmp.h"
#include "x509.h"
#include "x509spkac.h"
#ifdef SSHDIST_CERT_CMP
#include "x509cmp.h"
#endif /* SSHDIST_CERT_CMP */
#ifdef SSHDIST_SCEP_CLIENT
#include "x509scep.h"
#endif /* SSHDIST_SCEP_CLIENT */
#include "oid.h"
#include "iprintf.h"

#define SSH_DEBUG_MODULE "SshDumpCRL"




























#ifdef SSHDIST_CERT_CMP
Boolean cu_dump_cmp(SshCmpMessage m, unsigned char *der, size_t der_len)
{
  ssh_warning("dump_cmp not implemented");
  return FALSE;
}
#endif /* SSHDIST_CERT_CMP */

#ifdef SSHDIST_SCEP_CLIENT
Boolean cu_dump_scep(void *m, unsigned char *der, size_t der_len)
{
  ssh_warning("dump_scep not implemented");
  return FALSE;
}
#endif /* SSHDIST_SCEP_CLIENT */
#endif /* SSHDIST_CERT */
