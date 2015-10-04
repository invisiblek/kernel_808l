/*
  tls_kt_RServerHelloDone.c

  Copyright:
          Copyright 2002-2007, SafeNet Inc. All rights reserved.
  All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_read_server_hellodone(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len)
{
  if (data_len != 0)
    FAILMF;

  s->kex.state = SSH_TLS_KEX_SEND_C_CERT;

  return SSH_TLS_TRANS_OK;
}
