/*
  ssheap_otp.c

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
  All Rights Reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshcrypt.h"

#include "ssheap.h"
#include "ssheapi.h"


#include "ssheap_config.h"

#define SSH_DEBUG_MODULE "SshEapOtp"

void*
ssh_eap_otp_create(SshEapProtocol protocol, SshEap eap, SshUInt8 type)
{
  return NULL;
}

void
ssh_eap_otp_destroy(SshEapProtocol protocol, SshUInt8 type, void *state)
{


}

SshEapOpStatus
ssh_eap_otp_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshBuffer buf)
{
  return SSH_EAP_OPSTATUS_SUCCESS;
}
