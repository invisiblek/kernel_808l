/*
 * Author: Tuomas A. Sir�n <tuomas.siren@ssh.com>
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */

#ifndef SSHPPP_FCS_H
#define SSHPPP_FCS_H

#define SSH_PPP_FCS_16BIT_INITIAL_FCS   0xffff
#define SSH_PPP_FCS_16BIT_SSH_PPP_OK_FCS 0xf0b8

/* Calculate 16 bit FCS */
SshUInt16
ssh_ppp_fcs_calculate_16bit_fcs
(
        SshUInt16               initial_fcs,
        unsigned char           *pdata,
        size_t                  size
);

#endif /* SSHPPP_FCS_H */
