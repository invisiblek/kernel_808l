/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 14:05 Nov  4 2004 kivinen
 *        Last Modification : 17:43 Oct 25 2006 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.30
 *        
 *
 *        Description       : IKEv2 IKE SPI render function
 *
 *
 *        $Log: ikev2-render-ike-spi.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:18  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2RenderIkeSPI"

int ssh_ikev2_ike_spi_render(unsigned char *buf, int buf_size,
			     int precision, void *datum)
{
  SshIkev2Sa ike_sa = datum;
  unsigned char *ike_spi, *initiator;
  int len;

  if (ike_sa == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      ike_spi = ike_sa->ike_spi_i;
      initiator = ssh_ustr("I");
    }
  else
    {
      ike_spi = ike_sa->ike_spi_r;
      initiator = ssh_ustr("R");
    }
  len = ssh_snprintf(buf, buf_size + 1, 
		     "%s%02x%02x%02x%02x %02x%02x%02x%02x",
		     initiator, ike_spi[0], ike_spi[1], ike_spi[2], ike_spi[3],
		     ike_spi[4], ike_spi[5], ike_spi[6], ike_spi[7]);

  if (len >= buf_size)
    return buf_size + 1;
  return len;
}
