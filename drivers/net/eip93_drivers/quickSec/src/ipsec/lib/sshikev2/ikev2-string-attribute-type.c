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
 *        Creation          : 21:58 Nov 11 2004 kivinen
 *        Last Modification : 17:21 Nov 24 2004 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.26
 *        
 *
 *        Description       : IKEv2 conf attr. type table and print function
 *
 *
 *        $Log: ikev2-string-attribute-type.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:21  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringAttributeType"

/* Conf attribute type to string mapping.  */
const SshKeywordStruct ssh_ikev2_attr_type_to_string_table[] = {
  { "IPv4 address", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS },
  { "IPv4 netmask", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK },
  { "IPv4 dns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS },
  { "IPv4 nbns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NBNS },
  { "address expiry", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_ADDRESS_EXPIRY },
  { "IPv4 dhcp", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DHCP },
  { "application version", SSH_IKEV2_CFG_ATTRIBUTE_APPLICATION_VERSION },
  { "IPv6 address", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS },
  { "IPv6 dns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS },
  { "IPv6 nbns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_NBNS },
  { "IPv6 dhcp", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DHCP },
  { "IPv4 subnet", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET },
  { "supported attributes", SSH_IKEV2_CFG_ATTRIBUTE_SUPPORTED_ATTRIBUTES },
  { "IPv6 subnet", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET },
  { NULL, 0 }
};

const char *ssh_ikev2_attr_to_string(SshIkev2ConfAttributeType attr_type)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_attr_type_to_string_table,
			       attr_type);
  if (name == NULL)
    return "unknown";
  return name;
}
