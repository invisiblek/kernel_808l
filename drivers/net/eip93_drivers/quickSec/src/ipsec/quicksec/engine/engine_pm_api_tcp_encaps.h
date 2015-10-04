/*
 * engine_pm_api_tcp_encaps.h
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * IPSec over TCP encapsulation. PM to engine message handling.
 */

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_pm_api_marshal.h"

#ifndef ENGINE_PM_API_TCP_ENCAPS_H
#define ENGINE_PM_API_TCP_ENCAPS_H 1

#ifndef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_ADD_CONFIG);
SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_CLEAR_CONFIG);
SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_CREATE_IKE_MAPPING);
SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_GET_IKE_MAPPING);
SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_UPDATE_IKE_MAPPING);

#endif /* !SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

#endif /* ENGINE_PM_API_TCP_ENCAPS_H */
