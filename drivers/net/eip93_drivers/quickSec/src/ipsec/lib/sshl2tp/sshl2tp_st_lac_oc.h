/*
 *
 * sshl2tp_st_lac_oc.h
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * LAC outgoing call (responder).
 *
 */

#ifndef SSHL2TP_ST_LAC_OC_H
#define SSHL2TP_ST_LAC_OC_H

/* Prototypes for state functions. */

SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_idle);
SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_reject_new);
SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_accept_new);
SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_wait_cs_answer);

#endif /* not SSHL2TP_ST_LAC_OC_H */
