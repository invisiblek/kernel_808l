/*
 *
 * sshl2tp_st_lns_ic.h
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * LNS incoming call (responder).
 *
 */

#ifndef SSHL2TP_ST_LNS_IC_H
#define SSHL2TP_ST_LNS_IC_H

/* Prototypes for state functions. */

SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_idle);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_reject_new);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_accept_new);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_wait_connect);

#endif /* not SSHL2TP_ST_LNS_IC_H */
