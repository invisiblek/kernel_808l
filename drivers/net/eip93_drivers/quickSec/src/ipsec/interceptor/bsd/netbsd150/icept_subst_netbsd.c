/*
  File: icept_subst_netbsd.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku Rossi <mtr@ssh.fi>

  Description:
        Replacement functions for certain NetBSD kernel functions.
        These replacements attach the packet interceptor into the
        kernel.

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
        All rights reserved

  This work has been derived from the NetBSD kernel sources. The
  original copyright information is below. */

/*      $NetBSD: ip_input.c,v 1.82.2.2 1999/05/03 22:22:42 perry Exp $  */

/*-
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Public Access Networks Corporation ("Panix").  It was developed under
 * contract to Panix by Eric Haszlakiewicz and Thor Lancelot Simon.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the NetBSD
 *      Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip_input.c  8.2 (Berkeley) 1/4/94
 */

/*      $NetBSD: ip_output.c,v 1.58 1999/03/27 01:24:50 aidan Exp $     */

/*
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip_output.c 8.3 (Berkeley) 1/21/94
 */

#include "sshincludes.h"
#include "ipsec_params.h"
#include "interceptor.h"
#include "icept_internal.h"
#include "icept_attach.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/pool.h>

#include <vm/vm.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
/* just for gif_ttl */
#if 0
#include <netinet/in_gif.h>
#include "gif.h"
#endif

#ifdef MROUTING
#include <netinet/ip_mroute.h>
#endif

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#include <netkey/key_debug.h>
#endif

#ifndef IPFORWARDING
#ifdef GATEWAY
#define IPFORWARDING    1       /* forward IP packets not for us */
#else /* GATEWAY */
#define IPFORWARDING    0       /* don't forward IP packets not for us */
#endif /* GATEWAY */
#endif /* IPFORWARDING */
#ifndef IPSENDREDIRECTS
#define IPSENDREDIRECTS 1
#endif
#ifndef IPFORWSRCRT
#define IPFORWSRCRT     1       /* forward source-routed packets */
#endif
#ifndef IPALLOWSRCRT
#define IPALLOWSRCRT    1       /* allow source-routed packets */
#endif
#ifndef IPMTUDISC
#define IPMTUDISC       0
#endif
#ifndef IPMTUDISCTIMEOUT
#define IPMTUDISCTIMEOUT (10 * 60)      /* as per RFC 1191 */
#endif

/*
 * Note: DIRECTED_BROADCAST is handled this way so that previous
 * configuration using this option will Just Work.
 */
#ifndef IPDIRECTEDBCAST
#ifdef DIRECTED_BROADCAST
#define IPDIRECTEDBCAST 1
#else
#define IPDIRECTEDBCAST 0
#endif /* DIRECTED_BROADCAST */
#endif /* IPDIRECTEDBCAST */
int     ipforwarding = IPFORWARDING;
int     ipsendredirects = IPSENDREDIRECTS;
int     ip_defttl = IPDEFTTL;
int     ip_forwsrcrt = IPFORWSRCRT;
int     ip_directedbcast = IPDIRECTEDBCAST;
int     ip_allowsrcrt = IPALLOWSRCRT;
int     ip_mtudisc = IPMTUDISC;
u_int   ip_mtudisc_timeout = IPMTUDISCTIMEOUT;
#ifdef DIAGNOSTIC
int     ipprintfs = 0;
#endif

struct rttimer_queue *ip_mtudisc_timeout_q = NULL;

extern  struct domain inetdomain;
extern  struct protosw inetsw[];
u_char  ip_protox[IPPROTO_MAX];
int     ipqmaxlen = IFQ_MAXLEN;
struct  in_ifaddrhead in_ifaddr;
struct  in_ifaddrhashhead *in_ifaddrhashtbl;
struct  ifqueue ipintrq;
struct  ipstat  ipstat;
u_int16_t       ip_id;
int     ip_defttl;

struct ipqhead ipq;
int     ipq_locked;

static __inline int ipq_lock_try __P((void));
static __inline void ipq_unlock __P((void));

static __inline int
ipq_lock_try()
{
        int s;

        s = splimp();
        if (ipq_locked) {
                splx(s);
                return (0);
        }
        ipq_locked = 1;
        splx(s);
        return (1);
}

static __inline void
ipq_unlock()
{
        int s;

        s = splimp();
        ipq_locked = 0;
        splx(s);
}

#ifdef DIAGNOSTIC
#define IPQ_LOCK()                                                      \
do {                                                                    \
        if (ipq_lock_try() == 0) {                                      \
                printf("%s:%d: ipq already locked\n", __FILE__, __LINE__); \
                panic("ipq_lock");                                      \
        }                                                               \
} while (0)
#define IPQ_LOCK_CHECK()                                                \
do {                                                                    \
        if (ipq_locked == 0) {                                          \
                printf("%s:%d: ipq lock not held\n", __FILE__, __LINE__); \
                panic("ipq lock check");                                \
        }                                                               \
} while (0)
#else
#define IPQ_LOCK()              (void) ipq_lock_try()
#define IPQ_LOCK_CHECK()        /* nothing */
#endif

#define IPQ_UNLOCK()            ipq_unlock()

struct pool ipqent_pool;

/*********************************************************************
 * ipintr replacement.
 *********************************************************************/


/* Based on ipintr in ip_input.c,v 1.102 1998/10/16 03:55:01 peter Exp
 *
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void ssh_interceptor_ipintr(void)
{
        int s;
        struct mbuf *m;

        while (1) {
                s = splimp();
                IF_DEQUEUE(&ipintrq, m);
                splx(s);
                if (m == 0)
                        return;

                /* Pass the packet to the interceptor.  This call will perform
                   m_freem(m).  We must be in the correct spl level when ipintr
                   was called so no need to do any spls here. */
                ssh_interceptor_receive(SSH_PROTOCOL_IP4, 0,
                                        m->m_pkthdr.rcvif,
                                        NULL, 0, m);
        }
}

/* Processes an ethernet packet coming from the interceptor and going
   up to the protocol.  This will call m_freem(m).  */

void ssh_interceptor_ip4_mbuf_send_to_protocol(ifp, mediahdr, mediahdr_len, m)
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
#ifdef SSH_INTERCEPTOR_DEBUG
  printf("ssh_interceptor_ip4_mbuf_send_to_protocol\n");
#endif

  /* Pass the packet to the normal ip_input function. */
  ip_input(m);
}


/*********************************************************************
 * ip_output replacement.
 *********************************************************************/

static struct mbuf *ip_insertoptions __P((struct mbuf *, struct mbuf *, int *));
static void ip_mloopback
        __P((struct ifnet *, struct mbuf *, struct sockaddr_in *));


/*
 * IP output.  The packet in mbuf chain m contains a skeletal IP
 * header (with len, off, ttl, proto, tos, src, dst).
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 */
int ssh_interceptor_ip_output(struct mbuf *m0, ...);

int
#if __STDC__
ssh_interceptor_ip_output(struct mbuf *m0, ...)
#else
ssh_interceptor_ip_output(m0, va_alist)
        struct mbuf *m0;
        va_dcl
#endif
{
        struct ifnet *ifp;
        struct mbuf *m = m0;
        int hlen = sizeof (struct ip);
        struct ip *ip;
        int len, error = 0, s;
        struct route iproute;
        struct sockaddr_in *dst;
#if IFA_STATS
        struct sockaddr_in src;
#endif
        struct in_ifaddr *ia;
        struct mbuf *opt;
        struct route *ro;
        int flags;
        int *mtu_p;
        int mtu;
        struct ip_moptions *imo;
        va_list ap;
#ifdef PFIL_HOOKS
        struct packet_filter_hook *pfh;
        struct mbuf *m1;
        int rv;
#endif /* PFIL_HOOKS */
        unsigned int icept_flags;

#ifdef SSH_INTERCEPTOR_DEBUG
        printf("ssh_interceptor_ip_output\n");
#endif

        va_start(ap, m0);
        opt = va_arg(ap, struct mbuf *);
        ro = va_arg(ap, struct route *);
        flags = va_arg(ap, int);
        imo = va_arg(ap, struct ip_moptions *);
        if (flags & IP_RETURNMTU)
                mtu_p = va_arg(ap, int *);
        else
                mtu_p = NULL;
        va_end(ap);

#ifdef  DIAGNOSTIC
        if ((m->m_flags & M_PKTHDR) == 0)
                panic("ip_output no HDR");
#endif
        if (opt) {
                m = ip_insertoptions(m, opt, &len);
                hlen = len;
        }
        ip = mtod(m, struct ip *);
        /*
         * Fill in IP header.
         */
        if ((flags & (IP_FORWARDING|IP_RAWOUTPUT)) == 0) {
                ip->ip_v = IPVERSION;
                ip->ip_off &= IP_DF;
                ip->ip_id = htons(ip_id++);
                ip->ip_hl = hlen >> 2;
                ipstat.ips_localout++;
        } else {
                hlen = ip->ip_hl << 2;
        }
        /*
         * Route packet.
         */
        if (ro == 0) {
                ro = &iproute;
                bzero((caddr_t)ro, sizeof (*ro));
        }
        dst = satosin(&ro->ro_dst);
        /*
         * If there is a cached route,
         * check that it is to the same destination
         * and is still up.  If not, free it and try again.
         */
        if (ro->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
            !in_hosteq(dst->sin_addr, ip->ip_dst))) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = (struct rtentry *)0;
        }
        if (ro->ro_rt == 0) {
                dst->sin_family = AF_INET;
                dst->sin_len = sizeof(*dst);
                dst->sin_addr = ip->ip_dst;
        }
        /*
         * If routing to interface only,
         * short circuit routing lookup.
         */
        if (flags & IP_ROUTETOIF) {
                if ((ia = ifatoia(ifa_ifwithladdr(sintosa(dst)))) == 0) {
                        ipstat.ips_noroute++;
                        error = ENETUNREACH;
                        goto bad;
                }
                ifp = ia->ia_ifp;
                mtu = ifp->if_mtu;
                ip->ip_ttl = 1;
        } else {
                if (ro->ro_rt == 0)
                        rtalloc(ro);
                if (ro->ro_rt == 0) {
                        ipstat.ips_noroute++;
                        error = EHOSTUNREACH;
                        goto bad;
                }
                ia = ifatoia(ro->ro_rt->rt_ifa);
                ifp = ro->ro_rt->rt_ifp;
                if ((mtu = ro->ro_rt->rt_rmx.rmx_mtu) == 0)
                        mtu = ifp->if_mtu;
                ro->ro_rt->rt_use++;
                if (ro->ro_rt->rt_flags & RTF_GATEWAY)
                        dst = satosin(ro->ro_rt->rt_gateway);
        }
        if (IN_MULTICAST(ip->ip_dst.s_addr) ||
            (ip->ip_dst.s_addr == INADDR_BROADCAST)) {
                struct in_multi *inm;

                m->m_flags |= (ip->ip_dst.s_addr == INADDR_BROADCAST) ?
                        M_BCAST : M_MCAST;
                /*
                 * IP destination address is multicast.  Make sure "dst"
                 * still points to the address in "ro".  (It may have been
                 * changed to point to a gateway address, above.)
                 */
                dst = satosin(&ro->ro_dst);
                /*
                 * See if the caller provided any multicast options
                 */
                if (imo != NULL) {
                        ip->ip_ttl = imo->imo_multicast_ttl;
                        if (imo->imo_multicast_ifp != NULL) {
                                ifp = imo->imo_multicast_ifp;
                                mtu = ifp->if_mtu;
                        }
                } else
                        ip->ip_ttl = IP_DEFAULT_MULTICAST_TTL;
                /*
                 * Confirm that the outgoing interface supports multicast.
                 */
                if (((m->m_flags & M_MCAST) &&
                     (ifp->if_flags & IFF_MULTICAST) == 0) ||
                    ((m->m_flags & M_BCAST) &&
                     (ifp->if_flags & IFF_BROADCAST) == 0))  {
                        ipstat.ips_noroute++;
                        error = ENETUNREACH;
                        goto bad;
                }
                /*
                 * If source address not specified yet, use an address
                 * of outgoing interface.
                 */
                if (in_nullhost(ip->ip_src)) {
                        struct in_ifaddr *ia;

                        IFP_TO_IA(ifp, ia);
                        ip->ip_src = ia->ia_addr.sin_addr;
                }

                IN_LOOKUP_MULTI(ip->ip_dst, ifp, inm);
                if (inm != NULL &&
                   (imo == NULL || imo->imo_multicast_loop)) {
                        /*
                         * If we belong to the destination multicast group
                         * on the outgoing interface, and the caller did not
                         * forbid loopback, loop back a copy.
                         */
                        ip_mloopback(ifp, m, dst);
                }
#ifdef MROUTING
                else {
                        /*
                         * If we are acting as a multicast router, perform
                         * multicast forwarding as if the packet had just
                         * arrived on the interface to which we are about
                         * to send.  The multicast forwarding function
                         * recursively calls this function, using the
                         * IP_FORWARDING flag to prevent infinite recursion.
                         *
                         * Multicasts that are looped back by ip_mloopback(),
                         * above, will be forwarded by the ip_input() routine,
                         * if necessary.
                         */
                        extern struct socket *ip_mrouter;

                        if (ip_mrouter && (flags & IP_FORWARDING) == 0) {
                                if (ip_mforward(m, ifp) != 0) {
                                        m_freem(m);
                                        goto done;
                                }
                        }
                }
#endif
                /*
                 * Multicasts with a time-to-live of zero may be looped-
                 * back, above, but must not be transmitted on a network.
                 * Also, multicasts addressed to the loopback interface
                 * are not sent -- the above call to ip_mloopback() will
                 * loop back a copy if this host actually belongs to the
                 * destination group on the loopback interface.
                 */
                if (ip->ip_ttl == 0 || (ifp->if_flags & IFF_LOOPBACK) != 0) {
                        m_freem(m);
                        goto done;
                }

                goto sendit;
        }
#ifndef notdef
        /*
         * If source address not specified yet, use address
         * of outgoing interface.
         */
        if (in_nullhost(ip->ip_src))
                ip->ip_src = ia->ia_addr.sin_addr;
#endif

        /*
         * packets with Class-D address as source are not valid per
         * RFC 1112
         */
        if (IN_MULTICAST(ip->ip_src.s_addr)) {
                ipstat.ips_odropped++;
                error = EADDRNOTAVAIL;
                goto bad;
        }

        /*
         * Look for broadcast address and
         * and verify user is allowed to send
         * such a packet.
         */
        if (in_broadcast(dst->sin_addr, ifp)) {
                if ((ifp->if_flags & IFF_BROADCAST) == 0) {
                        error = EADDRNOTAVAIL;
                        goto bad;
                }
                if ((flags & IP_ALLOWBROADCAST) == 0) {
                        error = EACCES;
                        goto bad;
                }
                /* don't allow broadcast messages to be fragmented */
                if ((u_int16_t)ip->ip_len > ifp->if_mtu) {
                        error = EMSGSIZE;
                        goto bad;
                }
                m->m_flags |= M_BCAST;
        } else
                m->m_flags &= ~M_BCAST;

sendit:
#ifdef PFIL_HOOKS
        /*
         * Run through list of hooks for output packets.
         */
        m1 = m;
        pfh = pfil_hook_get(PFIL_OUT, &inetsw[ip_protox[IPPROTO_IP]].pr_pfh);
        for (; pfh; pfh = pfh->pfil_link.tqe_next)
                if (pfh->pfil_func) {
                        rv = pfh->pfil_func(ip, hlen, ifp, 1, &m1);
                        if (rv) {
                                error = EHOSTUNREACH;
                                goto done;
                        }
                        m = m1;
                        if (m == NULL)
                                goto done;
                        ip = mtod(m, struct ip *);
                }
#endif /* PFIL_HOOKS */

        /********************************************************************
         * We are now ready to send the packet.  However, instead of sending,
         * pass it to the SSH packet interceptor code.
         *******************************************************************/

        /* Release the route if appropriate. */
        if (ro == &iproute && ro->ro_rt) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = 0;
        }

        /* Fix up various fields of the packet. */
        HTONS(ip->ip_len);
        HTONS(ip->ip_off);
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum(m, hlen);

        /* Construct interceptor flags. */
        icept_flags = SSH_ICEPT_F_FROM_PROTOCOL;
        if (flags & IP_FORWARDING)
          icept_flags |= SSH_ICEPT_F_FORWARDED;

        /* Pass the packet to the interceptor.  This call will perform
           m_freem(m).  Make sure we are at splsoftnet. */
        s = splsoftnet();
        ssh_interceptor_receive(SSH_PROTOCOL_IP4, icept_flags,
                                ifp, NULL, 0, m);
        splx(s);
        return 0;

done:
        if (ro == &iproute && (flags & IP_ROUTETOIF) == 0 && ro->ro_rt) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = 0;
        }
        return (error);
bad:
        m_freem(m);
        goto done;
}


void ssh_interceptor_ip4_mbuf_send_to_network(ifp, mediahdr, mediahdr_len, m)
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
        register struct ip *ip;
        struct route *ro;
        struct sockaddr_in *dst;
        struct in_ifaddr *ia;
        int error = 0;
        struct route iproute;
        int len, hlen, off, mtu;

#ifdef SSH_INTERCEPTOR_DEBUG
        printf("ssh_interceptor_ip4_mbuf_send_to_network\n");
#endif
        /* Sanity check: mbuf should contain at least IP header. */
        if (m->m_pkthdr.len < sizeof(struct ip)) {
            printf("ssh_interceptor_ip4_mbuf_send_to_network: "
                   "mbuf too short\n");
            m_freem(m);
            return;
        }

        /* Convert packet len and offset back to host byte order. */
        ip = mtod(m, struct ip *);
        NTOHS(ip->ip_len);
        NTOHS(ip->ip_off);

        /* Sanity checks: mbuf should contain the entire packet, and
           nothing else, and IP header should not be longer than
           packet. */
        if (m->m_pkthdr.len != ip->ip_len) {
            printf("ssh_interceptor_ip4_mbuf_send_to_network: "
                   "bad mbuf len %d vs. %d\n",
                   m->m_pkthdr.len, ip->ip_len);
            m_freem(m);
            return;
        }

        if ((ip->ip_hl << 2) > ip->ip_len) {
            printf("ssh_interceptor_ip4_mbuf_send_to_network: "
                   "hlen too large\n");
            m_freem(m);
            return;
        }

        /* We must route the packet again, as any work done before
           entering the interceptor was lost. This code fragment is
           found from ip_output. */

        /*
         * Route packet.
         */
        ro = &iproute;
        bzero((caddr_t)ro, sizeof (*ro));
        dst = satosin(&ro->ro_dst);
        /*
         * If there is a cached route,
         * check that it is to the same destination
         * and is still up.  If not, free it and try again.
         */
        if (ro->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
            !in_hosteq(dst->sin_addr, ip->ip_dst))) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = (struct rtentry *)0;
        }
        if (ro->ro_rt == 0) {
                dst->sin_family = AF_INET;
                dst->sin_len = sizeof(*dst);
                dst->sin_addr = ip->ip_dst;
        }
        /*
         * If routing to interface only,
         * short circuit routing lookup.
         */
        if (ro->ro_rt == 0)
                rtalloc(ro);
        if (ro->ro_rt == 0) {
                ipstat.ips_noroute++;
                error = EHOSTUNREACH;
                goto bad;
        }
        ia = ifatoia(ro->ro_rt->rt_ifa);

        /* Sanity check; not sure if this can happen except when there
           is a bug in the routing interface.  This check must not be
           done for multicast packets.  */
        if (!IN_MULTICAST(ip->ip_dst.s_addr) && ifp != ro->ro_rt->rt_ifp) {
            printf("SSH interceptor: ifp %s (%d) different from "
                   "route ifp %s (%d)\n",
                   ifp->if_xname, ifp->if_index - 1,
                   ro->ro_rt->rt_ifp->if_xname,
                   ro->ro_rt->rt_ifp->if_index - 1);
            ifp = ro->ro_rt->rt_ifp;
        }

        ro->ro_rt->rt_use++;
        if (ro->ro_rt->rt_flags & RTF_GATEWAY)
            dst = satosin(ro->ro_rt->rt_gateway);

        if (IN_MULTICAST(ip->ip_dst.s_addr)) {
            /*
             * IP destination address is multicast.  Make sure "dst"
             * still points to the address in "ro".  (It may have been
             * changed to point to a gateway address, above.)
             */
            dst = satosin(&ro->ro_dst);
        }

        /*
         * If small enough for mtu of path, can just send directly.
         */
        hlen =  ip->ip_hl << 2;
        mtu = ifp->if_mtu;

        if ((u_int16_t)ip->ip_len <= mtu) {
#if IFA_STATS
                /*
                 * search for the source address structure to
                 * maintain output statistics.
                 */
                bzero((caddr_t*) &src, sizeof(src));
                src.sin_family = AF_INET;
                src.sin_addr.s_addr = ip->ip_src.s_addr;
                src.sin_len = sizeof(src);
                ia = ifatoia(ifa_ifwithladdr(sintosa(&src)));
                if (ia)
                        ia->ia_ifa.ifa_data.ifad_outbytes += ntohs(ip->ip_len);
#endif
                HTONS(ip->ip_len);
                HTONS(ip->ip_off);
                ip->ip_sum = 0;
                ip->ip_sum = in_cksum(m, hlen);
                error = (*ifp->if_output)(ifp, m, sintosa(dst), ro->ro_rt);
                goto done;
        }

        /*
         * Too large for interface; fragment if possible.
         * Must be able to put at least 8 bytes per fragment.
         */












        if (ip->ip_off & IP_DF) {
                error = EMSGSIZE;
                ipstat.ips_cantfrag++;
                goto bad;
        }
        len = (mtu - hlen) &~ 7;
        if (len < 8) {
                error = EMSGSIZE;
                goto bad;
        }

    {
        int mhlen, firstlen = len;
        struct mbuf *m0, **mnext = &m->m_nextpkt;
        int fragments = 0;
        int s;
        struct ip *mhip;

        /*
         * Loop through length of segment after first fragment,
         * make new header and copy data of each part and link onto chain.
         */
        m0 = m;
        mhlen = sizeof (struct ip);
        for (off = hlen + len; off < (u_int16_t)ip->ip_len; off += len) {
                MGETHDR(m, M_DONTWAIT, MT_HEADER);
                if (m == 0) {
                        error = ENOBUFS;
                        ipstat.ips_odropped++;
                        goto sendorfree;
                }
                *mnext = m;
                mnext = &m->m_nextpkt;
                m->m_data += max_linkhdr;
                mhip = mtod(m, struct ip *);
                *mhip = *ip;
                /* we must inherit MCAST and BCAST flags */
                m->m_flags |= m0->m_flags & (M_MCAST|M_BCAST);
                if (hlen > sizeof (struct ip)) {
                        mhlen = ip_optcopy(ip, mhip) + sizeof (struct ip);
                        mhip->ip_hl = mhlen >> 2;
                }
                m->m_len = mhlen;
                mhip->ip_off = ((off - hlen) >> 3) + (ip->ip_off & ~IP_MF);
                if (ip->ip_off & IP_MF)
                        mhip->ip_off |= IP_MF;
                if (off + len >= (u_int16_t)ip->ip_len)
                        len = (u_int16_t)ip->ip_len - off;
                else
                        mhip->ip_off |= IP_MF;
                mhip->ip_len = htons((u_int16_t)(len + mhlen));
                m->m_next = m_copy(m0, off, len);
                if (m->m_next == 0) {
                        error = ENOBUFS;        /* ??? */
                        ipstat.ips_odropped++;
                        goto sendorfree;
                }
                m->m_pkthdr.len = mhlen + len;
                m->m_pkthdr.rcvif = (struct ifnet *)0;
                HTONS(mhip->ip_off);
                mhip->ip_sum = 0;
                mhip->ip_sum = in_cksum(m, mhlen);
                ipstat.ips_ofragments++;
                fragments++;
        }
        /*
         * Update first fragment by trimming what's been copied out
         * and updating header, then send each fragment (in order).
         */
        m = m0;
        m_adj(m, hlen + firstlen - (u_int16_t)ip->ip_len);
        m->m_pkthdr.len = hlen + firstlen;
        ip->ip_len = htons((u_int16_t)m->m_pkthdr.len);
        ip->ip_off |= IP_MF;
        HTONS(ip->ip_off);
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum(m, hlen);
sendorfree:
        /*
         * If there is no room for all the fragments, don't queue
         * any of them.
         */
        s = splimp();
        if (ifp->if_snd.ifq_maxlen - ifp->if_snd.ifq_len < fragments)
                error = ENOBUFS;
        splx(s);
        for (m = m0; m; m = m0) {
                m0 = m->m_nextpkt;
                m->m_nextpkt = 0;
                if (error == 0) {
#if IFA_STATS
                        /*
                         * search for the source address structure to
                         * maintain output statistics.
                         */
                        bzero((caddr_t*) &src, sizeof(src));
                        src.sin_family = AF_INET;
                        src.sin_addr.s_addr = ip->ip_src.s_addr;
                        src.sin_len = sizeof(src);
                        ia = ifatoia(ifa_ifwithladdr(sintosa(&src)));
                        if (ia) {
                                ia->ia_ifa.ifa_data.ifad_outbytes +=
                                        ntohs(ip->ip_len);
                        }
#endif
                        error = (*ifp->if_output)(ifp, m, sintosa(dst),
                            ro->ro_rt);
                } else
                        m_freem(m);
        }

        if (error == 0)
                ipstat.ips_fragmented++;
    }
done:
        if (ro == &iproute && ro->ro_rt) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = 0;
        }
        return;
bad:
        m_freem(m);
        goto done;
}

/*
 * Insert IP options into preformed packet.
 * Adjust IP destination as required for IP source routing,
 * as indicated by a non-zero in_addr at the start of the options.
 */
static struct mbuf *
ip_insertoptions(m, opt, phlen)
        struct mbuf *m;
        struct mbuf *opt;
        int *phlen;
{
        struct ipoption *p = mtod(opt, struct ipoption *);
        struct mbuf *n;
        struct ip *ip = mtod(m, struct ip *);
        unsigned optlen;

        optlen = opt->m_len - sizeof(p->ipopt_dst);
        if (optlen + (u_int16_t)ip->ip_len > IP_MAXPACKET)
                return (m);             



        if (!in_nullhost(p->ipopt_dst))
                ip->ip_dst = p->ipopt_dst;
        if (m->m_flags & M_EXT || m->m_data - optlen < m->m_pktdat) {
                MGETHDR(n, M_DONTWAIT, MT_HEADER);
                if (n == 0)
                        return (m);
                n->m_pkthdr.len = m->m_pkthdr.len + optlen;
                m->m_len -= sizeof(struct ip);
                m->m_data += sizeof(struct ip);
                n->m_next = m;
                m = n;
                m->m_len = optlen + sizeof(struct ip);
                m->m_data += max_linkhdr;
                bcopy((caddr_t)ip, mtod(m, caddr_t), sizeof(struct ip));
        } else {
                m->m_data -= optlen;
                m->m_len += optlen;
                m->m_pkthdr.len += optlen;
                memmove(mtod(m, caddr_t), ip, sizeof(struct ip));
        }
        ip = mtod(m, struct ip *);
        bcopy((caddr_t)p->ipopt_list, (caddr_t)(ip + 1), (unsigned)optlen);
        *phlen = sizeof(struct ip) + optlen;
        ip->ip_len += optlen;
        return (m);
}


/*
 * Routine called from ip_output() to loop back a copy of an IP multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be &loif -- easier than replicating that code here.
 */
static void
ip_mloopback(ifp, m, dst)
        struct ifnet *ifp;
        struct mbuf *m;
        struct sockaddr_in *dst;
{
        struct ip *ip;
        struct mbuf *copym;

        copym = m_copy(m, 0, M_COPYALL);
        if (copym != NULL
         && (copym->m_flags & M_EXT || copym->m_len < sizeof(struct ip)))
                copym = m_pullup(copym, sizeof(struct ip));
        if (copym != NULL) {
                /*
                 * We don't bother to fragment if the IP length is greater
                 * than the interface's MTU.  Can this possibly matter?
                 */
                ip = mtod(copym, struct ip *);
                HTONS(ip->ip_len);
                HTONS(ip->ip_off);
                ip->ip_sum = 0;
                ip->ip_sum = in_cksum(copym, ip->ip_hl << 2);
                (void) looutput(ifp, copym, sintosa(dst), NULL);
        }
}


/*********************************************************************
 * ifioctl hook.
 *********************************************************************/

/* This function is attached to be called after any call to ifioctl.
   Such calls are a potential indication of interface status or parameters
   changing. */
void ssh_interceptor_after_ifioctl(void)
{
  int s;

  s = splsoftnet();
  ssh_interceptor_notify_interface_change();
  splx(s);
}


/*********************************************************************
 * ipflow_fastforward replacement.
 *********************************************************************/

int ssh_interceptor_ipflow_fastforward(struct mbuf *m)
{
  /* Do not fast-forward packets. */
  return 0;
}


#if defined (WITH_IPV6)
/******************************** IPv6 hooks ********************************/

/* This implementation is derived from the NetBSD kernel sources.  The
   original copyright information is below. */

#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/nd6.h>

#ifdef IPV6FIREWALL
#include <netinet6/ip6_fw.h>
#endif

#include <netinet6/ip6protosw.h>

#ifndef NLOOP
#define NLOOP 1
#endif

/*      $NetBSD: ip6_input.c,v 1.20 2000/04/12 10:36:45 itojun Exp $    */
/*      $KAME: ip6_input.c,v 1.72 2000/03/21 09:23:19 itojun Exp $      */

/*
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip_input.c  8.2 (Berkeley) 1/4/94
 */

void
ssh_interceptor_ip6intr()
{
        int s;
        struct mbuf *m;

        for (;;) {
                s = splimp();
                IF_DEQUEUE(&ip6intrq, m);
                splx(s);
                if (m == 0)
                        return;

                /* Pass the packet to the interceptor.  This call will
                   perform m_freem(m).  We must be in the correct spl
                   level when ipintr was called so no need to do any
                   spls here. */
                ssh_interceptor_receive(SSH_PROTOCOL_IP6, 0,
                                        m->m_pkthdr.rcvif,
                                        NULL, 0, m);
        }
}

/* Process an IP packet coming from the interceptor and going up to
   the protocol.  This will call m_freem(m). */

void ssh_interceptor_ip6_mbuf_send_to_protocol(ifp, mediahdr, mediahdr_len, m)
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
  size_t pullup_len;

  /* KAME requires the drivers to store incoming data so that the
     region between the IP6 header and the target header (including
     IPv6 itself, extension headers and TCP/UDP/ICMP6 header) are
     continuous.  We will try to fix this with the following pullup
     thing which should compress possible internal mbufs into one. */

  pullup_len = m->m_pkthdr.len;
  if (pullup_len > MHLEN)
    pullup_len = MHLEN;

  if ((m->m_flags & M_EXT) == 0 && m->m_next && m->m_len < pullup_len)
    {
      m = m_pullup(m, pullup_len);
      if (m == NULL)
        return;
    }

#ifdef SSH_INTERCEPTOR_DEBUG
  printf("ssh_interceptor_ip6_mbuf_send_to_protocol\n");
#endif

  /* Pass the packet to the normal ip6_input() function. */
  ip6_input(m);
}


/*      $NetBSD: ip6_output.c,v 1.18 2000/03/29 03:38:53 simonb Exp $   */

/*
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip_output.c 8.3 (Berkeley) 1/21/94
 */

struct ip6_exthdrs {
        struct mbuf *ip6e_ip6;
        struct mbuf *ip6e_hbh;
        struct mbuf *ip6e_dest1;
        struct mbuf *ip6e_rthdr;
        struct mbuf *ip6e_dest2;
};

static int ip6_copyexthdr __P((struct mbuf **, caddr_t, int));
static int ip6_insertfraghdr __P((struct mbuf *, struct mbuf *, int,
                                  struct ip6_frag **));
static int ip6_insert_jumboopt __P((struct ip6_exthdrs *, u_int32_t));
static int ip6_splithdr __P((struct mbuf *, struct ip6_exthdrs *));

extern struct ifnet loif[NLOOP];

/*
 * IP6 output. The packet in mbuf chain m contains a skeletal IP6
 * header (with pri, len, nxt, hlim, src, dst).
 * This function may modify ver and hlim only.
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 */
int
ssh_interceptor_ip6_output(m0, opt, ro, flags, im6o, ifpp)
        struct mbuf *m0;
        struct ip6_pktopts *opt;
        struct route_in6 *ro;
        int flags;
        struct ip6_moptions *im6o;
        struct ifnet **ifpp;            
{
        struct ip6_hdr *ip6;
        struct ifnet *ifp, *origifp;
        struct mbuf *m = m0;
        struct route_in6 ip6route;
        struct sockaddr_in6 *dst;
        int error = 0;
        struct in6_ifaddr *ia;
        u_int32_t optlen = 0, plen = 0, unfragpartlen = 0;
        struct ip6_exthdrs exthdrs;
        struct in6_addr finaldst;
        struct route_in6 *ro_pmtu = NULL;
        int hdrsplit = 0;
        int needipsec = 0;
        int s;                  /* spl level */
#ifdef PFIL_HOOKS
        struct packet_filter_hook *pfh;
        struct mbuf *m1;
        int rv;
#endif /* PFIL_HOOKS */
        unsigned int icept_flags;
#ifdef IPSEC
        int needipsectun = 0;
        struct socket *so;
        struct secpolicy *sp = NULL;

        /* for AH processing. stupid to have "socket" variable in IP layer... */
        so = ipsec_getsocket(m);
        ipsec_setsocket(m, NULL);
        ip6 = mtod(m, struct ip6_hdr *);
#endif /* IPSEC */

#ifdef SSH_INTERCEPTOR_DEBUG
        printf("ssh_interceptor_ip6_output\n");
#endif

#define MAKE_EXTHDR(hp, mp)                                             \
    do {                                                                \
        if (hp) {                                                       \
                struct ip6_ext *eh = (struct ip6_ext *)(hp);            \
                error = ip6_copyexthdr((mp), (caddr_t)(hp),             \
                                       ((eh)->ip6e_len + 1) << 3);      \
                if (error)                                              \
                        goto freehdrs;                                  \
        }                                                               \
    } while (0)

        bzero(&exthdrs, sizeof(exthdrs));
        if (opt) {
                /* Hop-by-Hop options header */
                MAKE_EXTHDR(opt->ip6po_hbh, &exthdrs.ip6e_hbh);
                /* Destination options header(1st part) */
                MAKE_EXTHDR(opt->ip6po_dest1, &exthdrs.ip6e_dest1);
                /* Routing header */
                MAKE_EXTHDR(opt->ip6po_rthdr, &exthdrs.ip6e_rthdr);
                /* Destination options header(2nd part) */
                MAKE_EXTHDR(opt->ip6po_dest2, &exthdrs.ip6e_dest2);
        }

#ifdef IPSEC
        /* get a security policy for this packet */
        if (so == NULL)
                sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_OUTBOUND, 0, &error);
        else
                sp = ipsec6_getpolicybysock(m, IPSEC_DIR_OUTBOUND, so, &error);

        if (sp == NULL) {
                ipsec6stat.out_inval++;
                goto freehdrs;
        }

        error = 0;

        /* check policy */
        switch (sp->policy) {
        case IPSEC_POLICY_DISCARD:
                /*
                 * This packet is just discarded.
                 */
                ipsec6stat.out_polvio++;
                goto freehdrs;

        case IPSEC_POLICY_BYPASS:
        case IPSEC_POLICY_NONE:
                /* no need to do IPsec. */
                needipsec = 0;
                break;

        case IPSEC_POLICY_IPSEC:
                if (sp->req == NULL) {



                        printf("ip6_output: No IPsec request specified.\n");
                        error = EINVAL;
                        goto freehdrs;
                }
                needipsec = 1;
                break;

        case IPSEC_POLICY_ENTRUST:
        default:
                printf("ip6_output: Invalid policy found. %d\n", sp->policy);
        }
#endif /* IPSEC */

        /*
         * Calculate the total length of the extension header chain.
         * Keep the length of the unfragmentable part for fragmentation.
         */
        optlen = 0;
        if (exthdrs.ip6e_hbh) optlen += exthdrs.ip6e_hbh->m_len;
        if (exthdrs.ip6e_dest1) optlen += exthdrs.ip6e_dest1->m_len;
        if (exthdrs.ip6e_rthdr) optlen += exthdrs.ip6e_rthdr->m_len;
        unfragpartlen = optlen + sizeof(struct ip6_hdr);
        /* NOTE: we don't add AH/ESP length here. do that later. */
        if (exthdrs.ip6e_dest2) optlen += exthdrs.ip6e_dest2->m_len;

        /*
         * If we need IPsec, or there is at least one extension header,
         * separate IP6 header from the payload.
         */
        if ((needipsec || optlen) && !hdrsplit) {
                if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
                        m = NULL;
                        goto freehdrs;
                }
                m = exthdrs.ip6e_ip6;
                hdrsplit++;
        }

        /* adjust pointer */
        ip6 = mtod(m, struct ip6_hdr *);

        /* adjust mbuf packet header length */
        m->m_pkthdr.len += optlen;
        plen = m->m_pkthdr.len - sizeof(*ip6);

        /* If this is a jumbo payload, insert a jumbo payload option. */
        if (plen > IPV6_MAXPACKET) {
                if (!hdrsplit) {
                        if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
                                m = NULL;
                                goto freehdrs;
                        }
                        m = exthdrs.ip6e_ip6;
                        hdrsplit++;
                }
                /* adjust pointer */
                ip6 = mtod(m, struct ip6_hdr *);
                if ((error = ip6_insert_jumboopt(&exthdrs, plen)) != 0)
                        goto freehdrs;
                ip6->ip6_plen = 0;
        } else
                ip6->ip6_plen = htons(plen);

        /*
         * Concatenate headers and fill in next header fields.
         * Here we have, on "m"
         *      IPv6 payload
         * and we insert headers accordingly.  Finally, we should be getting:
         *      IPv6 hbh dest1 rthdr ah* [esp* dest2 payload]
         *
         * during the header composing process, "m" points to IPv6 header.
         * "mprev" points to an extension header prior to esp.
         */
        {
                u_char *nexthdrp = &ip6->ip6_nxt;
                struct mbuf *mprev = m;

                /*
                 * we treat dest2 specially.  this makes IPsec processing
                 * much easier.
                 *
                 * result: IPv6 dest2 payload
                 * m and mprev will point to IPv6 header.
                 */
                if (exthdrs.ip6e_dest2) {
                        if (!hdrsplit)
                                panic("assumption failed: hdr not split");
                        exthdrs.ip6e_dest2->m_next = m->m_next;
                        m->m_next = exthdrs.ip6e_dest2;
                        *mtod(exthdrs.ip6e_dest2, u_char *) = ip6->ip6_nxt;
                        ip6->ip6_nxt = IPPROTO_DSTOPTS;
                }

#define MAKE_CHAIN(m, mp, p, i)\
    do {\
        if (m) {\
                if (!hdrsplit) \
                        panic("assumption failed: hdr not split"); \
                *mtod((m), u_char *) = *(p);\
                *(p) = (i);\
                p = mtod((m), u_char *);\
                (m)->m_next = (mp)->m_next;\
                (mp)->m_next = (m);\
                (mp) = (m);\
        }\
    } while (0)
                /*
                 * result: IPv6 hbh dest1 rthdr dest2 payload
                 * m will point to IPv6 header.  mprev will point to the
                 * extension header prior to dest2 (rthdr in the above case).
                 */
                MAKE_CHAIN(exthdrs.ip6e_hbh, mprev,
                           nexthdrp, IPPROTO_HOPOPTS);
                MAKE_CHAIN(exthdrs.ip6e_dest1, mprev,
                           nexthdrp, IPPROTO_DSTOPTS);
                MAKE_CHAIN(exthdrs.ip6e_rthdr, mprev,
                           nexthdrp, IPPROTO_ROUTING);

#ifdef IPSEC
                if (!needipsec)
                        goto skip_ipsec2;

                /*
                 * pointers after IPsec headers are not valid any more.
                 * other pointers need a great care too.
                 * (IPsec routines should not mangle mbufs prior to AH/ESP)
                 */
                exthdrs.ip6e_dest2 = NULL;

            {
                struct ip6_rthdr *rh = NULL;
                int segleft_org = 0;
                struct ipsec_output_state state;

                if (exthdrs.ip6e_rthdr) {
                        rh = mtod(exthdrs.ip6e_rthdr, struct ip6_rthdr *);
                        segleft_org = rh->ip6r_segleft;
                        rh->ip6r_segleft = 0;
                }

                bzero(&state, sizeof(state));
                state.m = m;
                error = ipsec6_output_trans(&state, nexthdrp, mprev, sp, flags,
                        &needipsectun);
                m = state.m;
                if (error) {
                        /* mbuf is already reclaimed in ipsec6_output_trans. */
                        m = NULL;
                        switch (error) {
                        case EHOSTUNREACH:
                        case ENETUNREACH:
                        case EMSGSIZE:
                        case ENOBUFS:
                        case ENOMEM:
                                break;
                        default:
                                printf("ip6_output (ipsec): error code %d\n", error);
                                /*fall through*/
                        case ENOENT:
                                /* don't show these error codes to the user */
                                error = 0;
                                break;
                        }
                        goto bad;
                }
                if (exthdrs.ip6e_rthdr) {
                        /* ah6_output doesn't modify mbuf chain */
                        rh->ip6r_segleft = segleft_org;
                }
            }
skip_ipsec2:;
#endif
        }

        /*
         * If there is a routing header, replace destination address field
         * with the first hop of the routing header.
         */
        if (exthdrs.ip6e_rthdr) {
                struct ip6_rthdr *rh =
                        (struct ip6_rthdr *)(mtod(exthdrs.ip6e_rthdr,
                                                  struct ip6_rthdr *));
                struct ip6_rthdr0 *rh0;

                finaldst = ip6->ip6_dst;
                switch(rh->ip6r_type) {
                case IPV6_RTHDR_TYPE_0:
                         rh0 = (struct ip6_rthdr0 *)rh;
                         ip6->ip6_dst = rh0->ip6r0_addr[0];
                         bcopy((caddr_t)&rh0->ip6r0_addr[1],
                                 (caddr_t)&rh0->ip6r0_addr[0],
                                 sizeof(struct in6_addr)*(rh0->ip6r0_segleft - 1)
                                 );
                         rh0->ip6r0_addr[rh0->ip6r0_segleft - 1] = finaldst;
                         break;
                default:        /* is it possible? */
                         error = EINVAL;
                         goto bad;
                }
        }

        /* Source address validation */
        if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
            (flags & IPV6_DADOUTPUT) == 0) {
                error = EOPNOTSUPP;
                ip6stat.ip6s_badscope++;
                goto bad;
        }
        if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)) {
                error = EOPNOTSUPP;
                ip6stat.ip6s_badscope++;
                goto bad;
        }

        ip6stat.ip6s_localout++;

        /*
         * Route packet.
         */
        if (ro == 0) {
                ro = &ip6route;
                bzero((caddr_t)ro, sizeof(*ro));
        }
        ro_pmtu = ro;
        if (opt && opt->ip6po_rthdr)
                ro = &opt->ip6po_route;
        dst = (struct sockaddr_in6 *)&ro->ro_dst;
        /*
         * If there is a cached route,
         * check that it is to the same destination
         * and is still up. If not, free it and try again.
         */
        if (ro->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
                         !IN6_ARE_ADDR_EQUAL(&dst->sin6_addr, &ip6->ip6_dst))) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = (struct rtentry *)0;
        }
        if (ro->ro_rt == 0) {
                bzero(dst, sizeof(*dst));
                dst->sin6_family = AF_INET6;
                dst->sin6_len = sizeof(struct sockaddr_in6);
                dst->sin6_addr = ip6->ip6_dst;
        }
#ifdef IPSEC
        if (needipsec && needipsectun) {
                struct ipsec_output_state state;

                /*
                 * All the extension headers will become inaccessible
                 * (since they can be encrypted).
                 * Don't panic, we need no more updates to extension headers
                 * on inner IPv6 packet (since they are now encapsulated).
                 *
                 * IPv6 [ESP|AH] IPv6 [extension headers] payload
                 */
                bzero(&exthdrs, sizeof(exthdrs));
                exthdrs.ip6e_ip6 = m;

                bzero(&state, sizeof(state));
                state.m = m;
                state.ro = (struct route *)ro;
                state.dst = (struct sockaddr *)dst;

                error = ipsec6_output_tunnel(&state, sp, flags);

                m = state.m;
                ro = (struct route_in6 *)state.ro;
                dst = (struct sockaddr_in6 *)state.dst;
                if (error) {
                        /* mbuf is already reclaimed in ipsec6_output_tunnel. */
                        m0 = m = NULL;
                        m = NULL;
                        switch (error) {
                        case EHOSTUNREACH:
                        case ENETUNREACH:
                        case EMSGSIZE:
                        case ENOBUFS:
                        case ENOMEM:
                                break;
                        default:
                                printf("ip6_output (ipsec): error code %d\n", error);
                                /*fall through*/
                        case ENOENT:
                                /* don't show these error codes to the user */
                                error = 0;
                                break;
                        }
                        goto bad;
                }

                exthdrs.ip6e_ip6 = m;
        }
#endif /*IPSEC*/

        if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
                /* Unicast */

#define ifatoia6(ifa)   ((struct in6_ifaddr *)(ifa))
#define sin6tosa(sin6)  ((struct sockaddr *)(sin6))







                if (ro->ro_rt == 0) {
                        /*
                         * non-bsdi always clone routes, if parent is
                         * PRF_CLONING.
                         */
                        rtalloc((struct route *)ro);
                }
                if (ro->ro_rt == 0) {
                        ip6stat.ip6s_noroute++;
                        error = EHOSTUNREACH;



                        goto bad;
                }
                ia = ifatoia6(ro->ro_rt->rt_ifa);
                ifp = ro->ro_rt->rt_ifp;
                ro->ro_rt->rt_use++;
                if (ro->ro_rt->rt_flags & RTF_GATEWAY)
                        dst = (struct sockaddr_in6 *)ro->ro_rt->rt_gateway;
                m->m_flags &= ~(M_BCAST | M_MCAST);     /* just in case */

#if 0
                /* SSH: This is counted in ip6_mbuf_send_to_network()
                   if ever. */
                in6_ifstat_inc(ifp, ifs6_out_request);
#endif

                /*
                 * Check if the outgoing interface conflicts with
                 * the interface specified by ifi6_ifindex (if specified).
                 * Note that loopback interface is always okay.
                 * (this may happen when we are sending a packet to one of
                 *  our own addresses.)
                 */
                if (opt && opt->ip6po_pktinfo
                 && opt->ip6po_pktinfo->ipi6_ifindex) {
                        if (!(ifp->if_flags & IFF_LOOPBACK)
                         && ifp->if_index != opt->ip6po_pktinfo->ipi6_ifindex) {
                                ip6stat.ip6s_noroute++;
                                in6_ifstat_inc(ifp, ifs6_out_discard);
                                error = EHOSTUNREACH;
                                goto bad;
                        }
                }

                if (opt && opt->ip6po_hlim != -1)
                        ip6->ip6_hlim = opt->ip6po_hlim & 0xff;
        } else {
                /* Multicast */
                struct  in6_multi *in6m;

                m->m_flags = (m->m_flags & ~M_BCAST) | M_MCAST;

                /*
                 * See if the caller provided any multicast options
                 */
                ifp = NULL;
                if (im6o != NULL) {
                        ip6->ip6_hlim = im6o->im6o_multicast_hlim;
                        if (im6o->im6o_multicast_ifp != NULL)
                                ifp = im6o->im6o_multicast_ifp;
                } else
                        ip6->ip6_hlim = ip6_defmcasthlim;

                /*
                 * See if the caller provided the outgoing interface
                 * as an ancillary data.
                 * Boundary check for ifindex is assumed to be already done.
                 */
                if (opt && opt->ip6po_pktinfo && opt->ip6po_pktinfo->ipi6_ifindex)
                        ifp = ifindex2ifnet[opt->ip6po_pktinfo->ipi6_ifindex];

                /*
                 * If the destination is a node-local scope multicast,
                 * the packet should be loop-backed only.
                 */
                if (IN6_IS_ADDR_MC_NODELOCAL(&ip6->ip6_dst)) {
                        /*
                         * If the outgoing interface is already specified,
                         * it should be a loopback interface.
                         */
                        if (ifp && (ifp->if_flags & IFF_LOOPBACK) == 0) {
                                ip6stat.ip6s_badscope++;
                                error = ENETUNREACH; 




                                in6_ifstat_inc(ifp, ifs6_out_discard);
                                goto bad;
                        } else {
                                ifp = &loif[0];
                        }
                }

                if (opt && opt->ip6po_hlim != -1)
                        ip6->ip6_hlim = opt->ip6po_hlim & 0xff;

                /*
                 * If caller did not provide an interface lookup a
                 * default in the routing table.  This is either a
                 * default for the speicfied group (i.e. a host
                 * route), or a multicast default (a route for the
                 * ``net'' ff00::/8).
                 */
                if (ifp == NULL) {
                        if (ro->ro_rt == 0) {
                                ro->ro_rt = rtalloc1((struct sockaddr *)
                                                &ro->ro_dst, 0
                                                );
                        }
                        if (ro->ro_rt == 0) {
                                ip6stat.ip6s_noroute++;
                                error = EHOSTUNREACH;



                                goto bad;
                        }
                        ia = ifatoia6(ro->ro_rt->rt_ifa);
                        ifp = ro->ro_rt->rt_ifp;
                        ro->ro_rt->rt_use++;
                }

                /* SSH: We count the multicast output requests and
                   output multicasts here instead of in the
                   mbuf_send_to_network().  This way we get a better
                   approximation of the statistics, although the
                   engine can drop the packet.  But, the original
                   statistics did count the multicast packets in, not
                   the output packets from each multicast-enabled
                   interface. */
                if ((flags & IPV6_FORWARDING) == 0)
                        in6_ifstat_inc(ifp, ifs6_out_request);
                in6_ifstat_inc(ifp, ifs6_out_mcast);

                /*
                 * Confirm that the outgoing interface supports multicast.
                 */
                if ((ifp->if_flags & IFF_MULTICAST) == 0) {
                        ip6stat.ip6s_noroute++;
                        in6_ifstat_inc(ifp, ifs6_out_discard);
                        error = ENETUNREACH;
                        goto bad;
                }
                IN6_LOOKUP_MULTI(ip6->ip6_dst, ifp, in6m);
                if (in6m != NULL &&
                   (im6o == NULL || im6o->im6o_multicast_loop)) {
                        /*
                         * If we belong to the destination multicast group
                         * on the outgoing interface, and the caller did not
                         * forbid loopback, loop back a copy.
                         */
                        ip6_mloopback(ifp, m, dst);
                } else {
                        /*
                         * If we are acting as a multicast router, perform
                         * multicast forwarding as if the packet had just
                         * arrived on the interface to which we are about
                         * to send.  The multicast forwarding function
                         * recursively calls this function, using the
                         * IPV6_FORWARDING flag to prevent infinite recursion.
                         *
                         * Multicasts that are looped back by ip6_mloopback(),
                         * above, will be forwarded by the ip6_input() routine,
                         * if necessary.
                         */
                        if (ip6_mrouter && (flags & IPV6_FORWARDING) == 0) {
                                if (ip6_mforward(ip6, ifp, m) != 0) {
                                        m_freem(m);
                                        goto done;
                                }
                        }
                }
                /*
                 * Multicasts with a hoplimit of zero may be looped back,
                 * above, but must not be transmitted on a network.
                 * Also, multicasts addressed to the loopback interface
                 * are not sent -- the above call to ip6_mloopback() will
                 * loop back a copy if this host actually belongs to the
                 * destination group on the loopback interface.
                 */
                if (ip6->ip6_hlim == 0 || (ifp->if_flags & IFF_LOOPBACK)) {
                        m_freem(m);
                        goto done;
                }
        }

        /*
         * Fill the outgoing inteface to tell the upper layer
         * to increment per-interface statistics.
         */
        if (ifpp)
                *ifpp = ifp;


        /* Fake scoped addresses */
        if ((ifp->if_flags & IFF_LOOPBACK) != 0) {
                /*
                 * If source or destination address is a scoped address, and
                 * the packet is going to be sent to a loopback interface,
                 * we should keep the original interface.
                 */












          if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
            origifp = ifindex2ifnet[ntohs(ip6->ip6_src.s6_addr16[1])];
          else if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
            origifp = ifindex2ifnet[ntohs(ip6->ip6_dst.s6_addr16[1])];
          else
                        origifp = ifp;
        }
        else
                origifp = ifp;
#ifndef FAKE_LOOPBACK_IF
        if ((ifp->if_flags & IFF_LOOPBACK) == 0)
#else
        if (1)
#endif
        {
                if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
                        ip6->ip6_src.s6_addr16[1] = 0;
                if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
                        ip6->ip6_dst.s6_addr16[1] = 0;
        }

#ifdef PFIL_HOOKS
        /*
         * Run through list of hooks for output packets.
         */
        m1 = m;
        pfh = pfil_hook_get(PFIL_OUT, &inetsw[ip_protox[IPPROTO_IPV6]].pr_pfh);
        for (; pfh; pfh = pfh->pfil_link.tqe_next)
                if (pfh->pfil_func) {
                        rv = pfh->pfil_func(ip6, sizeof(*ip6), ifp, 1, &m1);
                        if (rv) {
                                error = EHOSTUNREACH;
                                goto done;
                        }
                        m = m1;
                        if (m == NULL)
                                goto done;
                        ip6 = mtod(m, struct ip6_hdr *);
                }
#endif /* PFIL_HOOKS */

        /********************************************************************
         * We are now ready to send the packet.  However, instead of
         * sending, pass it to the SSH packet interceptor code.
         ********************************************************************/

        /* Release the route if appropriate. */
        if (ro == &ip6route && ro->ro_rt) { /* brace necessary for RTFREE */
                RTFREE(ro->ro_rt);
        } else if (ro_pmtu == &ip6route && ro_pmtu->ro_rt) {
                RTFREE(ro_pmtu->ro_rt);
        }

        /* Construct interceptor flags. */
        icept_flags = SSH_ICEPT_F_FROM_PROTOCOL;
        if (flags & IPV6_FORWARDING)
          icept_flags |= SSH_ICEPT_F_FORWARDED;

        /* Pass the packet to the interceptor.  This call will perform
           m_freem(m).  Make sure we are at splsoftnet. */
        s = splsoftnet();
        ssh_interceptor_receive(SSH_PROTOCOL_IP6, icept_flags,
                                ifp, NULL, 0, m);
        splx(s);

        return 0;

done:
        if (ro == &ip6route && ro->ro_rt) { /* brace necessary for RTFREE */
                RTFREE(ro->ro_rt);
        } else if (ro_pmtu == &ip6route && ro_pmtu->ro_rt) {
                RTFREE(ro_pmtu->ro_rt);
        }

#ifdef IPSEC
        if (sp != NULL)
                key_freesp(sp);
#endif /* IPSEC */

        return(error);

freehdrs:
        m_freem(exthdrs.ip6e_hbh);      /* m_freem will check if mbuf is 0 */
        m_freem(exthdrs.ip6e_dest1);
        m_freem(exthdrs.ip6e_rthdr);
        m_freem(exthdrs.ip6e_dest2);
        /* fall through */
bad:
        m_freem(m);
        goto done;
}


/*      $NetBSD: ip6_forward.c,v 1.12.2.4 2000/09/29 06:29:54 itojun Exp $      */
/*      $KAME: ip6_forward.c,v 1.56 2000/09/22 04:01:37 itojun Exp $    */

/*
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/syslog.h>
#include <net/if.h>

#define if_name(ifp) ((ifp)->if_xname)

extern struct   route_in6 ip6_forward_rt;

/*
 * Forward a packet.  If some error occurs return the sender
 * an icmp packet.  Note we can't always generate a meaningful
 * icmp message because icmp doesn't have a large enough repertoire
 * of codes and types.
 *
 * If not forwarding, just drop the packet.  This could be confusing
 * if ipforwarding was zero but some routing protocol was advancing
 * us as a gateway to somewhere.  However, we must let the routing
 * protocol deal with that.
 *
 */

void
ssh_interceptor_ip6_forward(m, srcrt)
        struct mbuf *m;
        int srcrt;
{
        struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
        register struct sockaddr_in6 *dst;
        register struct rtentry *rt;
        int error, type = 0, code = 0;
        struct mbuf *mcopy = NULL;
        struct ifnet *origifp;  /* maybe unnecessary */
#ifdef IPSEC
        struct secpolicy *sp = NULL;
#endif
        long time_second = time.tv_sec;
        int s;

#ifdef IPSEC
        /*
         * Check AH/ESP integrity.
         */
        /*
         * Don't increment ip6s_cantforward because this is the check
         * before forwarding packet actually.
         */
        if (ipsec6_in_reject(m, NULL)) {
                ipsec6stat.in_polvio++;
                m_freem(m);
                return;
        }
#endif /*IPSEC*/

        /*
         * Do not forward packets to multicast destination (should be handled
         * by ip6_mforward().
         * Do not forward packets with unspecified source.  It was discussed
         * in July 2000, on ipngwg mailing list.
         */
        if ((m->m_flags & (M_BCAST|M_MCAST)) != 0 ||
            IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
            IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
                ip6stat.ip6s_cantforward++;



                if (ip6_log_time + ip6_log_interval < time_second) {
                        ip6_log_time = time_second;
                        log(LOG_DEBUG,
                            "cannot forward "
                            "from %s to %s nxt %d received on %s\n",
                            ip6_sprintf(&ip6->ip6_src),
                            ip6_sprintf(&ip6->ip6_dst),
                            ip6->ip6_nxt,
                            if_name(m->m_pkthdr.rcvif));
                }
                m_freem(m);
                return;
        }

        if (ip6->ip6_hlim <= IPV6_HLIMDEC) {



                icmp6_error(m, ICMP6_TIME_EXCEEDED,
                                ICMP6_TIME_EXCEED_TRANSIT, 0);
                return;
        }
        ip6->ip6_hlim -= IPV6_HLIMDEC;

        /*
         * Save at most ICMPV6_PLD_MAXLEN (= the min IPv6 MTU -
         * size of IPv6 + ICMPv6 headers) bytes of the packet in case
         * we need to generate an ICMP6 message to the src.
         * Thanks to M_EXT, in most cases copy will not occur.
         *
         * It is important to save it before IPsec processing as IPsec
         * processing may modify the mbuf.
         */
        mcopy = m_copy(m, 0, imin(m->m_pkthdr.len, ICMPV6_PLD_MAXLEN));

#ifdef IPSEC
        /* get a security policy for this packet */
        sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_OUTBOUND, IP_FORWARDING,
            &error);
        if (sp == NULL) {
                ipsec6stat.out_inval++;
                ip6stat.ip6s_cantforward++;
                if (mcopy) {
#if 0



#else
                        m_freem(mcopy);
#endif
                }
                m_freem(m);
                return;
        }

        error = 0;

        /* check policy */
        switch (sp->policy) {
        case IPSEC_POLICY_DISCARD:
                /*
                 * This packet is just discarded.
                 */
                ipsec6stat.out_polvio++;
                ip6stat.ip6s_cantforward++;
                key_freesp(sp);
                if (mcopy) {
#if 0



#else
                        m_freem(mcopy);
#endif
                }
                m_freem(m);
                return;

        case IPSEC_POLICY_BYPASS:
        case IPSEC_POLICY_NONE:
                /* no need to do IPsec. */
                key_freesp(sp);
                goto skip_ipsec;

        case IPSEC_POLICY_IPSEC:
                if (sp->req == NULL) {



                        printf("ip6_forward: No IPsec request specified.\n");
                        ip6stat.ip6s_cantforward++;
                        key_freesp(sp);
                        if (mcopy) {
#if 0



#else
                                m_freem(mcopy);
#endif
                        }
                        m_freem(m);
                        return;
                }
                /* do IPsec */
                break;

        case IPSEC_POLICY_ENTRUST:
        default:
                /* should be panic ?? */
                printf("ip6_forward: Invalid policy found. %d\n", sp->policy);
                key_freesp(sp);
                goto skip_ipsec;
        }

    {
        struct ipsec_output_state state;

        /*
         * All the extension headers will become inaccessible
         * (since they can be encrypted).
         * Don't panic, we need no more updates to extension headers
         * on inner IPv6 packet (since they are now encapsulated).
         *
         * IPv6 [ESP|AH] IPv6 [extension headers] payload
         */
        bzero(&state, sizeof(state));
        state.m = m;
        state.ro = NULL;        /* update at ipsec6_output_tunnel() */
        state.dst = NULL;       /* update at ipsec6_output_tunnel() */

        error = ipsec6_output_tunnel(&state, sp, 0);

        m = state.m;






        key_freesp(sp);

        if (error) {
                /* mbuf is already reclaimed in ipsec6_output_tunnel. */
                switch (error) {
                case EHOSTUNREACH:
                case ENETUNREACH:
                case EMSGSIZE:
                case ENOBUFS:
                case ENOMEM:
                        break;
                default:
                        printf("ip6_output (ipsec): error code %d\n", error);
                        /*fall through*/
                case ENOENT:
                        /* don't show these error codes to the user */
                        break;
                }
                ip6stat.ip6s_cantforward++;
                if (mcopy) {
#if 0



#else
                        m_freem(mcopy);
#endif
                }
                m_freem(m);
                return;
        }
    }
    skip_ipsec:
#endif /* IPSEC */

        dst = &ip6_forward_rt.ro_dst;
        if (!srcrt) {
                /*
                 * ip6_forward_rt.ro_dst.sin6_addr is equal to ip6->ip6_dst
                 */
                if (ip6_forward_rt.ro_rt == 0 ||
                    (ip6_forward_rt.ro_rt->rt_flags & RTF_UP) == 0) {
                        if (ip6_forward_rt.ro_rt) {
                                RTFREE(ip6_forward_rt.ro_rt);
                                ip6_forward_rt.ro_rt = 0;
                        }
                        /* this probably fails but give it a try again */
                        rtalloc((struct route *)&ip6_forward_rt);
                }

                if (ip6_forward_rt.ro_rt == 0) {
                        ip6stat.ip6s_noroute++;



                        if (mcopy) {
                                icmp6_error(mcopy, ICMP6_DST_UNREACH,
                                            ICMP6_DST_UNREACH_NOROUTE, 0);
                        }
                        m_freem(m);
                        return;
                }
        } else if ((rt = ip6_forward_rt.ro_rt) == 0 ||
                 !IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &dst->sin6_addr)) {
                if (ip6_forward_rt.ro_rt) {
                        RTFREE(ip6_forward_rt.ro_rt);
                        ip6_forward_rt.ro_rt = 0;
                }
                bzero(dst, sizeof(*dst));
                dst->sin6_len = sizeof(struct sockaddr_in6);
                dst->sin6_family = AF_INET6;
                dst->sin6_addr = ip6->ip6_dst;

                rtalloc((struct route *)&ip6_forward_rt);
                if (ip6_forward_rt.ro_rt == 0) {
                        ip6stat.ip6s_noroute++;



                        if (mcopy) {
                                icmp6_error(mcopy, ICMP6_DST_UNREACH,
                                            ICMP6_DST_UNREACH_NOROUTE, 0);
                        }
                        m_freem(m);
                        return;
                }
        }
        rt = ip6_forward_rt.ro_rt;

        /*
         * Scope check: if a packet can't be delivered to its destination
         * for the reason that the destination is beyond the scope of the
         * source address, discard the packet and return an icmp6 destination
         * unreachable error with Code 2 (beyond scope of source address).
         * [draft-ietf-ipngwg-icmp-v3-00.txt, Section 3.1]
         */
        if (in6_addr2scopeid(m->m_pkthdr.rcvif, &ip6->ip6_src) !=
            in6_addr2scopeid(rt->rt_ifp, &ip6->ip6_src)) {
                ip6stat.ip6s_cantforward++;
                ip6stat.ip6s_badscope++;
                in6_ifstat_inc(rt->rt_ifp, ifs6_in_discard);

                if (ip6_log_time + ip6_log_interval < time_second) {
                        ip6_log_time = time_second;
                        log(LOG_DEBUG,
                            "cannot forward "
                            "src %s, dst %s, nxt %d, rcvif %s, outif %s\n",
                            ip6_sprintf(&ip6->ip6_src),
                            ip6_sprintf(&ip6->ip6_dst),
                            ip6->ip6_nxt,
                            if_name(m->m_pkthdr.rcvif), if_name(rt->rt_ifp));
                }
                if (mcopy)
                        icmp6_error(mcopy, ICMP6_DST_UNREACH,
                                    ICMP6_DST_UNREACH_BEYONDSCOPE, 0);
                m_freem(m);
                return;
        }

        if (m->m_pkthdr.len > rt->rt_ifp->if_mtu) {
                in6_ifstat_inc(rt->rt_ifp, ifs6_in_toobig);
                if (mcopy) {
                        u_long mtu;
#ifdef IPSEC
                        struct secpolicy *sp;
                        int ipsecerror;
                        size_t ipsechdrsiz;
#endif

                        mtu = rt->rt_ifp->if_mtu;
#ifdef IPSEC
                        /*
                         * When we do IPsec tunnel ingress, we need to play
                         * with if_mtu value (decrement IPsec header size
                         * from mtu value).  The code is much simpler than v4
                         * case, as we have the outgoing interface for
                         * encapsulated packet as "rt->rt_ifp".
                         */
                        sp = ipsec6_getpolicybyaddr(mcopy, IPSEC_DIR_OUTBOUND,
                                IP_FORWARDING, &ipsecerror);
                        if (sp) {
                                ipsechdrsiz = ipsec6_hdrsiz(mcopy,
                                        IPSEC_DIR_OUTBOUND, NULL);
                                if (ipsechdrsiz < mtu)
                                        mtu -= ipsechdrsiz;
                        }

                        /*
                         * if mtu becomes less than minimum MTU,
                         * tell minimum MTU (and I'll need to fragment it).
                         */
                        if (mtu < IPV6_MMTU)
                                mtu = IPV6_MMTU;
#endif
                        icmp6_error(mcopy, ICMP6_PACKET_TOO_BIG, 0, mtu);
                }
                m_freem(m);
                return;
        }

        if (rt->rt_flags & RTF_GATEWAY)
                dst = (struct sockaddr_in6 *)rt->rt_gateway;

        /*
         * If we are to forward the packet using the same interface
         * as one we got the packet from, perhaps we should send a redirect
         * to sender to shortcut a hop.
         * Only send redirect if source is sending directly to us,
         * and if packet was not source routed (or has any options).
         * Also, don't send redirect if forwarding using a route
         * modified by a redirect.
         */
        if (rt->rt_ifp == m->m_pkthdr.rcvif && !srcrt &&
            (rt->rt_flags & (RTF_DYNAMIC|RTF_MODIFIED)) == 0)
                type = ND_REDIRECT;

#ifdef IPV6FIREWALL
        /*
         * Check with the firewall...
         */
        if (ip6_fw_chk_ptr) {
                u_short port = 0;
                /* If ipfw says divert, we have to just drop packet */
                if ((*ip6_fw_chk_ptr)(&ip6, rt->rt_ifp, &port, &m)) {
                        m_freem(m);
                        goto freecopy;
                }
                if (!m)
                        goto freecopy;
        }
#endif

        /*
         * Fake scoped addresses. Note that even link-local source or
         * destinaion can appear, if the originating node just sends the
         * packet to us (without address resolution for the destination).
         * Since both icmp6_error and icmp6_redirect_output fill the embedded
         * link identifiers, we can do this stuff after make a copy for
         * returning error.
         */
        if ((rt->rt_ifp->if_flags & IFF_LOOPBACK) != 0) {











#if 1
                if (0)
#else
                if ((rt->rt_flags & (RTF_BLACKHOLE|RTF_REJECT)) == 0)
#endif
                {
                        printf("ip6_forward: outgoing interface is loopback. "
                               "src %s, dst %s, nxt %d, rcvif %s, outif %s\n",
                               ip6_sprintf(&ip6->ip6_src),
                               ip6_sprintf(&ip6->ip6_dst),
                               ip6->ip6_nxt, if_name(m->m_pkthdr.rcvif),
                               if_name(rt->rt_ifp));
                }

                if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
                        origifp = ifindex2ifnet[ntohs(ip6->ip6_src.s6_addr16[1])];
                else if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
                        origifp = ifindex2ifnet[ntohs(ip6->ip6_dst.s6_addr16[1])];
                else
                        origifp = rt->rt_ifp;
        }
        else
                origifp = rt->rt_ifp;
#ifndef FAKE_LOOPBACK_IF
        if ((rt->rt_ifp->if_flags & IFF_LOOPBACK) == 0)
#else
        if (1)
#endif
        {
                if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
                        ip6->ip6_src.s6_addr16[1] = 0;
                if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
                        ip6->ip6_dst.s6_addr16[1] = 0;
        }

        /********************************************************************
         * Now we are ready to send the packet.  However, instead of
         * sending, pass it to the SSH packet interceptor code.
         ********************************************************************/

        /* Pass the packet to the interceptor.  This call will perform
           m_free(m).  Make sure we are at splsoftnet. */
        s = splsoftnet();
        ssh_interceptor_receive(SSH_PROTOCOL_IP6,
                                (SSH_ICEPT_F_FROM_PROTOCOL
                                 | SSH_ICEPT_F_FORWARDED),
                                rt->rt_ifp, NULL, 0, m);
        splx(s);

        /* Engine is always successful. */
        error = 0;

        if (error) {
                in6_ifstat_inc(rt->rt_ifp, ifs6_out_discard);
                ip6stat.ip6s_cantforward++;
        } else {
                ip6stat.ip6s_forward++;
                in6_ifstat_inc(rt->rt_ifp, ifs6_out_forward);
                if (type)
                        ip6stat.ip6s_redirectsent++;
                else {
                        if (mcopy)
                                goto freecopy;
                }
        }
        if (mcopy == NULL)
                return;

        switch (error) {
        case 0:
#if 1
                if (type == ND_REDIRECT) {
                        icmp6_redirect_output(mcopy, rt);
                        return;
                }
#endif
                goto freecopy;

        case EMSGSIZE:



                goto freecopy;

        case ENOBUFS:
                /* Tell source to slow down like source quench in IP? */
                goto freecopy;

        case ENETUNREACH:       /* shouldn't happen, checked above */
        case EHOSTUNREACH:
        case ENETDOWN:
        case EHOSTDOWN:
        default:
                type = ICMP6_DST_UNREACH;
                code = ICMP6_DST_UNREACH_ADDR;
                break;
        }
        icmp6_error(mcopy, type, code, 0);
        return;

 freecopy:
        m_freem(mcopy);
        return;
}



/* Should we do path MTU discovery in the mbuf_send_to_network?  The
   right answer is not. */
#define SSH_IP6_MBUF_SEND_TO_NETWORK_DO_PMTU 0

void ssh_interceptor_ip6_mbuf_send_to_network(ifp, mediahdr, mediahdr_len, m)
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
        struct ip6_hdr *ip6, *mhip6;
        int hlen, tlen, len, off;
        struct route_in6 ip6route;
        struct sockaddr_in6 *dst;
        int error = 0;
        struct in6_ifaddr *ia;
        u_long mtu;
        u_int32_t plen = 0, unfragpartlen = 0;
#if SSH_IP6_MBUF_SEND_TO_NETWORK_DO_PMTU
        struct in6_addr finaldst;
#endif /* SSH_IP6_MBUF_SEND_TO_NETWORK_DO_PMTU */
        struct route_in6 *ro_pmtu = NULL;
        int flags = 0;          
        struct route_in6 *ro = NULL;
        struct mbuf *m0;
        unsigned char hbh_buf[64]; /* 64 is taken from my hat // mtr */
        struct ip6_hbh *hbh = NULL;
        struct ip6_exthdrs exthdrs;
        struct ifnet *origifp;

#ifdef SSH_INTERCEPTOR_DEBUG
        printf("ssh_interceptor_ip6_mbuf_send_to_network\n");
#endif

        /* Sanity check: mbuf should contain at least IP header. */
        if (m->m_pkthdr.len < sizeof(struct ip6_hdr)) {
                printf("ssh_interceptor_ip6_mbuf_send_to_network: "
                       "mbuf too short\n");
                goto bad;
        }

        /* Restore some local variables after the interceptor / engine
           call. */
        ip6 = mtod(m, struct ip6_hdr *);
        plen = ntohs(ip6->ip6_plen);

        /* The extension headers are currently used in the
           fragmentation code.  If our engine does the fragmentation,
           we do not need these.  If the fragmentation is peformed by
           this function, the extension headers must be extracted from
           the original packet `m'. */
        bzero(&exthdrs, sizeof(exthdrs));

        /* We must fetch the hop-by-hop extension header from the
           packet since later in this file, we will process it. */
        if (ip6->ip6_nxt == 0) {
                size_t hbh_len;

                /* The packet has a hop-by-hop extension header.
                   Check that the packet is long enought to hold the
                   minumum hop-by-hop header. */
                if (plen < 8
                    || m->m_pkthdr.len < sizeof(struct ip6_hdr) + 8) {
                        printf("ssh_interceptor_ip6_mbuf_send_to_network: "
                               "mbuf is too short to contain hop-by-hop "
                               "extension header");
                        goto bad;
                }

                /* Fetch the minimum hop-by-hop extension header. */
                hbh = (struct ip6_hbh *) &hbh_buf;
                m_copydata(m, sizeof(struct ip6_hdr), 8, (caddr_t) hbh);

                /* Check if the whole hop-by-hop header is in the
                   mbuf. */
                hbh_len = (hbh->ip6h_len + 1) * 8;
                if (plen < hbh_len || (m->m_pkthdr.len
                                       < sizeof(struct ip6_hdr) + hbh_len)) {
                        printf("ssh_interceptor_ip6_mbuf_send_to_network: "
                               "mbuf is too short to contain whole "
                               "hop-by-hop extension header");
                        goto bad;
                }

                /* Fetch the whole hop-by-hop extension header. */
                if (hbh_len > sizeof(hbh_buf)) {
                        /* It is too big for our static buffer.  We
                           must allocate the structure dynamically. */
                        hbh = malloc(hbh_len, M_IP6OPT, M_NOWAIT);
                        if (hbh == NULL)
                                goto bad;
                }
                m_copydata(m, sizeof(struct ip6_hdr), hbh_len, (caddr_t) hbh);
        }

        /* Sanity check: mbuf should contain the entire packet, and
           nothing else.  The IP header should not be longer than
           packet. */
        if (m->m_pkthdr.len != plen + sizeof(struct ip6_hdr)) {
                printf("ssh_interceptor_ip6_mbuf_send_to_network: "
                       "bad mbuf len: mbuflen=%d, plen=%d\n",
                       m->m_pkthdr.len, plen);
                goto bad;
        }

        /* We must route the packet again, as any work done before
           entering the interceptor was lost.  The remaining of this
           function is taken more or less directly from the
           ip6_output() function. */

        /* Source address validation */
        if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
            (flags & IPV6_DADOUTPUT) == 0) {
                error = EOPNOTSUPP;
                ip6stat.ip6s_badscope++;
                goto bad;
        }
        if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)) {
                error = EOPNOTSUPP;
                ip6stat.ip6s_badscope++;
                goto bad;
        }

        ip6stat.ip6s_localout++;

        /*
         * Route packet.
         */
        ro = &ip6route;
        bzero((caddr_t)ro, sizeof(*ro));
        ro_pmtu = ro;
        dst = (struct sockaddr_in6 *)&ro->ro_dst;

        /* Get a route for link-local addresses.  Check `raw_ip6.c'
           for the details. */
        if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst)
            || IN6_IS_ADDR_MC_LINKLOCAL(&ip6->ip6_dst))
          {
            ip6->ip6_dst.s6_addr16[1] = htons(ifp->if_index);

            if (in6_selectsrc(dst, NULL, NULL, ro, NULL, &error) == 0)
              {
                if (error == 0)
                  error = EADDRNOTAVAIL;
                goto bad;
              }
          }

        /*
         * If there is a cached route,
         * check that it is to the same destination
         * and is still up. If not, free it and try again.
         */
        if (ro->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
                         !IN6_ARE_ADDR_EQUAL(&dst->sin6_addr, &ip6->ip6_dst))) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = (struct rtentry *)0;
        }
        if (ro->ro_rt == 0) {
                bzero(dst, sizeof(*dst));
                dst->sin6_family = AF_INET6;
                dst->sin6_len = sizeof(struct sockaddr_in6);
                dst->sin6_addr = ip6->ip6_dst;
        }

        if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
                /* Unicast */

#define ifatoia6(ifa)   ((struct in6_ifaddr *)(ifa))
#define sin6tosa(sin6)  ((struct sockaddr *)(sin6))
                /* xxx
                 * interface selection comes here
                 * if an interface is specified from an upper layer,
                 * ifp must point it.
                 */
                if (ro->ro_rt == 0) {
                        /*
                         * NetBSD/OpenBSD always clones routes, if parent is
                         * PRF_CLONING.
                         */
                        rtalloc((struct route *)ro);
                }
                if (ro->ro_rt == 0) {
                        ip6stat.ip6s_noroute++;
                        error = EHOSTUNREACH;



                        goto bad;
                }
                ia = ifatoia6(ro->ro_rt->rt_ifa);

                /* Sanity check; not sure if this can happen except
                   when there is a bug in the routing interface. */
                if (ifp != ro->ro_rt->rt_ifp) {
                  printf("ssh_interceptor_ip6_mbuf_send_to_network: "
                         "ifp %s (%d) different from route ifp %s (%d) "
                         "for destination %s: "
                         "using route ifp\n",
                         ifp->if_xname, ifp->if_index - 1,
                         ro->ro_rt->rt_ifp->if_xname,
                         ro->ro_rt->rt_ifp->if_index - 1,
                         ip6_sprintf(&ip6->ip6_dst));
                  ifp = ro->ro_rt->rt_ifp;
                }

                ro->ro_rt->rt_use++;
                if (ro->ro_rt->rt_flags & RTF_GATEWAY)
                        dst = (struct sockaddr_in6 *)ro->ro_rt->rt_gateway;
                m->m_flags &= ~(M_BCAST | M_MCAST);     /* just in case */

                in6_ifstat_inc(ifp, ifs6_out_request);
        } else {
                /* Multicast */

                m->m_flags = (m->m_flags & ~M_BCAST) | M_MCAST;

                /* The ssh_interceptor_ip6_output function has already
                   took care of multicast routing and forwarding.  We
                   will use the interceptor/engine provided interface
                   to send out this multicast packet so there is no
                   need to do anything else here. */
        }

        /* We can not determine path MTU here because system's routing
           tables have too small idea about that.  It is the PMTU
           before any IPsec processing.  After that (in the physical
           link following us), we can use a bit bigger PMTU. */
        





#if SSH_IP6_MBUF_SEND_TO_NETWORK_DO_PMTU
        /*
         * Determine path MTU.
         */
        finaldst = ip6->ip6_dst;
        if (ro_pmtu != ro) {
                /* The first hop and the final destination may differ. */
                struct sockaddr_in6 *sin6_fin =
                        (struct sockaddr_in6 *)&ro_pmtu->ro_dst;
                if (ro_pmtu->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
                                       !IN6_ARE_ADDR_EQUAL(&sin6_fin->sin6_addr,
                                                           &finaldst))) {
                        RTFREE(ro_pmtu->ro_rt);
                        ro_pmtu->ro_rt = (struct rtentry *)0;
                }
                if (ro_pmtu->ro_rt == 0) {
                        bzero(sin6_fin, sizeof(*sin6_fin));
                        sin6_fin->sin6_family = AF_INET6;
                        sin6_fin->sin6_len = sizeof(struct sockaddr_in6);
                        sin6_fin->sin6_addr = finaldst;

                        rtalloc((struct route *)ro_pmtu);
                }
        }
        if (ro_pmtu->ro_rt != NULL) {
                u_int32_t ifmtu = nd_ifinfo[ifp->if_index].linkmtu;

                mtu = ro_pmtu->ro_rt->rt_rmx.rmx_mtu;
                if (mtu > ifmtu) {
                        /*
                         * The MTU on the route is larger than the MTU on
                         * the interface!  This shouldn't happen, unless the
                         * MTU of the interface has been changed after the
                         * interface was brought up.  Change the MTU in the
                         * route to match the interface MTU (as long as the
                         * field isn't locked).
                         */
                         mtu = ifmtu;
                         if ((ro_pmtu->ro_rt->rt_rmx.rmx_locks & RTV_MTU) == 0)
                                 ro_pmtu->ro_rt->rt_rmx.rmx_mtu = mtu; 
                }
        } else {
                mtu = nd_ifinfo[ifp->if_index].linkmtu;
        }
#else /* not SSH_IP6_MBUF_SEND_TO_NETWORK_DO_PMTU */
        mtu = nd_ifinfo[ifp->if_index].linkmtu;
#endif /* not SSH_IP6_MBUF_SEND_TO_NETWORK_DO_PMTU */

        /* Fake scoped addresses */
        if ((ifp->if_flags & IFF_LOOPBACK) != 0) {
                /*
                 * If source or destination address is a scoped address, and
                 * the packet is going to be sent to a loopback interface,
                 * we should keep the original interface.
                 */












          if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
            origifp = ifindex2ifnet[ntohs(ip6->ip6_src.s6_addr16[1])];
          else if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
            origifp = ifindex2ifnet[ntohs(ip6->ip6_dst.s6_addr16[1])];
          else
            origifp = ifp;
        }
        else
          origifp = ifp;
#ifndef FAKE_LOOPBACK_IF
        if ((ifp->if_flags & IFF_LOOPBACK) == 0)
#else
        if (1)
#endif
        {
                if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
                        ip6->ip6_src.s6_addr16[1] = 0;
                if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
                        ip6->ip6_dst.s6_addr16[1] = 0;
        }

        /*
         * If the outgoing packet contains a hop-by-hop options header,
         * it must be examined and processed even by the source node.
         * (RFC 2460, section 4.)
         */
        if (hbh) {
                u_int32_t dummy1; 
                u_int32_t dummy2; 









                m->m_flags |= M_LOOP;
                m->m_pkthdr.rcvif = ifp;
                if (ip6_process_hopopts(m,
                                        (u_int8_t *)(hbh + 1),
                                        ((hbh->ip6h_len + 1) << 3) -
                                        sizeof(struct ip6_hbh),
                                        &dummy1, &dummy2) < 0) {
                        /* m was already freed at this point */
                        error = EINVAL;/* better error? */
                        goto done;
                }
                m->m_flags &= ~M_LOOP; 
                m->m_pkthdr.rcvif = NULL;
        }

        /*
         * Send the packet to the outgoing interface.
         * If necessary, do IPv6 fragmentation before sending.
         */
        tlen = m->m_pkthdr.len;
        if (tlen <= mtu
#ifdef notyet
            /*
             * On any link that cannot convey a 1280-octet packet in one piece,
             * link-specific fragmentation and reassembly must be provided at
             * a layer below IPv6. [RFC 2460, sec.5]
             * Thus if the interface has ability of link-level fragmentation,
             * we can just send the packet even if the packet size is
             * larger than the link's MTU. */





            || ifp->if_flags & IFF_FRAGMENTABLE
#endif
            )
        {
#ifdef IFA_STATS
                if (IFA_STATS) {
                        struct in6_ifaddr *ia6;
                        ip6 = mtod(m, struct ip6_hdr *);
                        ia6 = in6_ifawithifp(ifp, &ip6->ip6_src);
                        if (ia6) {
                                ia->ia_ifa.ifa_data.ifad_outbytes +=
                                        m->m_pkthdr.len;
                        }
                }
#endif
#ifdef OLDIP6OUTPUT
                error = (*ifp->if_output)(ifp, m, (struct sockaddr *)dst,
                                          ro->ro_rt);
#else
                error = nd6_output(ifp, origifp, m, dst, ro->ro_rt);
#endif
                goto done;
        } else if (mtu < IPV6_MMTU) {
                /*
                 * note that path MTU is never less than IPV6_MMTU
                 * (see icmp6_input).
                 */
                error = EMSGSIZE;
                in6_ifstat_inc(ifp, ifs6_out_fragfail);
                goto bad;
        } else if (ip6->ip6_plen == 0) { /* jumbo payload cannot be fragmented */
                error = EMSGSIZE;
                in6_ifstat_inc(ifp, ifs6_out_fragfail);
                goto bad;
        } else {
                struct mbuf **mnext, *m_frgpart;
                struct ip6_frag *ip6f;
                u_int32_t id = htonl(ip6_id++);
                u_char nextproto;

                /*
                 * Too large for the destination or interface;
                 * fragment if possible.
                 * Must be able to put at least 8 bytes per fragment.
                 */
                hlen = unfragpartlen;
                if (mtu > IPV6_MAXPACKET)
                        mtu = IPV6_MAXPACKET;
                len = (mtu - hlen - sizeof(struct ip6_frag)) & ~7;
                if (len < 8) {
                        error = EMSGSIZE;
                        in6_ifstat_inc(ifp, ifs6_out_fragfail);
                        goto bad;
                }

                mnext = &m->m_nextpkt;

                /*
                 * Change the next header field of the last header in the
                 * unfragmentable part.
                 */
                if (exthdrs.ip6e_rthdr) {
                        nextproto = *mtod(exthdrs.ip6e_rthdr, u_char *);
                        *mtod(exthdrs.ip6e_rthdr, u_char *) = IPPROTO_FRAGMENT;
                } else if (exthdrs.ip6e_dest1) {
                        nextproto = *mtod(exthdrs.ip6e_dest1, u_char *);
                        *mtod(exthdrs.ip6e_dest1, u_char *) = IPPROTO_FRAGMENT;
                } else if (exthdrs.ip6e_hbh) {
                        nextproto = *mtod(exthdrs.ip6e_hbh, u_char *);
                        *mtod(exthdrs.ip6e_hbh, u_char *) = IPPROTO_FRAGMENT;
                } else {
                        nextproto = ip6->ip6_nxt;
                        ip6->ip6_nxt = IPPROTO_FRAGMENT;
                }

                /*
                 * Loop through length of segment after first fragment,
                 * make new header and copy data of each part and link onto chain.
                 */
                m0 = m;
                for (off = hlen; off < tlen; off += len) {
                        MGETHDR(m, M_DONTWAIT, MT_HEADER);
                        if (!m) {
                                error = ENOBUFS;
                                ip6stat.ip6s_odropped++;
                                goto sendorfree;
                        }
                        m->m_flags = m0->m_flags & M_COPYFLAGS;
                        *mnext = m;
                        mnext = &m->m_nextpkt;
                        m->m_data += max_linkhdr;
                        mhip6 = mtod(m, struct ip6_hdr *);
                        *mhip6 = *ip6;
                        m->m_len = sizeof(*mhip6);
                        error = ip6_insertfraghdr(m0, m, hlen, &ip6f);
                        if (error) {
                                ip6stat.ip6s_odropped++;
                                goto sendorfree;
                        }
                        ip6f->ip6f_offlg = htons((u_short)((off - hlen) & ~7));
                        if (off + len >= tlen)
                                len = tlen - off;
                        else
                                ip6f->ip6f_offlg |= IP6F_MORE_FRAG;
                        mhip6->ip6_plen = htons((u_short)(len + hlen +
                                                          sizeof(*ip6f) -
                                                          sizeof(struct ip6_hdr)));
                        if ((m_frgpart = m_copy(m0, off, len)) == 0) {
                                error = ENOBUFS;
                                ip6stat.ip6s_odropped++;
                                goto sendorfree;
                        }
                        m_cat(m, m_frgpart);
                        m->m_pkthdr.len = len + hlen + sizeof(*ip6f);
                        m->m_pkthdr.rcvif = (struct ifnet *)0;
                        ip6f->ip6f_reserved = 0;
                        ip6f->ip6f_ident = id;
                        ip6f->ip6f_nxt = nextproto;
                        ip6stat.ip6s_ofragments++;
                        in6_ifstat_inc(ifp, ifs6_out_fragcreat);
                }

                in6_ifstat_inc(ifp, ifs6_out_fragok);
        }

        /*
         * Remove leading garbages.
         */
sendorfree:
        m = m0->m_nextpkt;
        m0->m_nextpkt = 0;
        m_freem(m0);
        for (m0 = m; m; m = m0) {
                m0 = m->m_nextpkt;
                m->m_nextpkt = 0;
                if (error == 0) {
#ifdef IFA_STATS
                        if (IFA_STATS) {
                                struct in6_ifaddr *ia6;
                                ip6 = mtod(m, struct ip6_hdr *);
                                ia6 = in6_ifawithifp(ifp, &ip6->ip6_src);
                                if (ia6) {
                                        ia->ia_ifa.ifa_data.ifad_outbytes +=
                                                m->m_pkthdr.len;
                                }
                        }
#endif
#ifdef OLDIP6OUTPUT
                        error = (*ifp->if_output)(ifp, m,
                                                  (struct sockaddr *)dst,
                                                  ro->ro_rt);
#else
                        error = nd6_output(ifp, origifp, m, dst, ro->ro_rt);
#endif
                } else
                        m_freem(m);
        }

        if (error == 0)
                ip6stat.ip6s_fragmented++;

done:
        if (ro == &ip6route && ro->ro_rt) { /* brace necessary for RTFREE */
                RTFREE(ro->ro_rt);
        } else if (ro_pmtu == &ip6route && ro_pmtu->ro_rt) {
                RTFREE(ro_pmtu->ro_rt);
        }

        /* Free the hop-by-hop structure if it is dynamically allocated. */
        if (hbh && hbh != (struct ip6_hbh *) &hbh_buf)
                free(hbh, M_IP6OPT);

        return;

bad:
        m_freem(m);
        goto done;
}


/************* Static help functions from the ip6_output.c file *************/

static int
ip6_copyexthdr(mp, hdr, hlen)
        struct mbuf **mp;
        caddr_t hdr;
        int hlen;
{
        struct mbuf *m;

        if (hlen > MCLBYTES)
                return(ENOBUFS); 

        MGET(m, M_DONTWAIT, MT_DATA);
        if (!m)
                return(ENOBUFS);

        if (hlen > MLEN) {
                MCLGET(m, M_DONTWAIT);
                if ((m->m_flags & M_EXT) == 0) {
                        m_free(m);
                        return(ENOBUFS);
                }
        }
        m->m_len = hlen;
        if (hdr)
                bcopy(hdr, mtod(m, caddr_t), hlen);

        *mp = m;
        return(0);
}

/*
 * Insert fragment header and copy unfragmentable header portions.
 */
static int
ip6_insertfraghdr(m0, m, hlen, frghdrp)
        struct mbuf *m0, *m;
        int hlen;
        struct ip6_frag **frghdrp;
{
        struct mbuf *n, *mlast;

        if (hlen > sizeof(struct ip6_hdr)) {
                n = m_copym(m0, sizeof(struct ip6_hdr),
                            hlen - sizeof(struct ip6_hdr), M_DONTWAIT);
                if (n == 0)
                        return(ENOBUFS);
                m->m_next = n;
        }
        else
                n = m;

        /* Search for the last mbuf of unfragmentable part. */
        for (mlast = n; mlast->m_next; mlast = mlast->m_next)
                ;

        if ((mlast->m_flags & M_EXT) == 0 &&
            M_TRAILINGSPACE(mlast) < sizeof(struct ip6_frag)) {
                /* use the trailing space of the last mbuf for the fragment hdr */
                *frghdrp =
                        (struct ip6_frag *)(mtod(mlast, caddr_t) + mlast->m_len);
                mlast->m_len += sizeof(struct ip6_frag);
                m->m_pkthdr.len += sizeof(struct ip6_frag);
        }
        else {
                /* allocate a new mbuf for the fragment header */
                struct mbuf *mfrg;

                MGET(mfrg, M_DONTWAIT, MT_DATA);
                if (mfrg == 0)
                        return(ENOBUFS);
                mfrg->m_len = sizeof(struct ip6_frag);
                *frghdrp = mtod(mfrg, struct ip6_frag *);
                mlast->m_next = mfrg;
        }

        return(0);
}

/*
 * Insert jumbo payload option.
 */
static int
ip6_insert_jumboopt(exthdrs, plen)
        struct ip6_exthdrs *exthdrs;
        u_int32_t plen;
{
        struct mbuf *mopt;
        u_char *optbuf;

#define JUMBOOPTLEN     8       /* length of jumbo payload option and padding */

        /*
         * If there is no hop-by-hop options header, allocate new one.
         * If there is one but it doesn't have enough space to store the
         * jumbo payload option, allocate a cluster to store the whole options.
         * Otherwise, use it to store the options.
         */
        if (exthdrs->ip6e_hbh == 0) {
                MGET(mopt, M_DONTWAIT, MT_DATA);
                if (mopt == 0)
                        return(ENOBUFS);
                mopt->m_len = JUMBOOPTLEN;
                optbuf = mtod(mopt, u_char *);
                optbuf[1] = 0;  /* = ((JUMBOOPTLEN) >> 3) - 1 */
                exthdrs->ip6e_hbh = mopt;
        } else {
                struct ip6_hbh *hbh;

                mopt = exthdrs->ip6e_hbh;
                if (M_TRAILINGSPACE(mopt) < JUMBOOPTLEN) {
                        caddr_t oldoptp = mtod(mopt, caddr_t);
                        int oldoptlen = mopt->m_len;

                        if (mopt->m_flags & M_EXT)
                                return(ENOBUFS); 
                        MCLGET(mopt, M_DONTWAIT);
                        if ((mopt->m_flags & M_EXT) == 0)
                                return(ENOBUFS);

                        bcopy(oldoptp, mtod(mopt, caddr_t), oldoptlen);
                        optbuf = mtod(mopt, caddr_t) + oldoptlen;
                        mopt->m_len = oldoptlen + JUMBOOPTLEN;
                } else {
                        optbuf = mtod(mopt, u_char *) + mopt->m_len;
                        mopt->m_len += JUMBOOPTLEN;
                }
                optbuf[0] = IP6OPT_PADN;
                optbuf[1] = 1;

                /*
                 * Adjust the header length according to the pad and
                 * the jumbo payload option.
                 */
                hbh = mtod(mopt, struct ip6_hbh *);
                hbh->ip6h_len += (JUMBOOPTLEN >> 3);
        }

        /* fill in the option. */
        optbuf[2] = IP6OPT_JUMBO;
        optbuf[3] = 4;
        *(u_int32_t *)&optbuf[4] = htonl(plen + JUMBOOPTLEN);

        /* finally, adjust the packet header length */
        exthdrs->ip6e_ip6->m_pkthdr.len += JUMBOOPTLEN;

        return(0);
#undef JUMBOOPTLEN
}

/*
 * Chop IPv6 header off from the payload.
 */
static int
ip6_splithdr(m, exthdrs)
        struct mbuf *m;
        struct ip6_exthdrs *exthdrs;
{
        struct mbuf *mh;
        struct ip6_hdr *ip6;

        ip6 = mtod(m, struct ip6_hdr *);
        if (m->m_len > sizeof(*ip6)) {
                MGETHDR(mh, M_DONTWAIT, MT_HEADER);
                if (mh == 0) {
                        m_freem(m);
                        return ENOBUFS;
                }
                M_COPY_PKTHDR(mh, m);
                MH_ALIGN(mh, sizeof(*ip6));
                m->m_flags &= ~M_PKTHDR;
                m->m_len -= sizeof(*ip6);
                m->m_data += sizeof(*ip6);
                mh->m_next = m;
                m = mh;
                m->m_len = sizeof(*ip6);
                bcopy((caddr_t)ip6, mtod(m, caddr_t), sizeof(*ip6));
        }
        exthdrs->ip6e_ip6 = m;
        return 0;
}
#endif /* WITH_IPV6 */


/*********************** Generic interface functions ************************/

void ssh_interceptor_mbuf_send_to_network(SshInterceptorProtocol protocol,
                                          struct ifnet *ifp,
                                          void *mediahdr,
                                          size_t mediahdr_len,
                                          struct mbuf *m)
{
#if defined (WITH_IPV6)
  if (protocol == SSH_PROTOCOL_IP6)
    {
      ssh_interceptor_ip6_mbuf_send_to_network(ifp, mediahdr, mediahdr_len, m);
      return;
    }
#endif /* WITH_IPV6 */

  ssh_interceptor_ip4_mbuf_send_to_network(ifp, mediahdr, mediahdr_len, m);
}

void ssh_interceptor_mbuf_send_to_protocol(SshInterceptorProtocol protocol,
                                           struct ifnet *ifp,
                                           void *mediahdr,
                                           size_t mediahdr_len,
                                           struct mbuf *m)
{
#if defined (WITH_IPV6)
  if (protocol == SSH_PROTOCOL_IP6)
    {
      ssh_interceptor_ip6_mbuf_send_to_protocol(ifp, mediahdr, mediahdr_len,
                                                m);
      return;
    }
#endif /* WITH_IPV6 */

  ssh_interceptor_ip4_mbuf_send_to_protocol(ifp, mediahdr, mediahdr_len, m);
}

/* Returns the substitutions to be made on this platform. */

SshAttachRec *ssh_get_substitutions()
{
  static SshAttachRec sub[] =
  {
    /* IPv4 */
    { SSH_ATTACH_REPLACE, ipintr, ssh_interceptor_ipintr },
    { SSH_ATTACH_REPLACE, ip_output, ssh_interceptor_ip_output },

#if defined (WITH_IPV6)
    /* IPv6 */
    { SSH_ATTACH_REPLACE, ip6intr, ssh_interceptor_ip6intr },
    { SSH_ATTACH_REPLACE, ip6_output, ssh_interceptor_ip6_output },
    { SSH_ATTACH_REPLACE, ip6_forward, ssh_interceptor_ip6_forward },
#endif /* WITH_IPV6 */

    /* Other hooks. */
    { SSH_ATTACH_AFTER, ifioctl, ssh_interceptor_after_ifioctl },
    { SSH_ATTACH_REPLACE, ipflow_fastforward,
      ssh_interceptor_ipflow_fastforward },

    { SSH_ATTACH_END }
  };

  return sub;
}

int ssh_interceptor_iftype(struct ifnet *ifp)
{
  return SSH_INTERCEPTOR_MEDIA_PLAIN;
}

const char *ssh_ident_attach = ("NetBSD 1.5 IP-level (IPv4"
#if defined (WITH_IPV6)
                                ", IPv6"
#endif /* WITH_IPV6 */
                                ")");

int ssh_interceptor_spl()
{
  return splsoftnet();
}
