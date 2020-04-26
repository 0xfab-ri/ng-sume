/*
 * ng_nf.h
 */

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999-2001, Vitaly V Belekhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: releng/12.0/sys/netgraph/ng_nf.h 326272 2017-11-27 15:23:17Z pfg $
 */

#include <net/ethernet.h>
#include <net/iflib.h>
#include "ifdi_if.h"
#include <sys/bitstring.h>

#ifndef _NETGRAPH_NG_NGF_H_
#define _NETGRAPH_NG_NGF_H_

/* Node type name and magic cookie */
#define NG_NGF_NODE_TYPE		"nf"
#define NGM_NGF_COOKIE		948158920

/* Interface base name */
#define NG_NGF_NGF_NAME		"nf"

/* My hook names */
#define NG_NGF_HOOK_ETHER		"ether"

/* MTU bounds */
#define NG_NGF_MTU_MIN		72
#define NG_NGF_MTU_MAX		ETHER_MAX_LEN_JUMBO
#define NG_NGF_MTU_DEFAULT		1500

struct ngf_softc;

/* Node private data */
struct ng_ngf_private {
	struct ifnet	*ifp;		/* per-interface network data */
	struct ifmedia	media;		/* (fake) media information */
	int		link_status;	/* fake */
	int		unit;		/* Interface unit number */
	node_p		node;		/* Our netgraph node */
	hook_p		ether;		/* Hook for ethernet stream */
};
typedef struct ng_ngf_private *priv_p;

/* Netgraph commands */
enum {
	NGM_NGF_GET_IFNAME = 1,	/* get the interface name */
	NGM_NGF_GET_IFADDRS,		/* returns list of addresses */
	NGM_NGF_SET,			/* set ethernet address */
};

struct iflib_txq;
typedef struct iflib_txq *iflib_txq_t;
struct iflib_rxq;
typedef struct iflib_rxq *iflib_rxq_t;
struct iflib_fl;
typedef struct iflib_fl *iflib_fl_t;

struct iflib_ctx;

typedef struct iflib_filter_info {
	driver_filter_t *ifi_filter;
	void *ifi_filter_arg;
	struct grouptask *ifi_task;
	void *ifi_ctx;
} *iflib_filter_info_t;

#endif /* _NETGRAPH_NG_NGF_H_ */

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

/* Transmit Descriptor */
struct ngf_tx_desc {
	u64 buffer_addr;   /* Address of the descriptor's data buffer */
	union {
		u32 data;
		struct {
			u16 length;  /* Data buffer length */
			u8 cso;  /* Checksum offset */
			u8 cmd;  /* Descriptor control */
		} flags;
	} lower;
	union {
		u32 data;
		struct {
			u8 status; /* Descriptor status */
			u8 css;  /* Checksum start */
			u16 special;
		} fields;
	} upper;
};

/* Receive Descriptor */
struct ngf_rx_desc {
	u64 buffer_addr; /* Address of the descriptor's data buffer */
	u16 length;      /* Length of data DMAed into data buffer */
	u16 csum; /* Packet checksum */
	u8  status;  /* Descriptor status */
	u8  errors;  /* Descriptor Errors */
	u16 special;
};

struct tx_ring {
	struct ngf_softc	*adapter;
	struct ngf_tx_desc	*tx_base;
	uint64_t                tx_paddr; 
	uint8_t			me;
	qidx_t			*tx_rsq;

	qidx_t			tx_rs_cidx;
	qidx_t			tx_rs_pidx;
	qidx_t			tx_cidx_processed;
};

struct rx_ring {
	struct ngf_softc	*adapter;
	struct ngf_rx_desc	*rx_base;
        struct ngf_rx_queue     *que;
	uint64_t                rx_paddr; 
	uint8_t			me;
	qidx_t			*rx_rsq;

	qidx_t			rx_rs_cidx;
	qidx_t			rx_rs_pidx;
	qidx_t			rx_cidx_processed;
};

struct ngf_tx_queue {
	struct ngf_softc	*adapter;
        u32                     msix;
	//u32			eims;		/* This queue's EIMS bit */
	u32                    me;
	struct tx_ring	txr;
};

struct ngf_rx_queue {
	struct ngf_softc	*adapter;
        u32                     msix;
	//u32			eims;		/* This queue's EIMS bit */
	u32                    me;
	struct rx_ring	rxr;
	u64                    irqs;
	struct if_irq          que_irq; 
};

struct ngf_osdep
{
	bus_space_tag_t    mem_bus_space_tag;
	bus_space_handle_t mem_bus_space_handle;
	bus_space_tag_t    io_bus_space_tag;
	bus_space_handle_t io_bus_space_handle;
	bus_space_tag_t    flash_bus_space_tag;
	bus_space_handle_t flash_bus_space_handle;
	device_t	   dev;
	if_ctx_t	   ctx;
};

/* Our adapter structure */
struct ngf_softc {
        device_t        dev;
	node_p		node;
	// priv
	//const char	*name;
        //struct e1000_hw hw;
	priv_p	priv;
	struct ifmedia	*media;		/* (fake) media information */
	u16		link_active;
	//u16		fc;
	u16		link_speed;
	u16		link_duplex;
	//u32		smartspeed;
	//u32		dmac;
	//int		link_mask;

        if_softc_ctx_t shared;
        if_ctx_t ctx;
#define tx_num_queues shared->isc_ntxqsets
#define rx_num_queues shared->isc_nrxqsets
#define intr_type shared->isc_intr
        /* FreeBSD operating-system-specific structures. */
        struct ngf_osdep osdep;
        //struct cdev     *led_dev;

        struct ngf_tx_queue *tx_queues;
        struct ngf_rx_queue *rx_queues;
        struct if_irq   irq;
	u32		rx_mbuf_sz;

	struct resource *memory;

        u32		txd_cmd;

	struct iflib_txq	*txq;

	struct mbuf	*m;
	unsigned long	link_irq;
	u32		linkvec;
};

void ngf_dump_rs(struct ngf_softc *);

#define MEMORY_LOGGING 0
/*
 * Enable mbuf vectors for compressing long mbuf chains
 */

/*
 * NB:
 * - Prefetching in tx cleaning should perhaps be a tunable. The distance ahead
 *   we prefetch needs to be determined by the time spent in m_free vis a vis
 *   the cost of a prefetch. This will of course vary based on the workload:
 *      - NFLX's m_free path is dominated by vm-based M_EXT manipulation which
 *        is quite expensive, thus suggesting very little prefetch.
 *      - small packet forwarding which is just returning a single mbuf to
 *        UMA will typically be very fast vis a vis the cost of a memory
 *        access.
 */


/*
 * File organization:
 *  - private structures
 *  - iflib private utility functions
 *  - ifnet functions
 *  - vlan registry and other exported functions
 *  - iflib public core functions
 *
 *
 */

struct iflib_ctx {
	KOBJ_FIELDS;
	/*
	 * Pointer to hardware driver's softc
	 */
	void *ifc_softc;
	device_t ifc_dev;
	if_t ifc_ifp;

	cpuset_t ifc_cpus;
	if_shared_ctx_t ifc_sctx;
	struct if_softc_ctx ifc_softc_ctx;

	struct sx ifc_ctx_sx;
	struct mtx ifc_state_mtx;

	iflib_txq_t ifc_txqs;
	iflib_rxq_t ifc_rxqs;
	uint32_t ifc_if_flags;
	uint32_t ifc_flags;
	uint32_t ifc_max_fl_buf_size;
	uint32_t ifc_rx_mbuf_sz;

	int ifc_link_state;
	int ifc_watchdog_events;
	struct cdev *ifc_led_dev;
	struct resource *ifc_msix_mem;

	struct if_irq ifc_legacy_irq;
	struct grouptask ifc_admin_task;
	struct grouptask ifc_vflr_task;
	struct iflib_filter_info ifc_filter_info;
	struct ifmedia	ifc_media;

	struct sysctl_oid *ifc_sysctl_node;
	uint16_t ifc_sysctl_ntxqs;
	uint16_t ifc_sysctl_nrxqs;
	uint16_t ifc_sysctl_qs_eq_override;
	uint16_t ifc_sysctl_rx_budget;
	uint16_t ifc_sysctl_tx_abdicate;
	uint16_t ifc_sysctl_core_offset;
#define	CORE_OFFSET_UNSPECIFIED	0xffff
	uint8_t  ifc_sysctl_separate_txrx;

	qidx_t ifc_sysctl_ntxds[8];
	qidx_t ifc_sysctl_nrxds[8];
	struct if_txrx ifc_txrx;
#define isc_txd_encap  ifc_txrx.ift_txd_encap
#define isc_txd_flush  ifc_txrx.ift_txd_flush
#define isc_txd_credits_update  ifc_txrx.ift_txd_credits_update
#define isc_rxd_available ifc_txrx.ift_rxd_available
#define isc_rxd_pkt_get ifc_txrx.ift_rxd_pkt_get
#define isc_rxd_refill ifc_txrx.ift_rxd_refill
#define isc_rxd_flush ifc_txrx.ift_rxd_flush
#define isc_rxd_refill ifc_txrx.ift_rxd_refill
#define isc_rxd_refill ifc_txrx.ift_rxd_refill
#define isc_legacy_intr ifc_txrx.ift_legacy_intr
	eventhandler_tag ifc_vlan_attach_event;
	eventhandler_tag ifc_vlan_detach_event;
	uint8_t ifc_mac[ETHER_ADDR_LEN];
};
#define IP_ALIGNED(m) ((((uintptr_t)(m)->m_data) & 0x3) == 0x2)
#define CACHE_PTR_INCREMENT (CACHE_LINE_SIZE/sizeof(void*))
#define CACHE_PTR_NEXT(ptr) ((void *)(((uintptr_t)(ptr)+CACHE_LINE_SIZE-1) & (CACHE_LINE_SIZE-1)))

#define LINK_ACTIVE(ctx) ((ctx)->ifc_link_state == LINK_STATE_UP)
#define CTX_IS_VF(ctx) ((ctx)->ifc_sctx->isc_flags & IFLIB_IS_VF)

typedef struct iflib_sw_rx_desc_array {
	bus_dmamap_t	*ifsd_map;         /* bus_dma maps for packet */
	struct mbuf	**ifsd_m;           /* pkthdr mbufs */
	caddr_t		*ifsd_cl;          /* direct cluster pointer for rx */
	bus_addr_t	*ifsd_ba;          /* bus addr of cluster for rx */
} iflib_rxsd_array_t;

typedef struct iflib_sw_tx_desc_array {
	bus_dmamap_t    *ifsd_map;         /* bus_dma maps for packet */
	bus_dmamap_t	*ifsd_tso_map;     /* bus_dma maps for TSO packet */
	struct mbuf    **ifsd_m;           /* pkthdr mbufs */
} if_txsd_vec_t;

/* magic number that should be high enough for any hardware */
#define IFLIB_MAX_TX_SEGS		128
#define IFLIB_RX_COPY_THRESH		128
#define IFLIB_MAX_RX_REFRESH		32
/* The minimum descriptors per second before we start coalescing */
#define IFLIB_MIN_DESC_SEC		16384
#define IFLIB_DEFAULT_TX_UPDATE_FREQ	16
#define IFLIB_QUEUE_IDLE		0
#define IFLIB_QUEUE_HUNG		1
#define IFLIB_QUEUE_WORKING		2
/* maximum number of txqs that can share an rx interrupt */
#define IFLIB_MAX_TX_SHARED_INTR	4

/* this should really scale with ring size - this is a fairly arbitrary value */
#define TX_BATCH_SIZE			32

#define IFLIB_RESTART_BUDGET		8

#define CSUM_OFFLOAD		(CSUM_IP_TSO|CSUM_IP6_TSO|CSUM_IP| \
				 CSUM_IP_UDP|CSUM_IP_TCP|CSUM_IP_SCTP| \
				 CSUM_IP6_UDP|CSUM_IP6_TCP|CSUM_IP6_SCTP)

struct iflib_txq {
	qidx_t		ift_in_use;
	qidx_t		ift_cidx;
	qidx_t		ift_cidx_processed;
	qidx_t		ift_pidx;
	uint8_t		ift_gen;
	uint8_t		ift_br_offset;
	uint16_t	ift_npending;
	uint16_t	ift_db_pending;
	uint16_t	ift_rs_pending;
	/* implicit pad */
	uint8_t		ift_txd_size[8];
	uint64_t	ift_processed;
	uint64_t	ift_cleaned;
	uint64_t	ift_cleaned_prev;
#if MEMORY_LOGGING
	uint64_t	ift_enqueued;
	uint64_t	ift_dequeued;
#endif
	uint64_t	ift_no_tx_dma_setup;
	uint64_t	ift_no_desc_avail;
	uint64_t	ift_mbuf_defrag_failed;
	uint64_t	ift_mbuf_defrag;
	uint64_t	ift_map_failed;
	uint64_t	ift_txd_encap_efbig;
	uint64_t	ift_pullups;
	uint64_t	ift_last_timer_tick;

	struct mtx	ift_mtx;
	struct mtx	ift_db_mtx;

	/* constant values */
	if_ctx_t	ift_ctx;
	struct ifmp_ring        *ift_br;
	struct grouptask	ift_task;
	qidx_t		ift_size;
	uint16_t	ift_id;
	struct callout	ift_timer;

	if_txsd_vec_t	ift_sds;
	uint8_t		ift_qstatus;
	uint8_t		ift_closed;
	uint8_t		ift_update_freq;
	struct iflib_filter_info ift_filter_info;
	bus_dma_tag_t	ift_buf_tag;
	bus_dma_tag_t	ift_tso_buf_tag;
	iflib_dma_info_t	ift_ifdi;
#define MTX_NAME_LEN 16
	char                    ift_mtx_name[MTX_NAME_LEN];
	bus_dma_segment_t	ift_segs[IFLIB_MAX_TX_SEGS]  __aligned(CACHE_LINE_SIZE);
#ifdef IFLIB_DIAGNOSTICS
	uint64_t ift_cpu_exec_count[256];
#endif
} __aligned(CACHE_LINE_SIZE);

struct iflib_fl {
	qidx_t		ifl_cidx;
	qidx_t		ifl_pidx;
	qidx_t		ifl_credits;
	uint8_t		ifl_gen;
	uint8_t		ifl_rxd_size;
#if MEMORY_LOGGING
	uint64_t	ifl_m_enqueued;
	uint64_t	ifl_m_dequeued;
	uint64_t	ifl_cl_enqueued;
	uint64_t	ifl_cl_dequeued;
#endif
	/* implicit pad */

	bitstr_t 	*ifl_rx_bitmap;
	qidx_t		ifl_fragidx;
	/* constant */
	qidx_t		ifl_size;
	uint16_t	ifl_buf_size;
	uint16_t	ifl_cltype;
	uma_zone_t	ifl_zone;
	iflib_rxsd_array_t	ifl_sds;
	iflib_rxq_t	ifl_rxq;
	uint8_t		ifl_id;
	bus_dma_tag_t	ifl_buf_tag;
	iflib_dma_info_t	ifl_ifdi;
	uint64_t	ifl_bus_addrs[IFLIB_MAX_RX_REFRESH] __aligned(CACHE_LINE_SIZE);
	caddr_t		ifl_vm_addrs[IFLIB_MAX_RX_REFRESH];
	qidx_t	ifl_rxd_idxs[IFLIB_MAX_RX_REFRESH];
}  __aligned(CACHE_LINE_SIZE);
