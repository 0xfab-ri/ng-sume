/*	$FreeBSD: releng/12.1/sys/dev/sound/usb/uaudio.c 345544 2019-03-26 13:52:01Z hselasky $ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause-NetBSD
 *
 * Copyright (c) 1999 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (lennart@augustsson.net) at
 * Carlstedt Research & Technology.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.1/sys/dev/sound/usb/uaudio.c 345544 2019-03-26 13:52:01Z hselasky $");

#include <sys/param.h>
#include <sys/systm.h>
#ifdef DDB
#include <sys/types.h>
#include <ddb/ddb.h>
#endif
#if __FreeBSD_version >= 800000
#include <sys/buf_ring.h>
#endif
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/eventhandler.h>
#include <machine/bus.h>
#include <machine/resource.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/iflib.h>

#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <machine/in_cksum.h>
#include <dev/led/led.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net/iflib.h>
#include "ifdi_if.h"

/* netgraph stuff */
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/syslog.h>

#include <net/netisr.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include "ngf.h"

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

//#include <net/mp_ring.h>

/* START */

char ngf_driver_version[] = "0.0.0-a";

#define E1000_DEV_ID_82540EM			0x100E

static pci_vendor_info_t ngf_vendor_info_array[] =
{
        PVID(0x10ee, 0x7028, "Xilinx NetFPGA SUME"),
        /* required last entry */
        PVID_END
};

//static pci_vendor_info_t ngf_vendor_info_array[] =
//{
//	/* Intel(R) PRO/1000 Network Connection - Legacy em*/
//	PVID(0x8086, E1000_DEV_ID_82540EM, "Intel(R) PRO/1000 Network Connection"),
//	/* required last entry */
//	PVID_END
//};


/* prototypes */

int ngf_intr(void *arg);
static int	ngf_setup_interface(if_ctx_t ctx);
static void	ngf_if_init(if_ctx_t ctx);
static void	ngf_if_stop(if_ctx_t ctx);
static void	ngf_if_intr_enable(if_ctx_t ctx);
static void	ngf_if_intr_disable(if_ctx_t ctx);

static int	ngf_allocate_pci_resources(if_ctx_t ctx);
static void	ngf_free_pci_resources(if_ctx_t ctx);

//static device_probe_t ngf_probe;
static void *ngf_register(device_t dev);
//static int      ngf_device_attach(device_t dev);
//static int      ngf_device_detach(device_t dev);

static int      ngf_if_attach_pre(if_ctx_t ctx);
static int      ngf_if_attach_post(if_ctx_t ctx);

static int	ngf_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets);
static int	ngf_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets);
static void	ngf_if_queues_free(if_ctx_t ctx);

static uint64_t	ngf_if_get_counter(if_ctx_t, ift_counter);
static void	ngf_if_media_status(if_ctx_t, struct ifmediareq *);
static int	ngf_if_media_change(if_ctx_t ctx);
static void	ngf_if_timer(if_ctx_t ctx, uint16_t qid);
static void	ngf_if_update_admin_status(if_ctx_t ctx);
static int      ngf_if_detach(if_ctx_t ctx);

static int	ngf_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t rxqid);
static int	ngf_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t txqid);

static int	ngf_if_msix_intr_assign(if_ctx_t, int);
static int	ngf_msix_link(void *);
static void	ngf_handle_link(void *context);
///////////
static devclass_t ngf_devclass;

static device_method_t ngf_methods[] = {
	//DEVMETHOD(device_probe, ngf_probe),
	DEVMETHOD(device_register, ngf_register),
	DEVMETHOD(device_probe, iflib_device_probe),
	DEVMETHOD(device_attach, iflib_device_attach),
	DEVMETHOD(device_detach, iflib_device_detach),
	//DEVMETHOD(device_attach, ngf_device_attach),
	//DEVMETHOD(device_detach, ngf_device_detach),

	DEVMETHOD_END
};

static device_method_t ngf_if_methods[] = {
        DEVMETHOD(ifdi_attach_pre, ngf_if_attach_pre),
        DEVMETHOD(ifdi_attach_post, ngf_if_attach_post),
	DEVMETHOD(ifdi_detach, ngf_if_detach),
	DEVMETHOD(ifdi_init, ngf_if_init),
	DEVMETHOD(ifdi_stop, ngf_if_stop),
	DEVMETHOD(ifdi_msix_intr_assign, ngf_if_msix_intr_assign),
	DEVMETHOD(ifdi_intr_enable, ngf_if_intr_enable),
	DEVMETHOD(ifdi_intr_disable, ngf_if_intr_disable),
	DEVMETHOD(ifdi_tx_queues_alloc, ngf_if_tx_queues_alloc),
	DEVMETHOD(ifdi_rx_queues_alloc, ngf_if_rx_queues_alloc),
	DEVMETHOD(ifdi_queues_free, ngf_if_queues_free),
	DEVMETHOD(ifdi_update_admin_status, ngf_if_update_admin_status),
	//DEVMETHOD(ifdi_multi_set, em_if_multi_set),
	DEVMETHOD(ifdi_media_status, ngf_if_media_status),
	DEVMETHOD(ifdi_media_change, ngf_if_media_change),
	//DEVMETHOD(ifdi_mtu_set, em_if_mtu_set),
	//DEVMETHOD(ifdi_promisc_set, em_if_set_promisc),
	DEVMETHOD(ifdi_timer, ngf_if_timer),
	//DEVMETHOD(ifdi_watchdog_reset, em_if_watchdog_reset),
	//DEVMETHOD(ifdi_vlan_register, em_if_vlan_register),
	//DEVMETHOD(ifdi_vlan_unregister, em_if_vlan_unregister),
	DEVMETHOD(ifdi_get_counter, ngf_if_get_counter),
	//DEVMETHOD(ifdi_led_func, em_if_led_func),
	DEVMETHOD(ifdi_rx_queue_intr_enable, ngf_if_rx_queue_intr_enable),
	DEVMETHOD(ifdi_tx_queue_intr_enable, ngf_if_tx_queue_intr_enable),
	//DEVMETHOD(ifdi_debug, em_if_debug),

	DEVMETHOD_END
};

static driver_t ngf_if_driver = {
        "ngf_if", ngf_if_methods, sizeof(struct ngf_softc)
};

extern struct if_txrx ngf_txrx;

/* THIS? */
#define NF_TSO_SIZE 65536
#define NF_TSO_SEG_SIZE 4096
#define NF_MIN_TXD              128
#define NF_MAX_TXD              4096
#define NF_DEFAULT_TXD          1024
#define NF_MIN_RXD              128
#define NF_MAX_RXD              4096
#define NF_DEFAULT_RXD          1024

static struct if_shared_ctx ngf_sctx_init = {
        .isc_magic = IFLIB_MAGIC,
        .isc_q_align = PAGE_SIZE,
        .isc_tx_maxsize = NF_TSO_SIZE + sizeof(struct ether_vlan_header),
        .isc_tx_maxsegsize = PAGE_SIZE,
        .isc_tso_maxsize = NF_TSO_SIZE + sizeof(struct ether_vlan_header),
        .isc_tso_maxsegsize = NF_TSO_SEG_SIZE,
        .isc_rx_maxsize = MJUM9BYTES,
        .isc_rx_nsegments = 1,
        .isc_rx_maxsegsize = MJUM9BYTES,
        .isc_nfl = 1,
        .isc_nrxqs = 1,
        .isc_ntxqs = 1,
        .isc_admin_intrcnt = 1,
        .isc_vendor_info = ngf_vendor_info_array,
        .isc_driver_version = ngf_driver_version,
        .isc_driver = &ngf_if_driver,
        //.isc_flags = IFLIB_DRIVER_MEDIA, // NOT YET IN KERNEL
        //.isc_flags = IFLIB_VIRTUAL,
        //.isc_flags = IFLIB_SKIP_MSIX,

        .isc_nrxd_min = {NF_MIN_RXD},
        .isc_ntxd_min = {NF_MIN_TXD},
        .isc_nrxd_max = {NF_MAX_RXD},
        .isc_ntxd_max = {NF_MAX_TXD},
        .isc_nrxd_default = {NF_DEFAULT_RXD},
        .isc_ntxd_default = {NF_DEFAULT_TXD},
};

if_shared_ctx_t ngf_sctx = &ngf_sctx_init;

static driver_t ngf_driver = {
	.name = "ngf",
	.methods = ngf_methods,
	.size = sizeof(struct ngf_softc),
};

//DRIVER_MODULE_ORDERED(uaudio, uhub, uaudio_driver, uaudio_devclass, NULL, 0, SI_ORDER_ANY);
//DRIVER_MODULE(nf_if, ether, nf_if_driver, nf_if_devclass, 0, 0);
//MODULE_DEPEND(uaudio, usb, 1, 1, 1);
//MODULE_DEPEND(uaudio, sound, SOUND_MINVER, SOUND_PREFVER, SOUND_MAXVER);
//MODULE_VERSION(uaudio, 1);
DRIVER_MODULE(ngf, pci, ngf_driver, ngf_devclass, 0, 0);
MODULE_DEPEND(ngf, pci, 1, 1, 1);
MODULE_DEPEND(ngf, ether, 1, 1, 1);
MODULE_DEPEND(ngf, iflib, 1, 1, 1);
IFLIB_PNP_INFO(pci, ngf, ngf_vendor_info_array);

/*
DRIVER_MODULE(nf_if, ether, nf_if_driver, nf_if_devclass, 0, 0);
MODULE_DEPEND(nf_if, ether, 1, 1, 1);
MODULE_DEPEND(nf_if, iflib, 1, 1, 1);
*/

/* NF */
static const struct ng_cmdlist ng_ngf_cmdlist[] = {
	{
	  NGM_NGF_COOKIE,
	  NGM_NGF_GET_IFNAME,
	  "getifname",
	  NULL,
	  &ng_parse_string_type
	},
	{
	  NGM_NGF_COOKIE,
	  NGM_NGF_SET,
	  "set",
	  &ng_parse_enaddr_type,
	  NULL
	},
	{ 0 }
};

/* Interface methods */
//static void	ng_ngf_init(void *xsc);
//static void	ng_ngf_start(struct ifnet *ifp);
//static int	ng_ngf_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data);

/* Netgraph methods */
static int		ng_ngf_mod_event(module_t, int, void *);
//static ng_constructor_t	ng_ngf_constructor;
static ng_rcvmsg_t	ng_ngf_rcvmsg;
static ng_shutdown_t	ng_ngf_rmnode;
//static ng_newhook_t	ng_ngf_newhook;
static ng_rcvdata_t	ng_ngf_rcvdata;
//static ng_disconnect_t	ng_ngf_disconnect;

/* Node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_NGF_NODE_TYPE,
	.mod_event =	ng_ngf_mod_event,
	//.constructor =	ng_ngf_constructor,
	.rcvmsg =	ng_ngf_rcvmsg,
	.shutdown =	ng_ngf_rmnode,
	//.newhook =	ng_ngf_newhook,
	.rcvdata =	ng_ngf_rcvdata,
	//.disconnect =	ng_ngf_disconnect,
	.cmdlist =	ng_ngf_cmdlist
};

VNET_DEFINE_STATIC(struct unrhdr *, ng_ngf_unit);
#define	V_ng_ngf_unit		VNET(ng_ngf_unit)

/*
static void
vnet_ng_ngf_init(const void *unused)
{
printf("%s\n", __func__);

	V_ng_ngf_unit = new_unrhdr(0, 0xffff, NULL);
}

static void
vnet_ng_ngf_uninit(const void *unused)
{
printf("%s\n", __func__);
	//printf("Killing dev %s\n", device_get_name(adapter->dev));
	//printf("Killing %s\n", adapter->name);

	delete_unrhdr(V_ng_ngf_unit);
}
*/

/*
static int
ngf_probe(device_t dev)
{
printf("start: %s\n", __func__);
	printf("DEVNAME: %s\n", device_get_name(dev));
	printf("DEVVEND: 0x%04X\n", pci_get_vendor(dev));
	printf("DEVID  : 0x%04X\n", pci_get_device(dev));
	adapter=malloc(sizeof(*adapter), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (DEVICE_REGISTER(dev) == NULL)
		return (ENOTSUP);

	printf("ngf_probe dev: %p\n", dev);
printf("end: %s\n", __func__);
	return (ENXIO);
}
*/

static void *
ngf_register(device_t dev)
{
printf("start: %s\n", __func__);
	//struct ngf_softc *adapter;
	//adapter = device_get_softc(dev);
	//adapter->dev = dev;

	//adapter=malloc(sizeof(*adapter), M_DEVBUF, M_NOWAIT | M_ZERO);

	//VNET_SYSINIT(vnet_ng_ngf_init, SI_SUB_PSEUDO, SI_ORDER_ANY,
	    //vnet_ng_ngf_init, NULL);
	//VNET_SYSUNINIT(vnet_ng_ngf_uninit, SI_SUB_INIT_IF, SI_ORDER_ANY,
	   //vnet_ng_ngf_uninit, NULL);
printf("end: %s\n", __func__);
        return (ngf_sctx);
}

/*
 * Handle loading and unloading for this node type.
 */
static int
ng_ngf_mod_event(module_t mod, int event, void *data)
{
printf("%s\n", __func__);
	int error = 0;

	switch (event) {
	case MOD_LOAD:
	case MOD_UNLOAD:
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

/*
 * ifmedia stuff
 */
static int
ngf_if_media_change(if_ctx_t ctx)
{
printf("%s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);
	const priv_p priv = adapter->priv;
	struct ifmedia *ifm = &priv->media;

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);
	if (IFM_SUBTYPE(ifm->ifm_media) == IFM_AUTO)
		ifp->if_baudrate = ifmedia_baudrate(IFM_ETHER | IFM_1000_T);
	else
		ifp->if_baudrate = ifmedia_baudrate(ifm->ifm_media);

	//ngf_if_init(ctx);

	return (0);
}

/*
static void
ng_ngf_mediastatus(struct ifnet *ifp, struct ifmediareq *ifmr)
{
printf("%s\n", __func__);
	const priv_p priv = (priv_p)ifp->if_softc;
	struct ifmedia *ifm = &priv->media;

	if (ifm->ifm_cur->ifm_media == (IFM_ETHER | IFM_AUTO) &&
	    (priv->link_status & IFM_ACTIVE))
		ifmr->ifm_active = IFM_ETHER | IFM_1000_T | IFM_FDX;
	else
		ifmr->ifm_active = ifm->ifm_cur->ifm_media;
	ifmr->ifm_status = priv->link_status;

	return;
}
*/

/*
 * Constructor for a node
 */
static int
ng_ngf_constructor_my(node_p node, if_ctx_t ctx)
{
printf("%s\n", __func__); // XXX
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);
	//struct ifmedia ifm = iflib_get_media(ctx);
	//struct ifmedia *ifmp = iflib_get_mediap(ctx);
	u_char eaddr[6] = {0,1,3,5,7,9};

        /* Allocate node and interface private structures */
        adapter->priv = malloc(sizeof(*(adapter->priv)), M_NETGRAPH, M_WAITOK | M_ZERO);
	adapter->priv->ifp = ifp;
	//adapter->priv->media = ifm;
//        //ifp = priv->ifp = if_alloc(IFT_ETHER);

	printf("adapter->priv address = %p\n", adapter->priv);
	printf("adapter->ifp address = %p\n", adapter->priv->ifp);
 
//        if (ifp == NULL) {
//        	free(adapter->priv, M_NETGRAPH);
//        	return (ENOSPC);
//        }
  
        /* Link them together */
        //ifp->if_softc = adapter; // PANIC!
  
        /* Get an interface unit number */
        adapter->priv->unit = alloc_unr(V_ng_ngf_unit);
  
        /* Link together node and private info */
        NG_NODE_SET_PRIVATE(node, adapter->priv);
  
//        /* Initialize interface structure */
//        if_initname(ifp, NG_NGF_NGF_NAME, adapter->priv->unit);
        //ifp->if_init = ng_ngf_init;
//        ifp->if_output = ether_output;
//        ifp->if_start = ng_ngf_start;
//        ifp->if_ioctl = ng_ngf_ioctl;
//        ifp->if_flags = (IFF_SIMPLEX | IFF_BROADCAST | IFF_MULTICAST);
//        ifp->if_capabilities = IFCAP_VLAN_MTU | IFCAP_JUMBO_MTU;
//        ifp->if_capenable = IFCAP_VLAN_MTU | IFCAP_JUMBO_MTU;
        //ifmedia_init(&adapter->priv->media, 0, ng_ngf_mediachange,
            //ng_ngf_mediastatus);
        //ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_10_T, 0, NULL);
        //ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_10_T | IFM_FDX, 0, NULL);
        //ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_100_TX, 0, NULL);
        //ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_100_TX | IFM_FDX, 0, NULL);
        //ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_1000_T, 0, NULL);
        //ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
//        ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_10G_T | IFM_FDX, 0, NULL);
        //ifmedia_add(&adapter->priv->media, IFM_ETHER | IFM_AUTO, 0, NULL);
        //ifmedia_set(&adapter->priv->media, IFM_ETHER | IFM_AUTO);

	adapter->priv->media = *adapter->media;
        adapter->priv->link_status = IFM_AVALID;
  
        /* Give this node the same name as the interface (if possible) */
        if (ng_name_node(node, ifp->if_xname) != 0)
        	log(LOG_WARNING, "%s: can't acquire netgraph name\n",
        	    ifp->if_xname);

	iflib_set_mac(ctx, eaddr);
  
        /* Attach the interface */
        //ether_ifattach(ifp, eaddr);
        ifp->if_baudrate = ifmedia_baudrate(IFM_ETHER | IFM_1000_T);
  
        /* Done */
	return (0);
}

/*
 * Give our ok for a hook to be added
 */
/*
static int
ng_ngf_newhook(node_p node, hook_p hook, const char *name)
{
printf("%s\n", __func__);
	priv_p priv = NG_NODE_PRIVATE(node);
	struct ifnet *ifp = priv->ifp;

	if (strcmp(name, NG_NGF_HOOK_ETHER))
		return (EPFNOSUPPORT);
	if (priv->ether != NULL)
		return (EISCONN);
	priv->ether = hook;
	NG_HOOK_SET_PRIVATE(hook, &priv->ether);
	NG_HOOK_SET_TO_INBOUND(hook);

	priv->link_status |= IFM_ACTIVE;
	CURVNET_SET_QUIET(ifp->if_vnet);
	if_link_state_change(ifp, LINK_STATE_UP);
	CURVNET_RESTORE();

	return (0);
}
*/

/*
 * Receive a control message
 */
static int
ng_ngf_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
printf("%s\n", __func__);
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ifnet *const ifp = priv->ifp;
	struct ng_mesg *resp = NULL;
	int error = 0;
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
	switch (msg->header.typecookie) {
	case NGM_NGF_COOKIE:
		switch (msg->header.cmd) {

		case NGM_NGF_SET:
		    {
			if (msg->header.arglen != ETHER_ADDR_LEN) {
				error = EINVAL;
				break;
			}
			error = if_setlladdr(priv->ifp,
			    (u_char *)msg->data, ETHER_ADDR_LEN);
			break;
		    }

		case NGM_NGF_GET_IFNAME:
			NG_MKRESPONSE(resp, msg, IFNAMSIZ, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			strlcpy(resp->data, ifp->if_xname, IFNAMSIZ);
			break;

		case NGM_NGF_GET_IFADDRS:
		    {
			struct ifaddr *ifa;
			caddr_t ptr;
			int buflen;

			/* Determine size of response and allocate it */
			buflen = 0;
			if_addr_rlock(ifp);
			CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link)
				buflen += SA_SIZE(ifa->ifa_addr);
			NG_MKRESPONSE(resp, msg, buflen, M_NOWAIT);
			if (resp == NULL) {
				if_addr_runlock(ifp);
				error = ENOMEM;
				break;
			}

			/* Add addresses */
			ptr = resp->data;
			CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				const int len = SA_SIZE(ifa->ifa_addr);

				if (buflen < len) {
					log(LOG_ERR, "%s: len changed?\n",
					    ifp->if_xname);
					break;
				}
				bcopy(ifa->ifa_addr, ptr, len);
				ptr += len;
				buflen -= len;
			}
			if_addr_runlock(ifp);
			break;
		    }

		default:
			error = EINVAL;
			break;
		} /* end of inner switch() */
		break;
	case NGM_FLOW_COOKIE:
		CURVNET_SET_QUIET(ifp->if_vnet);
		switch (msg->header.cmd) {
		case NGM_LINK_IS_UP:
			priv->link_status |= IFM_ACTIVE;
			if_link_state_change(ifp, LINK_STATE_UP);
			break;
		case NGM_LINK_IS_DOWN:
			priv->link_status &= ~IFM_ACTIVE;
			if_link_state_change(ifp, LINK_STATE_DOWN);
			break;
		default:
			break;
		}
		CURVNET_RESTORE();
		break;
	default:
		error = EINVAL;
		break;
	}
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);
	return (error);
}

/*
 * Receive data from a hook. Pass the packet to the ether_input routine.
 */
static int
ng_ngf_rcvdata(hook_p hook, item_p item)
{
printf("%s\n", __func__);
	const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct ifnet *const ifp = priv->ifp;
	struct mbuf *m;
	//if_ctx_t ctx = ifp->if_softc;
	//struct ngf_softc *adapter = iflib_get_softc(ctx);
	if (hook != NULL) {
		priv->ether = hook;
	} else {
		return (ENETDOWN);
	}

	//struct ngf_softc *adapter = iflib_get_softc(ctx);
	//ngf_intr(adapter);
	NGI_GET_M(item, m);
	NG_FREE_ITEM(item);

	if (!((ifp->if_flags & IFF_UP) &&
	    (ifp->if_drv_flags & IFF_DRV_RUNNING))) {
		NG_FREE_M(m);
		return (ENETDOWN);
	}

	if (m->m_len < ETHER_HDR_LEN) {
		m = m_pullup(m, ETHER_HDR_LEN);
		if (m == NULL)
			return (EINVAL);
	}

	/* Note receiving interface */
	m->m_pkthdr.rcvif = ifp;

	/* Update interface stats */
	if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);

	(*ifp->if_input)(ifp, m);

	/* Done */
	return (0);
}

/*
 * Shutdown processing.
 */
static int
ng_ngf_rmnode(node_p node)
{
printf("start: %s\n", __func__);
	const priv_p priv = NG_NODE_PRIVATE(node);
	printf("adapter->node %p\n", node);

	//struct ifnet *const ifp = priv->ifp;
	/*
	 * the ifnet may be in a different vnet than the netgraph node, 
	 * hence we have to change the current vnet context here.
	 */
	//CURVNET_SET_QUIET(ifp->if_vnet);
	ifmedia_removeall(&priv->media);
	//ether_ifdetach(ifp);
	//if_free(ifp);
	//CURVNET_RESTORE();
	free_unr(V_ng_ngf_unit, priv->unit);
	free(priv, M_NETGRAPH);
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
printf("end: %s\n", __func__);
	return (0);
}

/*
 * Hook disconnection
 */
/*
static int
ng_ngf_disconnect(hook_p hook)
{
printf("%s\n", __func__);
	if (hook == NULL)
		return (0);

	const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));

	priv->ether = NULL;
	priv->link_status &= ~IFM_ACTIVE;
	CURVNET_SET_QUIET(priv->ifp->if_vnet);
	if_link_state_change(priv->ifp, LINK_STATE_DOWN);
	CURVNET_RESTORE();
	return (0);
}
*/

/* !NF */

/* NGFX */
///*
// * Process an ioctl for the virtual interface
// */
//static int
//ng_ngf_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
//{
//printf("%s\n", __func__);
//	const priv_p priv = (priv_p)ifp->if_softc;
//	struct ifreq *const ifr = (struct ifreq *)data;
//	int error = 0;
//
//	switch (command) {
//	/* These two are mostly handled at a higher layer */
//	case SIOCSIFADDR:
//		error = ether_ioctl(ifp, command, data);
//		break;
//	case SIOCGIFADDR:
//		break;
//
//	/* Set flags */
//	case SIOCSIFFLAGS:
//		/*
//		 * If the interface is marked up and stopped, then start it.
//		 * If it is marked down and running, then stop it.
//		 */
//		if (ifp->if_flags & IFF_UP) {
//			if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
//				ifp->if_drv_flags &= ~(IFF_DRV_OACTIVE);
//				ifp->if_drv_flags |= IFF_DRV_RUNNING;
//			}
//		} else {
//			if (ifp->if_drv_flags & IFF_DRV_RUNNING)
//				ifp->if_drv_flags &= ~(IFF_DRV_RUNNING |
//				    IFF_DRV_OACTIVE);
//		}
//		break;
//
//	/* Set the interface MTU */
//	case SIOCSIFMTU:
//		if (ifr->ifr_mtu > NG_NGF_MTU_MAX ||
//		    ifr->ifr_mtu < NG_NGF_MTU_MIN)
//			error = EINVAL;
//		else
//			ifp->if_mtu = ifr->ifr_mtu;
//		break;
//
//	/* (Fake) media type manipulation */
//	case SIOCSIFMEDIA:
//	case SIOCGIFMEDIA:
//		error = ifmedia_ioctl(ifp, ifr, &priv->media, command);
//		break;
//
//	/* Stuff that's not supported */
//	case SIOCADDMULTI:
//	case SIOCDELMULTI:
//		error = 0;
//		break;
//	case SIOCSIFPHYS:
//		error = EOPNOTSUPP;
//		break;
//
//	default:
//		error = EINVAL;
//		break;
//	}
//	return (error);
//}

/*
static void
ng_ngf_init(void *xsc)
{
printf("%s\n", __func__);
	priv_p sc = xsc;
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}
*/

///*
// * We simply relay the packet to the "ether" hook, if it is connected.
// * We have been through the netgraph locking and are guaranteed to
// * be the only code running in this node at this time.
// */
//static void
//ng_ngf_start2(node_p node, hook_p hook, void *arg1, int arg2)
//{
//printf("%s\n", __func__);
//	struct ifnet *ifp = arg1;
//	const priv_p priv = (priv_p)ifp->if_softc;
//	int error = 0;
//	struct mbuf *m;
//
//	/* Check interface flags */
//
//	if (!((ifp->if_flags & IFF_UP) &&
//	    (ifp->if_drv_flags & IFF_DRV_RUNNING)))
//		return;
//
//	for (;;) {
//		/*
//		 * Grab a packet to transmit.
//		 */
//		IF_DEQUEUE(&ifp->if_snd, m);
//
//		/* If there's nothing to send, break. */
//		if (m == NULL)
//			break;
//
//		/* Peel the mbuf off any stale tags */
//		m_tag_delete_chain(m, NULL);
//
//		/*
//		 * Berkeley packet filter.
//		 * Pass packet to bpf if there is a listener.
//		 * XXX is this safe? locking?
//		 */
//		BPF_MTAP(ifp, m);
//
//		if (ifp->if_flags & IFF_MONITOR) {
//			if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);
//			m_freem(m);
//			continue;
//		}
//
//		/*
//		 * Send packet; if hook is not connected, mbuf will get
//		 * freed.
//		 */
//		NG_OUTBOUND_THREAD_REF();
//		NG_SEND_DATA_ONLY(error, priv->ether, m);
//		NG_OUTBOUND_THREAD_UNREF();
//
//		/* Update stats */
//		if (error == 0)
//			if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
//		else
//			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
//	}
//
//	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
//
//	return;
//}
//
///*
// * This routine is called to deliver a packet out the interface.
// * We simply queue the netgraph version to be called when netgraph locking
// * allows it to happen.
// * Until we know what the rest of the networking code is doing for
// * locking, we don't know how we will interact with it.
// * Take comfort from the fact that the ifnet struct is part of our
// * private info and can't go away while we are queued.
// * [Though we don't know it is still there now....]
// * it is possible we don't gain anything from this because
// * we would like to get the mbuf and queue it as data
// * somehow, but we can't and if we did would we solve anything?
// */
//static void
//ng_ngf_start(struct ifnet *ifp)
//{
//printf("%s\n", __func__);
//	const priv_p priv = (priv_p)ifp->if_softc;
//
//	/* Don't do anything if output is active */
//	if (ifp->if_drv_flags & IFF_DRV_OACTIVE)
//		return;
//
//	ifp->if_drv_flags |= IFF_DRV_OACTIVE;
//
//	if (ng_send_fn(priv->node, NULL, &ng_ngf_start2, ifp, 0) != 0)
//		ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
//}
/* !NGFX */

/*
static int
ngf_device_attach(device_t dev)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter;
	adapter = device_get_softc(dev);
	//node_p node;
	printf("ngf_device_attach dev: %p\n", dev);
	V_ng_ngf_unit = new_unrhdr(0, 0xffff, NULL);
	//printf("ng_findtype(typestruct.name): %p\n", ng_findtype(typestruct.name));
	int err = ng_make_node_common(&typestruct, &adapter->node);
	if (err)
		return (err);

	printf("adapter->node: %p\n", &adapter->node);
	err = ng_ngf_constructor_my(adapter->node);
	if (err)
		return (err);

	//err = ng_ngf_newhook(adapter->node, adapter->hook, "ether");
	//if (err)
		//return (err);

printf("end: %s\n", __func__);
	return (0);
}
*/

/*
static int
ngf_device_detach(device_t dev)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter;
	adapter = device_get_softc(dev);
	//ng_ngf_disconnect_my(adapter->node);
	//ng_ngf_disconnect(adapter->hook);
	ng_ngf_rmnode(adapter->node);	
	delete_unrhdr(V_ng_ngf_unit);
printf("end: %s\n", __func__);
	return (0);
}
*/

static int
ngf_if_attach_pre(if_ctx_t ctx)
{
printf("%s\n", __func__);
	NETGRAPH_INIT_ORDERED(ngf, &typestruct, SI_SUB_DRIVERS, SI_ORDER_FIRST);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	device_t dev = iflib_get_dev(ctx);
	printf("adapter address = %p\n", adapter);

	adapter->ctx = adapter->osdep.ctx = ctx;
	adapter->dev = adapter->osdep.dev = dev;
	printf("ngf_device_attach_pre adapter->dev: %p\n", adapter->dev);

	V_ng_ngf_unit = new_unrhdr(0, 0xffff, NULL);

	if_softc_ctx_t scctx;	
	scctx = adapter->shared = iflib_get_softc_ctx(ctx);
	adapter->media = iflib_get_media(ctx);
	printf("adapter->shared: %p\n", &adapter->shared);

	//struct f_iflib_txq *tmp = (struct f_iflib_txq *) ctx->ifc_txqs;
	//struct f_iflib_txq *tmp = (struct f_iflib_txq *)(&adapter+sizeof(struct sx)+sizeof(struct mtx));
	//bcopy(&adapter->txq, *tmp, sizeof(struct f_iflib_txq));
	//adapter->txq = (struct f_iflib_txq *)(&adapter+sizeof(struct ngf_softc) + sizeof(struct sx) + sizeof(struct mtx));
	//adapter->m = *adapter->txq->ift_sds.ifsd_m;

	//int size = sizeof(qidx_t)*4+sizeof(uint8_t)*2+sizeof(uint16_t)*3+sizeof(uint8_t)+sizeof(uint64_t)*11+sizeof(struct mtx)*2 \
		   //+ sizeof(if_ctx_t)+sizeof(struct ifmp_ring)+sizeof(struct grouptask)+sizeof(qidx_t)+sizeof(uint16_t)+sizeof(struct callout);
	//int size = &adapter+sizeof(struct sx)+sizeof(struct mtx);

	//printf("SIZE: %d\n", size);

	/*
	for (int i=0; i < 8; i++) {
		printf("scctx->isc_nrxd[%d] = %d\n", i, scctx->isc_nrxd[i]);
	}
	*/
	//printf("scctx->isc_intr (LEGACY = 0) = %d\n", scctx->isc_intr);
	//printf("scctx->isc_vectors = %d\n", scctx->isc_vectors);
	//printf("scctx->isc_nrxqsets = %d\n", scctx->isc_nrxqsets); // 0
	//printf("scctx->isc_ntxqsets = %d\n", scctx->isc_ntxqsets); // 0

	int err = ng_make_node_common(&typestruct, &adapter->node);
	if (err)
		return (err);

	printf("adapter->node: %p\n", &adapter->node);

	scctx->isc_tx_nsegments = 85; // 1024/12 = 85
	scctx->isc_nrxqsets_max = scctx->isc_ntxqsets_max = 1;
	scctx->isc_txqsizes[0] = scctx->isc_rxqsizes[0] = 1024;
	scctx->isc_txd_size[0] = scctx->isc_rxd_size[0] = 80;
	scctx->isc_txrx = &ngf_txrx;

	scctx->isc_tx_tso_segments_max = 85; // 1024/12 = 85
	scctx->isc_tx_tso_size_max = NF_TSO_SIZE;
	scctx->isc_tx_tso_segsize_max = NF_TSO_SEG_SIZE;
	scctx->isc_capabilities = scctx->isc_capenable = 0;

	scctx->isc_msix_bar = PCIR_BAR(0);
	if (pci_read_config(dev, scctx->isc_msix_bar, 4) == 0)
		scctx->isc_msix_bar += 4;

	err = ng_ngf_constructor_my(adapter->node, ctx);
	if (err) {
		printf("ng_ngf_constructor_my err %d\n", err);
		ng_ngf_rmnode(adapter->node);	
		delete_unrhdr(V_ng_ngf_unit);
		return (err);
	}

	/* Setup PCI resources */
	if (ngf_allocate_pci_resources(ctx)) {
		device_t dev = iflib_get_dev(ctx);
		device_printf(dev, "Allocation of PCI resources failed\n");
		err = ENXIO;
		goto err_pci;
	}

	//ngf_if_msix_intr_assign(ctx, 2);
	return (0);

err_pci:
	ngf_free_pci_resources(ctx);

	return (err);
}

static int
ngf_if_attach_post(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	//struct ngf_softc *adapter = iflib_get_softc(ctx);
	//struct e1000_hw *hw = &adapter->hw;
	int error = 0;
	
	/* Setup OS specific network interface */
	error = ngf_setup_interface(ctx);
	if (error != 0) {
		goto err_late;
	}

	//em_reset(ctx);

	/* Initialize statistics */
	//em_update_stats_counters(adapter);
	//hw->mac.get_link_status = 1;
	ngf_if_update_admin_status(ctx);
	//em_add_hw_stats(adapter);

	//ngf_if_msix_intr_assign(ctx, 2);
	/* Non-AMT based hardware can now take control from firmware */
	//if (adapter->has_manage && !adapter->has_amt)
		//em_get_hw_control(adapter);

printf("end: %s\n", __func__);
	return (error);

err_late:
	ngf_free_pci_resources(ctx);
	ngf_if_queues_free(ctx);
	//free(adapter->mta, M_DEVBUF);

	return (error);
}

/*********************************************************************
 *
 *  Setup networking device structure and register interface media.
 *
 **********************************************************************/
static int
ngf_setup_interface(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;

	/* Single Queue */
	if (adapter->tx_num_queues == 1) {
		if_setsendqlen(ifp, scctx->isc_ntxd[0] - 1);
		if_setsendqready(ifp);
	}

	/*
	 * Specify the media types supported by this adapter and register
	 * callbacks to update media and link information
	 */
	ifmedia_add(adapter->media, IFM_ETHER | IFM_10_T, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_10_T | IFM_FDX, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_100_TX, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_100_TX | IFM_FDX, 0, NULL);

	ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_T, 0, NULL);

	ifmedia_add(adapter->media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(adapter->media, IFM_ETHER | IFM_AUTO);

printf("end: %s\n", __func__);
	return (0);
}

/*********************************************************************
 *  Init entry point
 *
 *  This routine is used in two ways. It is used by the stack as
 *  init entry point in network interface structure. It is also used
 *  by the driver as a hw/sw initialization routine to get to a
 *  consistent state.
 *
 **********************************************************************/
static void
ngf_if_init(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct ngf_tx_queue *tx_que;
	int i;

	adapter->priv->link_status |= IFM_ACTIVE;

	if (ifp->if_flags & IFF_UP) {
		if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
			ifp->if_drv_flags &= ~(IFF_DRV_OACTIVE);
			ifp->if_drv_flags |= IFF_DRV_RUNNING;
		}
	}

	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		printf("IFF_DRV_RUNNING\n");

	if (ifp->if_drv_flags & IFF_DRV_OACTIVE)
		printf("IFF_DRV_OACTIVE\n");

	//if ((ctx)->ifc_link_state == LINK_STATE_UP)
		//printf("LINK_STATE_UP\n");

	/* Get the latest mac address, User can use a LAA */
	//bcopy(if_getlladdr(ifp), adapter->hw.mac.addr,
	    //ETHER_ADDR_LEN);

	/* Put the address into the Receive Address Array */
	//e1000_rar_set(&adapter->hw, adapter->hw.mac.addr, 0);

	/*
	 * With the 82571 adapter, RAR[0] may be overwritten
	 * when the other port is reset, we make a duplicate
	 * in RAR[14] for that eventuality, this assures
	 * the interface continues to function.
	 */
	//if (adapter->hw.mac.type == e1000_82571) {
		//e1000_set_laa_state_82571(&adapter->hw, TRUE);
		//e1000_rar_set(&adapter->hw, adapter->hw.mac.addr,
		    //E1000_RAR_ENTRIES - 1);
	//}


	/* Initialize the hardware */
	//em_reset(ctx);
	ngf_if_update_admin_status(ctx);

	for (i = 0, tx_que = adapter->tx_queues; i < adapter->tx_num_queues; i++, tx_que++) {
		struct tx_ring *txr = &tx_que->txr;

		txr->tx_rs_cidx = txr->tx_rs_pidx;
		printf("txr->tx_rs_cidx = %hx\n", txr->tx_rs_cidx);

		/* Initialize the last processed descriptor to be the end of
		 * the ring, rather than the start, so that we avoid an
		 * off-by-one error when calculating how many descriptors are
		 * done in the credits_update function.
		 */
		txr->tx_cidx_processed = scctx->isc_ntxd[0] - 1;
		printf("txr->tx_cidx_processed = %hx\n", txr->tx_cidx_processed);
	}

	/* Setup VLAN support, basic and offload if available */
	//E1000_WRITE_REG(&adapter->hw, E1000_VET, ETHERTYPE_VLAN);

	/* Clear bad data from Rx FIFOs */
	//if (adapter->hw.mac.type >= igb_mac_min)
		//e1000_rx_fifo_flush_82575(&adapter->hw);

	/* Configure for OS presence */
	//em_init_manageability(adapter);

	/* Prepare transmit descriptors and buffers */
	//em_initialize_transmit_unit(ctx);

	/* Setup Multicast table */
	//em_if_multi_set(ctx);

	adapter->rx_mbuf_sz = iflib_get_rx_mbuf_sz(ctx);
	adapter->txq = ctx->ifc_txqs;
	//em_initialize_receive_unit(ctx);

	/* Use real VLAN Filter support? */
//	if (if_getcapenable(ifp) & IFCAP_VLAN_HWTAGGING) {
//		if (if_getcapenable(ifp) & IFCAP_VLAN_HWFILTER)
//			/* Use real VLAN Filter support */
//			em_setup_vlan_hw_support(adapter);
//		else {
//			u32 ctrl;
//			ctrl = E1000_READ_REG(&adapter->hw, E1000_CTRL);
//			ctrl |= E1000_CTRL_VME;
//			E1000_WRITE_REG(&adapter->hw, E1000_CTRL, ctrl);
//		}
//	}

	/* Don't lose promiscuous settings */
	//em_if_set_promisc(ctx, IFF_PROMISC);
	//e1000_clear_hw_cntrs_base_generic(&adapter->hw);

	/* MSI-X configuration for 82574 */
//	if (adapter->hw.mac.type == e1000_82574) {
//		int tmp = E1000_READ_REG(&adapter->hw, E1000_CTRL_EXT);
//
//		tmp |= E1000_CTRL_EXT_PBA_CLR;
//		E1000_WRITE_REG(&adapter->hw, E1000_CTRL_EXT, tmp);
//		/* Set the IVAR - interrupt vector routing. */
//		E1000_WRITE_REG(&adapter->hw, E1000_IVAR, adapter->ivars);
//	} else if (adapter->intr_type == IFLIB_INTR_MSIX) /* Set up queue routing */
//		igb_configure_queues(adapter);

	/* this clears any pending interrupts */
	//E1000_READ_REG(&adapter->hw, E1000_ICR);
	//E1000_WRITE_REG(&adapter->hw, E1000_ICS, E1000_ICS_LSC);

	/* AMT based hardware can now take control from firmware */
	//if (adapter->has_manage && adapter->has_amt)
		//em_get_hw_control(adapter);

	/* Set Energy Efficient Ethernet */
//	if (adapter->hw.mac.type >= igb_mac_min &&
//	    adapter->hw.phy.media_type == e1000_media_type_copper) {
//		if (adapter->hw.mac.type == e1000_i354)
//			e1000_set_eee_i354(&adapter->hw, TRUE, TRUE);
//		else
//			e1000_set_eee_i350(&adapter->hw, TRUE, TRUE);
//	}
}

/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC.
 *
 **********************************************************************/
static void
ngf_if_stop(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);

	adapter->priv->link_status &= ~IFM_ACTIVE;

	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		ifp->if_drv_flags &= ~(IFF_DRV_RUNNING |
		    IFF_DRV_OACTIVE);

printf("end: %s\n", __func__);
//	e1000_reset_hw(&adapter->hw);
//	if (adapter->hw.mac.type >= e1000_82544)
//		E1000_WRITE_REG(&adapter->hw, E1000_WUFC, 0);
//
//	e1000_led_off(&adapter->hw);
//	e1000_cleanup_led(&adapter->hw);
}

static int
ngf_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets)
{
printf("start: %s\n", __func__);

	struct ngf_softc *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	int error = 0;
	struct ngf_tx_queue *que;
	int i, j;

	//uint64_t *my_paddrs = malloc(sizeof(uint64_t)*ntxqsets*ntxqs, M_DEVBUF, M_WAITOK);

	MPASS(adapter->tx_num_queues > 0);
	MPASS(adapter->tx_num_queues == ntxqsets);

	/* First allocate the top level queue structs */
	if (!(adapter->tx_queues =
	    (struct ngf_tx_queue *) malloc(sizeof(struct ngf_tx_queue) *
	    adapter->tx_num_queues, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(iflib_get_dev(ctx), "Unable to allocate queue memory\n");
		return(ENOMEM);
	}

	for (i = 0, que = adapter->tx_queues; i < adapter->tx_num_queues; i++, que++) {
		/* Set up some basics */

		struct tx_ring *txr = &que->txr;
		txr->adapter = que->adapter = adapter;
		que->me = txr->me =  i;

		/* Allocate report status array */
		if (!(txr->tx_rsq = (qidx_t *) malloc(sizeof(qidx_t) * scctx->isc_ntxd[0], M_DEVBUF, M_NOWAIT | M_ZERO))) {
			device_printf(iflib_get_dev(ctx), "failed to allocate rs_idxs memory\n");
			error = ENOMEM;
			goto fail;
		}
		for (j = 0; j < scctx->isc_ntxd[0]; j++)
			txr->tx_rsq[j] = QIDX_INVALID;
		/* get the virtual and physical address of the hardware queues */
		txr->tx_base = (struct ngf_tx_desc *)vaddrs[i*ntxqs];
		//printf("txr->tx_base = %p\n", txr->tx_base);
		//printf("txr->tx_base[0].buffer_addr = %lx\n", txr->tx_base[0].buffer_addr);
		//txr->tx_my_paddr = (uint64_t)&my_paddrs[i*ntxqs];
		txr->tx_paddr = paddrs[i*ntxqs];
		//printf("txr->tx_paddr = 0x%lx\n", txr->tx_paddr);
	}

	//adapter->txq = (struct f_iflib_txq *)(&adapter+sizeof(struct sx)+sizeof(struct mtx));
	//adapter->txq = ctx->ifc_txqs;
	//adapter->txq->ift_sds.ifsd_m = (struct mbuf **) malloc(sizeof(struct mbuf *) * scctx->isc_ntxd[0], M_DEVBUF, M_NOWAIT | M_ZERO);
	//printf("adapter->txq->ift_sds.ifsd_m = %p\n", adapter->txq->ift_sds.ifsd_m);
	//adapter->m = *adapter->txq->ift_sds.ifsd_m;

	printf("adapter address = %p\n", adapter);
	printf("adapter->tx_queues address = %p\n", adapter->tx_queues);
	printf("adapter->tx_queues->txr address = %p\n", &adapter->tx_queues->txr);
	printf("adapter->tx_queues->txr.tx_base[0] descriptor address = %p\n", &adapter->tx_queues->txr.tx_base[0]);
	printf("adapter->tx_queues->txr.tx_base[0]->buffer_addr value = %lu\n", adapter->tx_queues->txr.tx_base[0].buffer_addr);

	device_printf(iflib_get_dev(ctx),
	    "allocated for %d tx_queues\n", adapter->tx_num_queues);

printf("end: %s\n", __func__);
	return (0);
fail:
	ngf_if_queues_free(ctx);
printf("end: %s\n", __func__);
	return (error);
}

static int
ngf_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets)
{
	printf("%s\n", __func__);
	
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	int error = 0;
	struct ngf_rx_queue *que;
	int i;

	MPASS(adapter->rx_num_queues > 0);
	MPASS(adapter->rx_num_queues == nrxqsets);

	/* First allocate the top level queue structs */
	if (!(adapter->rx_queues =
	    (struct ngf_rx_queue *) malloc(sizeof(struct ngf_rx_queue) *
	    adapter->rx_num_queues, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(iflib_get_dev(ctx), "Unable to allocate queue memory\n");
		error = ENOMEM;
		goto fail;
	}

	for (i = 0, que = adapter->rx_queues; i < nrxqsets; i++, que++) {
		/* Set up some basics */
		struct rx_ring *rxr = &que->rxr;
		rxr->adapter = que->adapter = adapter;
		rxr->que = que;
		que->me = rxr->me =  i;

		/* get the virtual and physical address of the hardware queues */
		rxr->rx_base = (struct ngf_rx_desc *)vaddrs[i*nrxqs];
		rxr->rx_paddr = paddrs[i*nrxqs];
	}
 
	printf("adapter address = %p\n", adapter);
	printf("adapter->rx_queues address = %p\n", adapter->rx_queues);
	printf("adapter->rx_queues->rxr address = %p\n", &adapter->rx_queues->rxr);
	printf("adapter->rx_queues->rxr.rx_base[0] descriptor address = %p\n", &adapter->rx_queues->rxr.rx_base[0]);
	printf("adapter->rx_queues->rxr.rx_base[0]->buffer_addr value = %lu\n", adapter->rx_queues->rxr.rx_base[0].buffer_addr);

	device_printf(iflib_get_dev(ctx),
	    "allocated for %d rx_queues\n", adapter->rx_num_queues);

printf("end: %s\n", __func__);
	return (0);
fail:
	ngf_if_queues_free(ctx);
printf("end: %s\n", __func__);
	return (error);
}

static void
ngf_if_queues_free(if_ctx_t ctx)
{
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	struct ngf_tx_queue *tx_que = adapter->tx_queues;
	struct ngf_rx_queue *rx_que = adapter->rx_queues;

	if (tx_que != NULL) {
		for (int i = 0; i < adapter->tx_num_queues; i++, tx_que++) {
			struct tx_ring *txr = &tx_que->txr;
			if (txr->tx_rsq == NULL)
				break;

			free(txr->tx_rsq, M_DEVBUF);
			txr->tx_rsq = NULL;
		}
		free(adapter->tx_queues, M_DEVBUF);
		adapter->tx_queues = NULL;
	}

	if (rx_que != NULL) {
		free(adapter->rx_queues, M_DEVBUF);
		adapter->rx_queues = NULL;
	}

	//ngf_release_hw_control(adapter);

	/*
	if (adapter->mta != NULL) {
		free(adapter->mta, M_DEVBUF);
	}
	*/
}

int
ngf_intr(void *arg)
{
printf("%s\n", __func__);
	struct ngf_softc *adapter = arg;
	if_ctx_t ctx = adapter->ctx;

	/*
	 * Only MSI-X interrupts have one-shot behavior by taking advantage
	 * of the EIAC register.  Thus, explicitly disable interrupts.  This
	 * also works around the MSI message reordering errata on certain
	 * systems.
	 */
	IFDI_INTR_DISABLE(ctx);

	if (adapter->link_active) {
		adapter->priv->link_status = 1;
		iflib_admin_intr_deferred(ctx);
	}

	return (FILTER_SCHEDULE_THREAD);
}

static uint64_t
ngf_if_get_counter(if_ctx_t ctx, ift_counter cnt)
{
	if ((int) cnt + 1 % 100 == 0) {
		printf("%s\n", __func__);
		printf("counter = %d\n", cnt);
	}

	return (1);

	/*
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);

	switch (cnt) {
	case IFCOUNTER_COLLISIONS:
		return (adapter->stats.colc);
	case IFCOUNTER_IERRORS:
		return (adapter->dropped_pkts + adapter->stats.rxerrc +
		    adapter->stats.crcerrs + adapter->stats.algnerrc +
		    adapter->stats.ruc + adapter->stats.roc +
		    adapter->stats.mpc + adapter->stats.cexterr);
	case IFCOUNTER_OERRORS:
		return (adapter->stats.ecol + adapter->stats.latecol +
		    adapter->watchdog_events);
	default:
		return (if_get_counter_default(ifp, cnt));
	}
	*/
}

static int
ngf_if_detach(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	ng_ngf_rmnode(adapter->node);	
	delete_unrhdr(V_ng_ngf_unit);
	ngf_free_pci_resources(ctx);
	ngf_if_queues_free(ctx);
printf("end: %s\n", __func__);
	return (0);
}

/*********************************************************************
 *
 *  Media Ioctl callback
 *
 *  This routine is called whenever the user queries the status of
 *  the interface using ifconfig.
 *
 **********************************************************************/
static void
ngf_if_media_status(if_ctx_t ctx, struct ifmediareq *ifmr)
{
//printf("start: %s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	const priv_p priv = adapter->priv;
	struct ifmedia *ifm = adapter->media;
	//struct ifmedia *ifm = &priv->media;

	iflib_admin_intr_deferred(ctx);

	//ifmr->ifm_status |= IFM_ACTIVE;
	//ifmr->ifm_status |= IFM_AVALID;
	//ifmr->ifm_active |= IFM_ETHER;

	//return;

	if (ifm->ifm_cur->ifm_media == (IFM_ETHER | IFM_AUTO) &&
	    (priv->link_status & IFM_ACTIVE))
		ifmr->ifm_active = IFM_ETHER | IFM_1000_T | IFM_FDX;
	else
		ifmr->ifm_active = ifm->ifm_cur->ifm_media;
	ifmr->ifm_status = priv->link_status;

//printf("end: %s\n", __func__);
	return;
}

static void
ngf_if_intr_enable(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	//struct ngf_softc *adapter = iflib_get_softc(ctx);
	//struct e1000_hw *hw = &adapter->hw;
	//u32 ims_mask = IMS_ENABLE_MASK;

	//if (hw->mac.type == e1000_82574) {
		//E1000_WRITE_REG(hw, EM_EIAC, EM_MSIX_MASK);
		//ims_mask |= adapter->ims;
	//}
	//E1000_WRITE_REG(hw, E1000_IMS, ims_mask);
printf("end: %s\n", __func__);
}

static void
ngf_if_intr_disable(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;

	printf("scctx->isc_intr (LEGACY = 0) = %d\n", scctx->isc_intr);
	printf("scctx->isc_vectors = %d\n", scctx->isc_vectors);
	printf("scctx->isc_msix_bar = %d\n", scctx->isc_msix_bar);


	//struct ngf_softc *adapter = iflib_get_softc(ctx);
	//struct e1000_hw *hw = &adapter->hw;

	//if (hw->mac.type == e1000_82574)
		//E1000_WRITE_REG(hw, EM_EIAC, 0);
	//E1000_WRITE_REG(hw, E1000_IMC, 0xffffffff);
printf("end: %s\n", __func__);
}

/*********************************************************************
 *  Timer routine
 *
 *  This routine schedules ngf_if_update_admin_status() to check for
 *  link status and to gather statistics as well as to perform some
 *  controller-specific hardware patting.
 *
 **********************************************************************/
static void
ngf_if_timer(if_ctx_t ctx, uint16_t qid)
{
printf("start: %s\n", __func__);
	printf("%s\n", __func__);

	if (qid != 0)
		return;

	iflib_admin_intr_deferred(ctx);
printf("end: %s\n", __func__);
}

static void
ngf_if_update_admin_status(if_ctx_t ctx)
{
	printf("%s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	//device_t dev = iflib_get_dev(ctx);
	//u32 thstat, ctrl;

	/* Get the cached link value or read phy for real */
//	switch (hw->phy.media_type) {
//	case e1000_media_type_copper:
//		if (hw->mac.get_link_status) {
//			if (hw->mac.type == e1000_pch_spt)
//				msec_delay(50);
//			/* Do the work to read phy */
//			e1000_check_for_link(hw);
//			link_check = !hw->mac.get_link_status;
//			if (link_check) /* ESB2 fix */
//				e1000_cfg_on_link_up(hw);
//		} else {
//			link_check = TRUE;
//		}
//		break;
//	case e1000_media_type_fiber:
//		e1000_check_for_link(hw);
//		link_check = (E1000_READ_REG(hw, E1000_STATUS) &
//			    E1000_STATUS_LU);
//		break;
//	case e1000_media_type_internal_serdes:
//		e1000_check_for_link(hw);
//		link_check = adapter->hw.mac.serdes_has_link;
//		break;
//	/* VF device is type_unknown */
//	case e1000_media_type_unknown:
//		e1000_check_for_link(hw);
//		link_check = !hw->mac.get_link_status;
//		/* FALLTHROUGH */
//	default:
//		break;
//	}

//	/* Check for thermal downshift or shutdown */
//	if (hw->mac.type == e1000_i350) {
//		thstat = E1000_READ_REG(hw, E1000_THSTAT);
//		ctrl = E1000_READ_REG(hw, E1000_CTRL_EXT);
//	}

	/* Now check for a transition */
	//printf("adapter->priv->link_status = %d\n", adapter->priv->link_status);
	if (!(adapter->priv->link_status == 0)) {
		adapter->link_speed = 1000;
		adapter->link_duplex = 2;
//		e1000_get_speed_and_duplex(hw, &adapter->link_speed,
//		    &adapter->link_duplex);
//		/* Check if we must disable SPEED_MODE bit on PCI-E */
//		if ((adapter->link_speed != SPEED_1000) &&
//		    ((hw->mac.type == e1000_82571) ||
//		    (hw->mac.type == e1000_82572))) {
//			int tarc0;
//			tarc0 = E1000_READ_REG(hw, E1000_TARC(0));
//			tarc0 &= ~TARC_SPEED_MODE_BIT;
//			E1000_WRITE_REG(hw, E1000_TARC(0), tarc0);
//		}
//		if (bootverbose)
//			device_printf(dev, "Link is up %d Mbps %s\n",
//			    adapter->link_speed,
//			    ((adapter->link_duplex == FULL_DUPLEX) ?
//			    "Full Duplex" : "Half Duplex"));
		adapter->link_active = 1;
		//adapter->priv->link_status |= IFM_ACTIVE;
//		adapter->smartspeed = 0;
//		if ((ctrl & E1000_CTRL_EXT_LINK_MODE_MASK) ==
//		    E1000_CTRL_EXT_LINK_MODE_GMII &&
//		    (thstat & E1000_THSTAT_LINK_THROTTLE))
//			device_printf(dev, "Link: thermal downshift\n");
//		/* Delay Link Up for Phy update */
//		if (((hw->mac.type == e1000_i210) ||
//		    (hw->mac.type == e1000_i211)) &&
//		    (hw->phy.id == I210_I_PHY_ID))
//			msec_delay(I210_LINK_DELAY);
//		/* Reset if the media type changed. */
//		if ((hw->dev_spec._82575.media_changed) &&
//			(adapter->hw.mac.type >= igb_mac_min)) {
//			hw->dev_spec._82575.media_changed = false;
//			adapter->flags |= IGB_MEDIA_RESET;
//			em_reset(ctx);
//		}
		iflib_link_state_change(ctx, LINK_STATE_UP,
		    IF_Mbps(adapter->link_speed));
	} else if (adapter->link_active == 1) {
		adapter->link_speed = 0;
		adapter->link_duplex = 0;
		adapter->link_active = 0;
		//adapter->priv->link_status = 0;
		iflib_link_state_change(ctx, LINK_STATE_DOWN, 0);
	}
	//em_update_stats_counters(adapter);

//	/* Reset LAA into RAR[0] on 82571 */
//	if ((adapter->hw.mac.type == e1000_82571) &&
//	    e1000_get_laa_state_82571(&adapter->hw))
//		e1000_rar_set(&adapter->hw, adapter->hw.mac.addr, 0);

//	if (adapter->hw.mac.type < em_mac_min)
//		lem_smartspeed(adapter);

	//E1000_WRITE_REG(&adapter->hw, E1000_IMS, EM_MSIX_LINK | E1000_IMS_LSC);
}

static int
ngf_allocate_pci_resources(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	device_t dev = iflib_get_dev(ctx);
	int rid; //, val;

	rid = PCIR_BAR(0);
	adapter->memory = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &rid, RF_ACTIVE);
	if (adapter->memory == NULL) {
		device_printf(dev, "Unable to allocate bus resource: memory\n");
		return (ENXIO);
	}
	adapter->osdep.mem_bus_space_tag = rman_get_bustag(adapter->memory);
	adapter->osdep.mem_bus_space_handle =
	    rman_get_bushandle(adapter->memory);
	//adapter->hw.hw_addr = (u8 *)&adapter->osdep.mem_bus_space_handle;

//	/* Only older adapters use IO mapping */
//	if (adapter->hw.mac.type < em_mac_min &&
//	    adapter->hw.mac.type > e1000_82543) {
//		/* Figure our where our IO BAR is ? */
//		for (rid = PCIR_BAR(0); rid < PCIR_CIS;) {
//			val = pci_read_config(dev, rid, 4);
//			if (EM_BAR_TYPE(val) == EM_BAR_TYPE_IO) {
//				break;
//			}
//			rid += 4;
//			/* check for 64bit BAR */
//			if (EM_BAR_MEM_TYPE(val) == EM_BAR_MEM_TYPE_64BIT)
//				rid += 4;
//		}
//		if (rid >= PCIR_CIS) {
//			device_printf(dev, "Unable to locate IO BAR\n");
//			return (ENXIO);
//		}
//		adapter->ioport = bus_alloc_resource_any(dev, SYS_RES_IOPORT,
//		    &rid, RF_ACTIVE);
//		if (adapter->ioport == NULL) {
//			device_printf(dev, "Unable to allocate bus resource: "
//			    "ioport\n");
//			return (ENXIO);
//		}
//		adapter->hw.io_base = 0;
//		adapter->osdep.io_bus_space_tag =
//		    rman_get_bustag(adapter->ioport);
//		adapter->osdep.io_bus_space_handle =
//		    rman_get_bushandle(adapter->ioport);
//	}

	//adapter->hw.back = &adapter->osdep;

printf("end: %s\n", __func__);
	return (0);
}

static void
ngf_free_pci_resources(if_ctx_t ctx)
{
printf("start: %s\n", __func__);
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	//struct em_rx_queue *que = adapter->rx_queues;
	device_t dev = iflib_get_dev(ctx);

	/* Release all MSI-X queue resources */
//	if (adapter->intr_type == IFLIB_INTR_MSIX)
//		iflib_irq_free(ctx, &adapter->irq);

//	for (int i = 0; i < adapter->rx_num_queues; i++, que++) {
//		iflib_irq_free(ctx, &que->que_irq);
//	}

	if (adapter->memory != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY,
		    rman_get_rid(adapter->memory), adapter->memory);
		adapter->memory = NULL;
	}

//	if (adapter->flash != NULL) {
//		bus_release_resource(dev, SYS_RES_MEMORY,
//		    rman_get_rid(adapter->flash), adapter->flash);
//		adapter->flash = NULL;
//	}
//
//	if (adapter->ioport != NULL) {
//		bus_release_resource(dev, SYS_RES_IOPORT,
//		    rman_get_rid(adapter->ioport), adapter->ioport);
//		adapter->ioport = NULL;
//	}
printf("end: %s\n", __func__);
}

/*********************************************************************
 *
 *  MSI-X RX Interrupt Service routine
 *
 **********************************************************************/
static int
ngf_msix_que(void *arg)
{
printf("start: %s\n", __func__);
	
	struct ngf_rx_queue *que = arg;

	++que->irqs;

printf("end: %s\n", __func__);
	return (FILTER_SCHEDULE_THREAD);
}

/*********************************************************************
 *
 *  Set up the MSI-X Interrupt handlers
 *
 **********************************************************************/
static int
ngf_if_msix_intr_assign(if_ctx_t ctx, int msix)
{
	printf("%s\n", __func__);
	
	struct ngf_softc *adapter = iflib_get_softc(ctx);
	struct ngf_rx_queue *rx_que = adapter->rx_queues;
	struct ngf_tx_queue *tx_que = adapter->tx_queues;
	int error, rid, i, vector = 0, rx_vectors;
	char buf[16];

	/* First set up ring resources */
	for (i = 0; i < adapter->rx_num_queues; i++, rx_que++, vector++) {
		rid = vector + 1;
		snprintf(buf, sizeof(buf), "rxq%d", i);
		error = iflib_irq_alloc_generic(ctx, &rx_que->que_irq, rid, IFLIB_INTR_RXTX, ngf_msix_que, rx_que, rx_que->me, buf);
		if (error) {
			device_printf(iflib_get_dev(ctx), "Failed to allocate que int %d err: %d", i, error);
			adapter->rx_num_queues = i + 1;
			goto fail;
		}

		rx_que->msix =  vector;

		/*
		 * Set the bit to enable interrupt
		 * in E1000_IMS -- bits 20 and 21
		 * are for RX0 and RX1, note this has
		 * NOTHING to do with the MSI-X vector
		 */
//		if (adapter->hw.mac.type == e1000_82574) {
//			rx_que->eims = 1 << (20 + i);
//			adapter->ims |= rx_que->eims;
//			adapter->ivars |= (8 | rx_que->msix) << (i * 4);
//		} else if (adapter->hw.mac.type == e1000_82575)
//			rx_que->eims = E1000_EICR_TX_QUEUE0 << vector;
//		else
//			rx_que->eims = 1 << vector;
	}
	rx_vectors = vector;

	vector = 0;
	for (i = 0; i < adapter->tx_num_queues; i++, tx_que++, vector++) {
		snprintf(buf, sizeof(buf), "txq%d", i);
		tx_que = &adapter->tx_queues[i];
		iflib_softirq_alloc_generic(ctx,
		    &adapter->rx_queues[i % adapter->rx_num_queues].que_irq,
		    IFLIB_INTR_TX, tx_que, tx_que->me, buf);

		tx_que->msix = (vector % adapter->rx_num_queues);

		/*
		 * Set the bit to enable interrupt
		 * in E1000_IMS -- bits 22 and 23
		 * are for TX0 and TX1, note this has
		 * NOTHING to do with the MSI-X vector
		 */
//		if (adapter->hw.mac.type == e1000_82574) {
//			tx_que->eims = 1 << (22 + i);
//			adapter->ims |= tx_que->eims;
//			adapter->ivars |= (8 | tx_que->msix) << (8 + (i * 4));
//		} else if (adapter->hw.mac.type == e1000_82575) {
//			tx_que->eims = E1000_EICR_TX_QUEUE0 << i;
//		} else {
//			tx_que->eims = 1 << i;
//		}
	}

	/* Link interrupt */
	rid = rx_vectors + 1;
	error = iflib_irq_alloc_generic(ctx, &adapter->irq, rid, IFLIB_INTR_ADMIN, ngf_msix_link, adapter, 0, "aq");

	if (error) {
		device_printf(iflib_get_dev(ctx), "Failed to register admin handler");
		goto fail;
	}
	adapter->linkvec = rx_vectors;
//	if (adapter->hw.mac.type < igb_mac_min) {
//		adapter->ivars |=  (8 | rx_vectors) << 16;
//		adapter->ivars |= 0x80000000;
//	}
	return (0);
fail:
	iflib_irq_free(ctx, &adapter->irq);
	rx_que = adapter->rx_queues;
	for (int i = 0; i < adapter->rx_num_queues; i++, rx_que++)
		iflib_irq_free(ctx, &rx_que->que_irq);
	return (error);
}

/*********************************************************************
 *
 *  MSI-X Link Fast Interrupt Service routine
 *
 **********************************************************************/
static int
ngf_msix_link(void *arg)
{
	printf("%s\n", __func__);
	
	struct ngf_softc *adapter = arg;
	//u32 reg_icr;

	++adapter->link_irq;
	//MPASS(adapter->hw.back != NULL);
	//reg_icr = E1000_READ_REG(&adapter->hw, E1000_ICR);

	//if (reg_icr & E1000_ICR_RXO)
		//adapter->rx_overruns++;

	//if (reg_icr & (E1000_ICR_RXSEQ | E1000_ICR_LSC)) {
		ngf_handle_link(adapter->ctx);
	//} else {
		//E1000_WRITE_REG(&adapter->hw, E1000_IMS,
				//EM_MSIX_LINK | E1000_IMS_LSC);
		//if (adapter->hw.mac.type >= igb_mac_min)
			//E1000_WRITE_REG(&adapter->hw, E1000_EIMS, adapter->link_mask);
	//}

	/*
	 * Because we must read the ICR for this interrupt
	 * it may clear other causes using autoclear, for
	 * this reason we simply create a soft interrupt
	 * for all these vectors.
	 */
	//if (reg_icr && adapter->hw.mac.type < igb_mac_min) {
		//E1000_WRITE_REG(&adapter->hw,
			//E1000_ICS, adapter->ims);
	//}

	return (FILTER_HANDLED);
}

static void
ngf_handle_link(void *context)
{
	printf("%s\n", __func__);
	
	if_ctx_t ctx = context;
	//struct ngf_softc *adapter = iflib_get_softc(ctx);

	//adapter->hw.mac.get_link_status = 1;
	iflib_admin_intr_deferred(ctx);
}

static int
ngf_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t rxqid)
{
	printf("%s\n", __func__);
	
	//struct adapter *adapter = iflib_get_softc(ctx);
	//struct em_rx_queue *rxq = &adapter->rx_queues[rxqid];

	//E1000_WRITE_REG(&adapter->hw, E1000_IMS, rxq->eims);
	return (0);
}

static int
ngf_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t txqid)
{
	printf("%s\n", __func__);
	
	//struct adapter *adapter = iflib_get_softc(ctx);
	//struct em_tx_queue *txq = &adapter->tx_queues[txqid];

	//E1000_WRITE_REG(&adapter->hw, E1000_IMS, txq->eims);
	return (0);
}

