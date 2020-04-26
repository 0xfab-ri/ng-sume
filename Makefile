KMOD=	ngf
SRCS=	ngf.c ngf_txrx.c ngf.h
SRCS+=  device_if.h bus_if.h ifdi_if.h opt_ddb.h opt_inet.h opt_inet6.h pci_if.h opt_acpi.h opt_sched.h

.include <bsd.kmod.mk>
