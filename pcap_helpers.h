/*
 * PCAP helpers, partially taken from netsniff-ng
 *
 * Copyright (C) 2017 Tobias Klauser
 * Copyright (C) 2009 - 2013 Daniel Borkmann.
 * Copyright (C) 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef __PCAP_HELPERS_H
#define __PCAP_HELPERS_H

#include <sys/socket.h>
#include <linux/if_arp.h>

#define LINKTYPE_NULL				0
#define LINKTYPE_EN10MB				1
#define LINKTYPE_EN3MB				2
#define LINKTYPE_AX25				3
#define LINKTYPE_PRONET				4
#define LINKTYPE_CHAOS				5
#define LINKTYPE_IEEE802			6
#define LINKTYPE_SLIP				8
#define LINKTYPE_PPP				9
#define LINKTYPE_FDDI				10
#define LINKTYPE_ATM_CLIP			19
#define LINKTYPE_C_HDLC				104
#define LINKTYPE_IEEE802_11			105
#define LINKTYPE_FRELAY				107
#define LINKTYPE_LINUX_SLL			113
#define LINKTYPE_ECONET				115
#define LINKTYPE_IEEE802_11_RADIOTAP		127
#define LINKTYPE_ARCNET_LINUX			129
#define LINKTYPE_LINUX_IRDA			144
#define LINKTYPE_CAN20B				190
#define LINKTYPE_IEEE802_15_4_LINUX		191
#define LINKTYPE_INFINIBAND			247
#define LINKTYPE_NETLINK			253
#define LINKTYPE_MAX				254

static inline int pcap_devtype_to_linktype(int dev_type)
{
	switch (dev_type) {
	case ARPHRD_TUNNEL:
	case ARPHRD_TUNNEL6:
	case ARPHRD_LOOPBACK:
	case ARPHRD_SIT:
	case ARPHRD_IPDDP:
	case ARPHRD_IPGRE:
	case ARPHRD_IP6GRE:
	case ARPHRD_ETHER:
		return LINKTYPE_EN10MB;
	case ARPHRD_IEEE80211_RADIOTAP:
		return LINKTYPE_IEEE802_11_RADIOTAP;
	case ARPHRD_IEEE80211_PRISM:
	case ARPHRD_IEEE80211:
		return LINKTYPE_IEEE802_11;
	case ARPHRD_NETLINK:
		return LINKTYPE_NETLINK;
	case ARPHRD_EETHER:
		return LINKTYPE_EN3MB;
	case ARPHRD_AX25:
		return LINKTYPE_AX25;
	case ARPHRD_CHAOS:
		return LINKTYPE_CHAOS;
	case ARPHRD_PRONET:
		return LINKTYPE_PRONET;
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE802:
		return LINKTYPE_IEEE802;
	case ARPHRD_INFINIBAND:
		return LINKTYPE_INFINIBAND;
	case ARPHRD_ATM:
		return LINKTYPE_ATM_CLIP;
	case ARPHRD_DLCI:
		return LINKTYPE_FRELAY;
	case ARPHRD_ARCNET:
		return LINKTYPE_ARCNET_LINUX;
	case ARPHRD_CSLIP:
	case ARPHRD_CSLIP6:
	case ARPHRD_SLIP6:
	case ARPHRD_SLIP:
		return LINKTYPE_SLIP;
	case ARPHRD_PPP:
		return LINKTYPE_PPP;
	case ARPHRD_CAN:
		return LINKTYPE_CAN20B;
	case ARPHRD_ECONET:
		return LINKTYPE_ECONET;
	case ARPHRD_RAWHDLC:
	case ARPHRD_CISCO:
		return LINKTYPE_C_HDLC;
	case ARPHRD_FDDI:
		return LINKTYPE_FDDI;
	case ARPHRD_IEEE802154_MONITOR:
	case ARPHRD_IEEE802154:
		return LINKTYPE_IEEE802_15_4_LINUX;
	case ARPHRD_IRDA:
		return LINKTYPE_LINUX_IRDA;
	default:
		return LINKTYPE_NULL;
	}
}

#endif /* __PCAP_HELPERS_H */
