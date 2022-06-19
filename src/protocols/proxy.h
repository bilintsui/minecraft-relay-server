/*
	protocols/proxy.h: Header file of protocols/proxy.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_PROTOCOLS_PROXY_H_INCLUDED_

#define _MRS_PROTOCOLS_PROXY_H_INCLUDED_

#define PROTOPROXY_PACKETMAXLEN 104

#include "../network.h"

typedef struct
{
	sa_family_t family;
	net_addr srcaddr,dstaddr;
	in_port_t srcport,dstport;
} p_proxy;

sa_family_t protocol_proxy_getfamily(const void * src, size_t n);
p_proxy protocol_proxy_read(const void * src, size_t n);
size_t protocol_proxy_write(void * dst, p_proxy src);
size_t protocol_proxy_write_plain(void * dst, sa_family_t family, net_addr srcaddr, net_addr dstaddr, in_port_t srcport, in_port_t dstport);

#endif
