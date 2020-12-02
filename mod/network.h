/*
	network.h: Header file of network.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta1
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_NETWORK_H_
#define _MOD_NETWORK_H_
#include "basic.h"
#ifdef linux
struct stru_net_srvrecord;
char ** net_resolve(char * hostname);
int net_srvresolve(char * query_name, struct stru_net_srvrecord * target);
struct sockaddr_in net_mksockaddr_in(unsigned short family, unsigned long addr, unsigned short port);
struct sockaddr_un net_mksockaddr_un(char * path);
int net_mkoutbound(int dst_type, char * dst_addr, unsigned short dst_port, int * dst_socket);
int net_relay(int socket_inbound_client, int socket_outbound);
#include "linux/network.c"
#endif
#endif
