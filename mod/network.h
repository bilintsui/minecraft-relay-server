/*
	network.h: Header file of network.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_NETWORK_H_
#define _MOD_NETWORK_H_
#ifdef linux
#define NETSOCK_BIND 0
#define NETSOCK_CONN 1
#define NET_EARGFAMILY 1
#define NET_EMALLOC 2
#define NET_ENORECORD 3
#define NET_EARGACTION 4
#define NET_EARGADDR 5
#define NET_ESOCKET 6
#define NET_EREUSEADDR 7
#define NET_EBIND 8
#define NET_ELISTEN 9
#define NET_ECONNECT 10
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
typedef struct
{
	sa_family_t family;
	int err;
	union
	{
		uint32_t v4;
		unsigned char v6[16];
	} addr;
} net_addr;
typedef union {
	char v4[INET_ADDRSTRLEN];
	char v6[INET6_ADDRSTRLEN+2];
} net_addrp;
typedef struct
{
	char target[128];
	unsigned short port;
} net_srvrecord;
typedef struct
{
	sa_family_t family;
	net_addrp address,address_clean;
	in_port_t port;
} net_addrbundle;
size_t net_getaddrsize(sa_family_t family);
sa_family_t net_getaltfamily(sa_family_t family);
void * net_resolve(char * hostname, sa_family_t family);
net_addr net_resolve_dual(char * hostname, sa_family_t primary_family, short dual);
net_addrp net_ntop(sa_family_t family, void * src, short v6addition);
int net_srvresolve(char * query_name, net_srvrecord * target);
int net_socket(short action, sa_family_t family, void * address, u_int16_t port, short reuseaddr);
int net_relay(int socket_in, int socket_out);
#include "linux/network.c"
#endif
#endif
