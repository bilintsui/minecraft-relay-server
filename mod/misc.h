/*
	misc.h: Header file of misc.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.5
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_MISC_H_
#define _MOD_MISC_H_
#include "basic.h"
#include "config.h"
#include "network.h"
#include "proto_legacy.h"
#include "proto_modern.h"
#ifdef linux
int backbone(int socket_in, int * socket_out, char * logfile, unsigned short runmode, struct conf conf_in, struct sockaddr_in addrinfo_in);
#include "linux/misc.c"
#endif
#endif
