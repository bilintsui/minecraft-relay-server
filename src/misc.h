/*
	misc.h: Header file of misc.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_MISC_H_INCLUDED_

#define _MRS_MISC_H_INCLUDED_

#include "config.h"
#include "network.h"

int backbone(int socket_in, int * socket_out, char * logfile, unsigned short runmode, conf * conf_in, net_addrbundle addrinfo_in, short netpriority_enabled);

#endif
