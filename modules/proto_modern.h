/*
	proto_modern.h: Header file of proto_modern.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_PROTO_MODERN_H_
#define _MOD_PROTO_MODERN_H_
#ifdef linux
#include <stdio.h>
#include <string.h>
#include "basic.h"
typedef struct
{
	unsigned long id_part1,version,nextstate,id_part2;
	unsigned char address[128],username[128];
	unsigned short version_fml,port;
} p_handshake;
int make_message(unsigned char * source, unsigned char * target);
int make_kickreason(unsigned char * source, unsigned char * target);
int make_motd(unsigned long version, unsigned char * description, unsigned char * target);
p_handshake packet_read(unsigned char * sourcepacket);
int packet_write(p_handshake source, unsigned char * target);
#include "linux/proto_modern.c"
#endif
#endif
