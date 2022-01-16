/*
	protocols/handshake.h: Header file of protocols/handshake.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_PROTOCOLS_HANDSHAKE_H_INCLUDED_

#define _MRS_PROTOCOLS_HANDSHAKE_H_INCLUDED_

#include <stddef.h>
#include "../defines.h"

typedef struct
{
	mcver version;
	unsigned long id_part1,nextstate,id_part2;
	unsigned char address[128],username[128];
	unsigned short version_fml,port;
} p_handshake;

size_t make_message(char * dst, const char * src);
size_t make_kickreason(char * dst, const char * src);
size_t make_motd(char * dst, const char * src, mcver ver);
p_handshake packet_read(unsigned char * sourcepacket);
int packet_write(p_handshake source, unsigned char * target);

#endif
