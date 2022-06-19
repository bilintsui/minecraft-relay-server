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

#include <netinet/in.h>
#include "../defines.h"

typedef struct
{
	varint_l id_part1,id_part2,nextstate,version;
	void * address,* signature_data,* username;
	size_t signature_data_length;
	unsigned short version_fml;
	in_port_t port;
} p_handshake;

size_t make_message(void * dst, const void * src);
size_t make_kickreason(void * dst, const void * src);
size_t make_motd(void * dst, const void * src, varint_l ver);
p_handshake packet_read(void * src);
size_t packet_write(void * dst, const p_handshake src);
void packet_destroy(p_handshake object);

#endif
