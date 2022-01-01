/*
	proto_modern.h: Header file of proto_modern.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_MODULES_PROTO_MODERN_H_INCLUDED_

#define _MRS_MODULES_PROTO_MODREN_H_INCLUDED_

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

#endif
