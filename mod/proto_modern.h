/*
	proto_modern.h: Header file of proto_modern.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.3
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_PROTO_MODERN_H_
#define _MOD_PROTO_MODERN_H_
#include "basic.h"
#ifdef linux
struct p_handshake;
struct p_handshake packet_read(unsigned char * sourcepacket);
int packet_write(struct p_handshake source, unsigned char * target);
int make_message(unsigned char * source, unsigned char * target);
int make_kickreason(unsigned char * source, unsigned char * target);
int make_motd(unsigned long version, unsigned char * description, unsigned char * target);
#include "linux/proto_modern.c"
#endif
#endif
