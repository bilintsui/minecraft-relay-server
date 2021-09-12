/*
	proto_legacy.h: Header file of proto_legacy.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta1
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_PROTO_LEGACY_H_
#define _MOD_PROTO_LEGACY_H_
#include "basic.h"
#ifdef linux
typedef struct
{
	int proto_ver;
	unsigned char username[128],address[128];
	unsigned short port,version;
} p_login_legacy;
typedef struct
{
	unsigned char address[128];
	unsigned short port,version;
} p_motd_legacy;
p_login_legacy packet_read_legacy_login(unsigned char * sourcepacket, int sourcepacket_length, int login_version);
int packet_write_legacy_login(p_login_legacy source, unsigned char * target);
p_motd_legacy packet_read_legacy_motd(unsigned char * sourcepacket, int sourcepacket_length);
int packet_write_legacy_motd(p_motd_legacy source, unsigned char * target);
int make_message_legacy(unsigned char * source, unsigned int source_length, unsigned char * target);
int make_kickreason_legacy(unsigned char * source, unsigned char * target);
int make_motd_legacy(unsigned int version, unsigned char * description, int motd_version, unsigned char * target);
#include "linux/proto_legacy.c"
#endif
#endif
