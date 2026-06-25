/*
	protocol/handshake_legacy.h: Header file of protocol/handshake_legacy.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta4
	(c) 2020-2024 Bilin Tsui.
	This is a Free Software, absolutely no warranty.

	Licensed under GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, see: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_PROTOCOLS_HANDSHAKE_LEGACY_H_INCLUDED_

#define _MRS_PROTOCOLS_HANDSHAKE_LEGACY_H_INCLUDED_

typedef struct
{
	int proto_ver;
	unsigned char username[128],address[128];
	unsigned short port,version;
} p_login_legacy;
typedef struct
{
	void * address;
	in_port_t port;
	u_int8_t version;
} p_motd_legacy;

size_t make_message_legacy(void * dst, void * src, size_t n);
size_t make_kickreason_legacy(void * dst, void * src);
size_t make_motd_legacy(void * dst, void * src, int motd_version, unsigned int version);
p_login_legacy packet_read_legacy_login(unsigned char * sourcepacket, int sourcepacket_length, int login_version);
p_motd_legacy packet_read_legacy_motd(void * src);
int packet_write_legacy_login(p_login_legacy source, unsigned char * target);
size_t packet_write_legacy_motd(void * dst, p_motd_legacy src);
void packet_destroy_legacy_motd(p_motd_legacy object);

#endif
