/*
	basic.h: Header file of basic.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_BASIC_H_INCLUDED_

#define _MRS_BASIC_H_INCLUDED_

#include <stddef.h>

#define PVER_UNIDENT 0
#define PVER_L_ORIGPRO 1
#define PVER_L_LEGACY1 2
#define PVER_L_LEGACY2 3
#define PVER_L_LEGACY3 4
#define PVER_L_LEGACY4 5
#define PVER_L_MODERN1 6
#define PVER_L_MODERN2 7
#define PVER_M_LEGACY1 8
#define PVER_M_LEGACY2 9
#define PVER_M_LEGACY3 10
#define FREADALL_SLIMIT 5242880
#define FREADALL_EINVAL 1
#define FREADALL_ERFAIL 2
#define FREADALL_ELARGE 3
#define FREADALL_ENOMEM 4

size_t freadall(const char * filename, char ** dst);
int handshake_protocol_identify(const void * src);
void * int2varint(unsigned long src, void * dst);
int legacy_motd_protocol_identify(const void * src);
int ismcproto(const char * src);
size_t memcat(void * dst, size_t dst_size, void * src, size_t src_size);
int packetexpand(unsigned char * source, int source_length, unsigned char * target);
int packetshrink(unsigned char * source, int source_length, unsigned char * target);
size_t strlen_notail(const char * src, char exemptchr);
size_t strcmp_notail(const char * str1, const char * str2, char exemptchr, short case_insensitive);
char * strtok_head(char * dst, char * src, char delim);
size_t strtok_tail(char * dst, char * src, char delim, size_t length);
void * varint2int(void * src, unsigned long * dst);

#endif
