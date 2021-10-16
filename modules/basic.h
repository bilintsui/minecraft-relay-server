/*
	basic.h: Header file of basic.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_BASIC_H_
#define _MOD_BASIC_H_
#ifdef linux
#define PVER_L_UNIDENT 0
#define PVER_L_ORIGPRO 1
#define PVER_L_LEGACY1 2
#define PVER_L_LEGACY2 3
#define PVER_L_LEGACY3 4
#define PVER_L_LEGACY4 5
#define PVER_L_MODERN1 6
#define PVER_L_MODERN2 7
#define PVER_M_UNIDENT 0
#define PVER_M_LEGACY1 1
#define PVER_M_LEGACY2 2
#define PVER_M_LEGACY3 3
#define FREADALL_NORMAL 0
#define FREADALL_ENONAME 1
#define FREADALL_ENOREAD 2
#define FREADALL_ECALLOC 3
#define FREADALL_ELARGE 4
#define FREADALL_EREALLOC 5
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
unsigned char * base64_encode(unsigned char * source, size_t source_size);
int handshake_protocol_identify(unsigned char * source, unsigned int length);
void * int2varint(unsigned long src, void * dst);
int legacy_motd_protocol_identify(unsigned char * source);
int ismcproto(unsigned char * data_in, unsigned int data_length);
size_t memcat(void * dst, size_t dst_size, void * src, size_t src_size);
size_t freadall(unsigned char * filename, unsigned char ** dest);
int packetexpand(unsigned char * source, int source_length, unsigned char * target);
int packetshrink(unsigned char * source, int source_length, unsigned char * target);
size_t strlen_notail(const char * src, char tailchar);
size_t strcmp_notail(const char * str1, const char * str2, char tailchar);
unsigned char * strsplit(unsigned char * string, char delim, unsigned char * firstfield);
unsigned char * strsplit_reverse(unsigned char * string, char delim);
void * varint2int(void * src, unsigned long * dst);
#include "linux/basic.c"
#endif
#endif
