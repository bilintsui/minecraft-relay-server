/*
	basic.h: Header file of basic.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.3
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_BASIC_H_
#define _MOD_BASIC_H_
#ifdef linux
#define TYPE_UNIX 1
#define TYPE_INET 2
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
void gettime(unsigned char * target);
long math_pow(int x,int y);
unsigned short basic_atosu(unsigned char * source);
unsigned char * varint2int(unsigned char * source, unsigned long * output);
unsigned char * int2varint(unsigned long data, unsigned char * output);
int datcat(char * dst, int dst_size, char * src, int src_size);
int handshake_protocol_identify(unsigned char * source, unsigned int length);
int packetshrink(unsigned char * source, int source_length, unsigned char * target);
int packetexpand(unsigned char * source, int source_length, unsigned char * target);
unsigned char * strsplit(unsigned char * string, char delim, unsigned char * firstfield);
int strsplit_fieldcount(unsigned char * string, char delim);
int mksysmsg(unsigned short noprefix, char * logfile, unsigned short runmode, unsigned short maxlevel, unsigned short msglevel, char * format, ...);
int legacy_motd_protocol_identify(unsigned char * source);
int ismcproto(unsigned char * data_in, unsigned int data_length);
#include "linux/basic.c"
#endif
#endif
