/*
	config2.h: Header file of config2.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_CONFIG2_H_
#define _MOD_CONFIG2_H_
#ifdef linux
#define CONF_EARGNULL 1
#define CONF_EROPENFAIL 2
#define CONF_EROPENLARGE 3
#define CONF_ERMEMORY 4
#define CONF_ERPARSE 5
#define CONF_ECMEMORY 6
#define CONF_ECNETPRIORITYPROTOCOL 7
#define CONF_ECLISTENPORT 8
#define CONF_ECPROXY 9
#define CONF_ECPROXYDUP 10
#include <cjson/cJSON.h>
#include <string.h>
#include <sys/socket.h>
#include "basic.h"
typedef struct
{
	char * address;
	u_int16_t port;
	short valid,srvenabled,rewrite,pheader;
} conf2_proxy;
typedef struct
{
	struct
	{
		short enabled;
		sa_family_t protocol;
	} netpriority;
	struct
	{
		char * filename;
		short level,binary;
	} log;
	struct
	{
		char * address;
		u_int16_t port;
	} listen;
	cJSON * proxy;
} conf2;
short config_jsonbool(cJSON * src, short defaultvalue);
void config_destroy(conf2 * target);
cJSON * config_proxy_parse(cJSON * src);
conf2 * config_read(char * filename);
void config_dumper(conf2 * src);
conf2_proxy config_proxy_search(conf2 * src, const char * targetvhost);
#include "linux/config2.c"
#endif
#endif
