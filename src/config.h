/*
	config.h: Header file of config.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_CONFIG_H_INCLUDED_

#define _MRS_CONFIG_H_INCLUDED_

#include <cjson/cJSON.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
		in_port_t port;
	} listen;
	cJSON * proxy;
} conf;
typedef struct
{
	char * address;
	in_port_t port;
	short valid,srvenabled,rewrite,pheader;
} conf_proxy;

void config_destroy(conf * target);
short config_jsonbool(cJSON * src, short defaultvalue);
void config_dumper(conf * src);
cJSON * config_proxy_parse(cJSON * src);
conf_proxy config_proxy_search(conf * src, const char * targetvhost);
void config_proxy_search_destroy(conf_proxy * target);
conf * config_read(char * filename);

#endif
