/*
	config.h: Header file of config.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta1
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_CONFIG_H_
#define _MOD_CONFIG_H_
#include "basic.h"
#ifdef linux
#define CONF_EOPENFILE 1
#define CONF_ENOLOGFILE 2
#define CONF_ENOLOGLEVEL 3
#define CONF_EINVALIDBIND 4
#define CONF_EPROXYNOFIND 5
#define CONF_EPROXYDUP 6
#define CONF_EDEFPROXYDUP 7
typedef struct
{
	char inet_addr[BUFSIZ];
	unsigned short inet_port;
} conf_bind;
typedef struct
{
	unsigned short enable_rewrite;
	char from[512],to_inet_addr[512];
	unsigned short to_inet_port;
	unsigned short to_inet_hybridmode;
} conf_map;
typedef struct
{
	char log[512];
	unsigned short loglevel;
	conf_bind bind;
	int relay_count;
	conf_map relay[128];
	int enable_default;
	conf_map relay_default;
} conf;
conf_map * getproxyinfo(conf * source, unsigned char * proxyname);
void config_dump(conf * source);
int config_load(char * filename, conf * result);
#include "linux/config.c"
#endif
#endif
