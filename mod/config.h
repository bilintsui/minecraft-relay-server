/*
	config.h: Header file of config.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta1
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_CONFIG_H_
#define _MOD_CONFIG_H_
#include "basic.h"
#ifdef linux
#define CONF_EOPENFILE 1
#define CONF_EBADRUNMODE 2
#define CONF_ENOLOGFILE 3
#define CONF_ENOLOGLEVEL 4
#define CONF_EINVALIDBIND 5
#define CONF_EPROXYNOFIND 6
#define CONF_EPROXYDUP 7
#define CONF_EDEFPROXYDUP 8
struct conf_bind;
struct conf_map;
struct conf;
struct conf_map * getproxyinfo(struct conf * source, unsigned char * proxyname);
void config_dump(struct conf * source);
int config_load(char * filename, struct conf * result);
#include "linux/config.c"
#endif
#endif
