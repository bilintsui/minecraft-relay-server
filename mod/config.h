/*
	config.h: Header file of config.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.2
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
struct conf_bind;
struct conf_map;
struct conf;
int config_load(char * filename, struct conf * result);
struct conf_map * getproxyinfo(struct conf * source, unsigned char * proxyname);
#include "linux/config.c"
#endif
#endif
