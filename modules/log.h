/*
	log.h: Header file of log.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_LOG_H_
#define _MOD_LOG_H_
#ifdef linux
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
void gettime(unsigned char * target);
int mksysmsg(unsigned short noprefix, char * logfile, unsigned short runmode, unsigned short maxlevel, unsigned short msglevel, char * format, ...);
#include "linux/log.c"
#endif
#endif
