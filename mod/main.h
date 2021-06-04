/*
	main.h: Header file of main.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.5
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#ifndef _MOD_MAIN_H_
#define _MOD_MAIN_H_
#include "basic.h"
#include "config.h"
#include "network.h"
#include "proto_legacy.h"
#include "proto_modern.h"
#include "misc.h"
#ifdef linux
void deal_sigterm();
void deal_sigusr1();
int main(int argc, char ** argv);
#include "linux/main.c"
#endif
#endif
