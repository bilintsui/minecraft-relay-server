/*
	protocols/common.h: Header file of protocols/common.c
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_PROTOCOLS_COMMON_H_INCLUDED_

#define _MRS_PROTOCOLS_COMMON_H_INCLUDED_

#define PVER_UNIDENT 0
#define PVER_ORIGPRO 1
#define PVER_LEGACYL1 2
#define PVER_LEGACYL2 3
#define PVER_LEGACYL3 4
#define PVER_LEGACYL4 5
#define PVER_LEGACYM1 6
#define PVER_LEGACYM2 7
#define PVER_LEGACYM3 8
#define PVER_MODERN1 9
#define PVER_MODERN2 10

int protocol_identify(const char * src);

#endif
