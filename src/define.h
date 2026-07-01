/*
	define.h: Header file for general defines on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta4
	(c) 2020-2026 Bilin Tsui.
	This is a Free Software, absolutely no warranty.

	Licensed under GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, see: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_DEFINES_H_INCLUDED_

#define _MRS_DEFINES_H_INCLUDED_

#include <stdint.h>

#define MCRELAY_VERSION_DISPLAY "1.2-beta4"
#define MCRELAY_VERSION_INTERNAL "66"
#define MCRELAY_COPYYEAR "2020-2026"

#define PVERDB_SNAPMASK 0xBFFFFFFF
#define PVERDB_R_1_20_1 763
#define PVERDB_S_1_20_1_RC1 0x8E

#define VARINT_T_MAXIDX (sizeof(varint_t) * 8 / 7)
#define VARINT_T_LAST_MASK ((varint_t)((1u << ((sizeof(varint_t) * 8) % 7)) - 1))

#define ADDRESS_MAXLEN 1024

typedef uint32_t varint_t;

#endif
