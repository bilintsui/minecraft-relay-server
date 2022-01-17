/*
	protocols/common.c: Common Functions for Protocols on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <string.h>

#include "common.h"

int protocol_identify(const char * src)
{
	if(src==NULL)
	{
		return PVER_UNIDENT;
	}
	const unsigned char * source=(unsigned char *)src;
	switch(source[0])
	{
		case 0x01:
			return PVER_ORIGPRO;
		case 0x02:
			switch(source[1])
			{
				case 0x00:
					if(memchr(source+3,';',source[2]*2)&&memchr(source+3,':',source[2]*2))
					{
						return PVER_LEGACYL2;
					}
					else
					{
						return PVER_LEGACYL1;
					}
				case 0x1F:
					return PVER_LEGACYL3;
				default:
					return PVER_LEGACYL4;
			}
		case 0xFE:
			switch(source[1])
			{
				case 0x00:
					return PVER_LEGACYM1;
				case 0x01:
					switch(source[2])
					{
						case 0x00:
							return PVER_LEGACYM2;
						case 0xFA:
							return PVER_LEGACYM3;
						default:
							return PVER_UNIDENT;
					}
				default:
					return PVER_UNIDENT;
			}
		default:
			if((source[source[0]]==1)||(source[source[0]]==2))
			{
				if(source[2])
				{
					return PVER_MODERN2;
				}
				else
				{
					return PVER_MODERN1;
				}
			}
			else
			{
				return PVER_UNIDENT;
			}
	}
}
