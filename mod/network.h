/*
	network.h: Network Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.
	Requires: mod/basic.h, please manually include it in main source code.
	
	Minecraft Relay Server, version 1.1-beta2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <string.h>
#include <sys/un.h>
int dstconnect(int dst_type, char * dst_addr, unsigned short dst_port, int * dst_socket)
{
	char str[INET_ADDRSTRLEN];
	if(dst_type==TYPE_INET)
	{
		*dst_socket=socket(AF_INET,SOCK_STREAM,0);
		if(inet_addr(dst_addr)==-1)
		{
			char ** addresses=getaddresses(dst_addr);
			if(addresses==NULL)
			{
				return 1;
			}
			else
			{
				struct sockaddr_in conninfo=genSockConf(AF_INET,htonl(inet_addr(inet_ntop(AF_INET,addresses[0],str,sizeof(str)))),dst_port);
				if(connect(*dst_socket,(struct sockaddr*)&conninfo,sizeof(struct sockaddr))==-1)
				{
					return 2;
				}
				else
				{
					return 0;
				}
			}
		}
		else
		{
			struct sockaddr_in conninfo=genSockConf(AF_INET,htonl(inet_addr(dst_addr)),dst_port);
			if(connect(*dst_socket,(struct sockaddr*)&conninfo,sizeof(struct sockaddr))==-1)
			{
				return 2;
			}
			else
			{
				return 0;
			}
		}
	}
	else if(dst_type==TYPE_UNIX)
	{
		struct sockaddr_un conninfo;
		conninfo.sun_family=AF_UNIX;
		strcpy(conninfo.sun_path,dst_addr);
		if(connect(*dst_socket,(struct sockaddr*)&conninfo,sizeof(struct sockaddr))==-1)
		{
			return 2;
		}
		else
		{
			return 0;
		}
	}
}
