/*
	misc.c: Misc Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "basic.h"
#include "log.h"
#include "protocols/common.h"
#include "protocols/handshake.h"
#include "protocols/handshake_legacy.h"
#include "protocols/proxy.h"

#include "misc.h"

void misc_srvresolve(conf_proxy * info)
{
	net_srvrecord srvrecords[128];
	if(net_srvresolve(info->address,srvrecords)>0)
	{
		info->address=(char *)realloc(info->address,strlen(srvrecords[0].target)+1);
		strcpy(info->address,srvrecords[0].target);
		info->port=srvrecords[0].port;
		info->srvenabled=0;
	}
}
int backbone(int socket_in, int * socket_out, char * logfile, unsigned short runmode, conf * conf_in, net_addrbundle addrinfo_in, short netpriority_enabled)
{
	unsigned char inbound[BUFSIZ],rewrited[BUFSIZ];
	size_t packlen_inbound,packlen_rewrited;
	memset(inbound,0,BUFSIZ);
	memset(rewrited,0,BUFSIZ);
	packlen_inbound=recv(socket_in,inbound,BUFSIZ,0);
	if(packlen_inbound==0)
	{
		mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, status: abort_init\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
		close(socket_in);
		return 1;
	}
	size_t packlen_inbound_append=0; //fetch full packet
	switch(inbound[0])
	{
		case 0xFE:
			if(packlen_inbound>2) //process PVER_LEGACYM3 only
			{
				while(packlen_inbound<0x20)
				{
					packlen_inbound_append=packlen_inbound+recv(socket_in,inbound+packlen_inbound,BUFSIZ-packlen_inbound,0);
					if(packlen_inbound_append==0)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, status: abort_init\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
						close(socket_in);
						return 1;
					}
					packlen_inbound=packlen_inbound+packlen_inbound_append;
				}
				while(packlen_inbound<(0x20+inbound[0x1F]*2+4))
				{
					packlen_inbound_append=packlen_inbound+recv(socket_in,inbound+packlen_inbound,BUFSIZ-packlen_inbound,0);
					if(packlen_inbound_append==0)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, status: abort_init\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
						close(socket_in);
						return 1;
					}
					packlen_inbound=packlen_inbound+packlen_inbound_append;
				}
			}
			break;
		case 0x02:
			break;
		default:
			if((inbound[packlen_inbound-1]==1)||(inbound[packlen_inbound-1]==2))
			{
				packlen_inbound_append=packlen_inbound+recv(socket_in,inbound+packlen_inbound,BUFSIZ-packlen_inbound,0);
				if(packlen_inbound_append==0)
				{
					mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, status: abort_init\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
					close(socket_in);
					return 1;
				}
				packlen_inbound=packlen_inbound+packlen_inbound_append;
			}
			break;
	}  //fetch full packet done
	int protocol_type=protocol_identify(inbound);
	switch(protocol_type)
	{
		case PVER_UNIDENT: //unidentified protocol
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, status: reject_unidentproto\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			close(socket_in);
			return 2;
		case PVER_ORIGPRO: //login: a1.0.15
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, status: reject_gamerelay_oldclient_alpha\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			close(socket_in);
			return 2;
		case PVER_LEGACYL1: //login: a1.0.16~12w03a
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, status: reject_gamerelay_oldclient\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			packlen_rewrited=make_kickreason_legacy("Proxy: Unsupported client, use 12w04a or later!",rewrited);
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		case PVER_LEGACYL3: //login: 12w17a
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, status: reject_gamerelay_12w17a\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			packlen_rewrited=make_kickreason_legacy("Proxy: Unsupported client, use 12w18a or later!",rewrited);
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		case PVER_LEGACYM1: //motd: b1.8-pre1~12w42a
		case PVER_LEGACYM2: //motd: 12w42b~1.6
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: motd, status: reject_motdrelay_oldclient\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			packlen_rewrited=make_motd_legacy(0,"Proxy: Please use direct connect.",protocol_type,rewrited);
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		case PVER_MODERN1: //login&motd: 13w41a~13w41b
		{
			unsigned long packlen_inbound_part1=0;
			void * inbound_offset=inbound;
			inbound_offset=varint2int(inbound_offset,&packlen_inbound_part1);
			inbound_offset=inbound_offset+packlen_inbound_part1-1;
			switch(*((unsigned char *)inbound_offset))
			{
				case 0x01:
					mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: motd, status: reject_motdrelay_13w41*\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
					packlen_rewrited=make_motd(rewrited,"[Proxy] Use 13w42a or later to play!",0);
					break;
				case 0x02:
					mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, status: reject_gamerelay_13w41*\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
					packlen_rewrited=make_kickreason(rewrited,"Proxy: Unsupported client, use 13w42a or later!");
					break;
			}
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			break;
		}
		case PVER_LEGACYL2: //login: 12w04a~12w16a
		case PVER_LEGACYL4: //login: 12w18a~13w39b
		{
			break; //continue, do further processes.
		}
		case PVER_LEGACYM3: //motd: 1.6.1~13w39b
		{
			break; //continue, do further processes.
		}
		case PVER_MODERN2: //login&motd: 13w42a+
			/* p_handshake inbound_info=packet_read(inbound);
			conf_proxy proxyinfo=config_proxy_search(conf_in,inbound_info.address);
			if(!proxyinfo.valid)
			{
				switch(inbound_info.nextstate)
				{
					case 1:
						mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address);
						packlen_rewrited=make_motd(rewrited,"[Proxy] Use a legit address to play!",inbound_info.version);
						break;
					case 2:
						mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,inbound_info.username);
						packlen_rewrited=make_kickreason(rewrited,"Proxy: Please use a legit name to connect!");
						break;
				}
				send(socket_in,rewrited,packlen_rewrited,0);
				close(socket_in);
				return 3;
			} */
			break; //continue, do further processes.
	}
}
