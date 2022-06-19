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

int backbone(int socket_in, int * socket_out, char * logfile, unsigned short runmode, conf * conf_in, net_addrbundle addrinfo_in, short netpriority_enabled)
{
	unsigned char inbound[BUFSIZ],outbound[BUFSIZ],rewrited[BUFSIZ],pheader[PROTOPROXY_PACKETMAXLEN+1];
	int packlen_inbound,packlen_outbound,packlen_rewrited,packlen_pheader;
	struct sockaddr_in addr_outbound;
	memset(inbound,0,BUFSIZ);
	memset(outbound,0,BUFSIZ);
	memset(rewrited,0,BUFSIZ);
	memset(pheader,0,PROTOPROXY_PACKETMAXLEN+1);
	packlen_inbound=recv(socket_in,inbound,BUFSIZ,0);
	if(packlen_inbound==0)
	{
		mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, status: abort_init\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
		close(socket_in);
		return 1;
	}
	size_t packlen_inbound_append=0;
	switch(inbound[0])
	{
		case 0xFE:
			if(packlen_inbound>2)
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
	}
	if(protocol_identify(inbound)==PVER_UNIDENT)
	{
		mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, status: reject_unidentproto\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
		close(socket_in);
		return 2;
	}
	if(inbound[0]==0xFE)
	{
		int motd_version=protocol_identify(inbound);
		if(motd_version==PVER_LEGACYM3)
		{
			p_motd_legacy inbound_info=packet_read_legacy_motd(inbound);
			conf_proxy proxyinfo=config_proxy_search(conf_in,inbound_info.address);
			if(proxyinfo.valid==0)
			{
				mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address);
				packlen_rewrited=make_motd_legacy(rewrited,"[Proxy] Use a legit address to play!",motd_version,inbound_info.version);
				send(socket_in,rewrited,packlen_rewrited,0);
				packet_destroy_legacy_motd(inbound_info);
				close(socket_in);
				return 3;
			}
			int mkoutbound_status,outmsg_level;
			if(proxyinfo.srvenabled==1)
			{
				net_srvrecord srvrecords[128];
				if(net_srvresolve(proxyinfo.address,srvrecords)>0)
				{
					proxyinfo.address=(char *)realloc(proxyinfo.address,strlen(srvrecords[0].target)+1);
					strcpy(proxyinfo.address,srvrecords[0].target);
					proxyinfo.port=srvrecords[0].port;
					proxyinfo.srvenabled=0;
				}
			}
			mkoutbound_status=0;
			net_addr connaddr=net_resolve_dual(proxyinfo.address,addrinfo_in.family,netpriority_enabled);
			if(connaddr.family==0)
			{
				mkoutbound_status=NET_ENORECORD;
			}
			*socket_out=net_socket(NETSOCK_CONN,connaddr.family,&(connaddr.addr),proxyinfo.port,0);
			if(*socket_out==-1)
			{
				mkoutbound_status=NET_ECONNECT;
			}
			if(mkoutbound_status!=0)
			{
				outmsg_level=1;
			}
			else
			{
				outmsg_level=3;
			}
			switch(mkoutbound_status)
			{
				case 0:
					mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: accept\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port);
					if(proxyinfo.pheader==1)
					{
						if(connaddr.family==addrinfo_in.family)
						{
							net_addrp addrinfo_out=net_ntop(connaddr.family,&(connaddr.addr),0);
							if(addrinfo_in.family==AF_INET)
							{
								packlen_pheader=sprintf(pheader,"PROXY TCP4 %s %s %d %d\r\n",(char *)&(addrinfo_in.address_clean),(char *)&addrinfo_out,addrinfo_in.port,proxyinfo.port);
								send(*socket_out,pheader,packlen_pheader,0);
							}
							else if(addrinfo_in.family==AF_INET6)
							{
								packlen_pheader=sprintf(pheader,"PROXY TCP6 %s %s %d %d\r\n",(char *)&(addrinfo_in.address_clean),(char *)&addrinfo_out,addrinfo_in.port,proxyinfo.port);
								send(*socket_out,pheader,packlen_pheader,0);
							}
						}
					}
					if(proxyinfo.rewrite==1)
					{
						inbound_info.address=realloc(inbound_info.address,strlen(proxyinfo.address)+1);
						strcpy(inbound_info.address,proxyinfo.address);
						inbound_info.port=proxyinfo.port;
						packlen_rewrited=packet_write_legacy_motd(rewrited,inbound_info);
						send(*socket_out,rewrited,packlen_rewrited,0);
					}
					else
					{
						send(*socket_out,inbound,packlen_inbound,0);
					}
					config_proxy_search_destroy(&proxyinfo);
					packet_destroy_legacy_motd(inbound_info);
					return 0;
				case NET_ENORECORD:
				case NET_ECONNECT:
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoresolve\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port);
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoconnect\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port);
					}
					packlen_rewrited=make_motd_legacy(rewrited,"[Proxy] Server Temporary Unavailable.",motd_version,inbound_info.version);
					send(socket_in,rewrited,packlen_rewrited,0);
					close(socket_in);
					packet_destroy_legacy_motd(inbound_info);
					config_proxy_search_destroy(&proxyinfo);
					return 4;
			}
		}
		else
		{
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: motd, status: reject_motdrelay_oldclient\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			packlen_rewrited=make_motd_legacy(rewrited,"Proxy: Please use direct connect.",protocol_identify(inbound),0);
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		}
	}
	else if(inbound[0]==2)
	{
		int login_version=protocol_identify(inbound);
		if(login_version==PVER_LEGACYL1)
		{
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, status: reject_gamerelay_oldclient\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			packlen_rewrited=make_kickreason_legacy(rewrited,"Proxy: Unsupported client, use 12w04a or later!");
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		}
		else if(login_version==PVER_LEGACYL3)
		{
			mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, status: reject_gamerelay_12w17a\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
			packlen_rewrited=make_kickreason_legacy(rewrited,"Proxy: Unsupported client, use 12w18a or later!");
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		}
		else if((login_version==PVER_LEGACYL2)||(login_version==PVER_LEGACYL4))
		{
			p_login_legacy inbound_info=packet_read_legacy_login(inbound,packlen_inbound,login_version);
			conf_proxy proxyinfo=config_proxy_search(conf_in,inbound_info.address);
			if(proxyinfo.valid==0)
			{
				mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,inbound_info.username);
				packlen_rewrited=make_kickreason_legacy(rewrited,"Proxy: Please use a legit name to connect!");
				send(socket_in,rewrited,packlen_rewrited,0);
				close(socket_in);
				return 3;
			}
			int mkoutbound_status,outmsg_level;
			if(proxyinfo.srvenabled==1)
			{
				net_srvrecord srvrecords[128];
				if(net_srvresolve(proxyinfo.address,srvrecords)>0)
				{
					proxyinfo.address=(char *)realloc(proxyinfo.address,strlen(srvrecords[0].target)+1);
					strcpy(proxyinfo.address,srvrecords[0].target);
					proxyinfo.port=srvrecords[0].port;
					proxyinfo.srvenabled=0;
				}
			}
			mkoutbound_status=0;
			net_addr connaddr=net_resolve_dual(proxyinfo.address,addrinfo_in.family,netpriority_enabled);
			if(connaddr.family==0)
			{
				mkoutbound_status=NET_ENORECORD;
			}
			*socket_out=net_socket(NETSOCK_CONN,connaddr.family,&(connaddr.addr),proxyinfo.port,0);
			if(*socket_out==-1)
			{
				mkoutbound_status=NET_ECONNECT;
			}
			if(mkoutbound_status!=0)
			{
				outmsg_level=1;
			}
			else
			{
				outmsg_level=2;
			}
			switch(mkoutbound_status)
			{
				case 0:
					mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: accept, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port,inbound_info.username);
					if(proxyinfo.pheader==1)
					{
						if(connaddr.family==addrinfo_in.family)
						{
							net_addrp addrinfo_out=net_ntop(connaddr.family,&(connaddr.addr),0);
							if(addrinfo_in.family==AF_INET)
							{
								packlen_pheader=sprintf(pheader,"PROXY TCP4 %s %s %d %d\r\n",(char *)&(addrinfo_in.address_clean),(char *)&addrinfo_out,addrinfo_in.port,proxyinfo.port);
								send(*socket_out,pheader,packlen_pheader,0);
							}
							else if(addrinfo_in.family==AF_INET6)
							{
								packlen_pheader=sprintf(pheader,"PROXY TCP6 %s %s %d %d\r\n",(char *)&(addrinfo_in.address_clean),(char *)&addrinfo_out,addrinfo_in.port,proxyinfo.port);
								send(*socket_out,pheader,packlen_pheader,0);
							}
						}
					}
					if(proxyinfo.rewrite==1)
					{
						strcpy(inbound_info.address,proxyinfo.address);
						inbound_info.port=proxyinfo.port;
						packlen_rewrited=packet_write_legacy_login(inbound_info,rewrited);
						send(*socket_out,rewrited,packlen_rewrited,0);
					}
					else
					{
						send(*socket_out,inbound,packlen_inbound,0);
					}
					config_proxy_search_destroy(&proxyinfo);
					return 0;
				case NET_ENORECORD:
				case NET_ECONNECT:
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port,inbound_info.username);
						packlen_rewrited=make_kickreason_legacy(rewrited,"Proxy(Internal): Temporary failed on resolving address for the target server, please try again later.");
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port,inbound_info.username);
						packlen_rewrited=make_kickreason_legacy(rewrited,"Proxy(Internal): Failed on connecting to the target server, please try again later.");
					}
					send(socket_in,rewrited,packlen_rewrited,0);
					close(socket_in);
					config_proxy_search_destroy(&proxyinfo);
					return 4;
			}
		}
	}
	else
	{
		p_handshake inbound_info=packet_read(inbound);
		if(inbound_info.version==0)
		{
			if(inbound[inbound[0]]==1)
			{
				mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: motd, status: reject_motdrelay_13w41*\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
				packlen_rewrited=make_motd(rewrited,"[Proxy] Use 13w42a or later to play!",inbound_info.version);
			}
			else if(inbound[inbound[0]]==2)
			{
				mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, status: reject_gamerelay_13w41*\n",(char *)&(addrinfo_in.address),addrinfo_in.port);
				packlen_rewrited=make_kickreason(rewrited,"Proxy: Unsupported client, use 13w42a or later!");
			}
			send(socket_in,rewrited,packlen_rewrited,0);
			packet_destroy(inbound_info);
			close(socket_in);
			return 5;
		}
		conf_proxy proxyinfo=config_proxy_search(conf_in,inbound_info.address);
		if(proxyinfo.valid==0)
		{
			if(inbound_info.nextstate==1)
			{
				mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address);
				packlen_rewrited=make_motd(rewrited,"[Proxy] Use a legit address to play!",inbound_info.version);
			}
			else if(inbound_info.nextstate==2)
			{
				mksysmsg(0,logfile,runmode,conf_in->log.level,1,"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,inbound_info.username);
				packlen_rewrited=make_kickreason(rewrited,"Proxy: Please use a legit name to connect!");
			}
			send(socket_in,rewrited,packlen_rewrited,0);
			packet_destroy(inbound_info);
			close(socket_in);
			return 3;
		}
		int mkoutbound_status,outmsg_level;
		if(proxyinfo.srvenabled==1)
		{
			net_srvrecord srvrecords[128];
			if(net_srvresolve(proxyinfo.address,srvrecords)>0)
			{
				proxyinfo.address=(char *)realloc(proxyinfo.address,strlen(srvrecords[0].target)+1);
				strcpy(proxyinfo.address,srvrecords[0].target);
				proxyinfo.port=srvrecords[0].port;
				proxyinfo.srvenabled=0;
			}
		}
		mkoutbound_status=0;
		net_addr connaddr=net_resolve_dual(proxyinfo.address,addrinfo_in.family,netpriority_enabled);
		if(connaddr.family==0)
		{
			mkoutbound_status=NET_ENORECORD;
		}
		*socket_out=net_socket(NETSOCK_CONN,connaddr.family,&(connaddr.addr),proxyinfo.port,0);
		if(*socket_out==-1)
		{
			mkoutbound_status=NET_ECONNECT;
		}
		if(mkoutbound_status!=0)
		{
			outmsg_level=1;
		}
		else
		{
			if(inbound_info.nextstate==1)
			{
				outmsg_level=3;
			}
			else if(inbound_info.nextstate==2)
			{
				outmsg_level=2;
			}
		}
		switch(mkoutbound_status)
		{
			case 0:
				if(inbound_info.nextstate==1)
				{
					mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: accept\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port);
				}
				else if(inbound_info.nextstate==2)
				{
					mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: accept, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port,inbound_info.username);
				}
				if(proxyinfo.pheader==1)
				{
					if(connaddr.family==addrinfo_in.family)
					{
						net_addrp addrinfo_out=net_ntop(connaddr.family,&(connaddr.addr),0);
						if(addrinfo_in.family==AF_INET)
						{
							packlen_pheader=sprintf(pheader,"PROXY TCP4 %s %s %d %d\r\n",(char *)&(addrinfo_in.address_clean),(char *)&addrinfo_out,addrinfo_in.port,proxyinfo.port);
							send(*socket_out,pheader,packlen_pheader,0);
						}
						else if(addrinfo_in.family==AF_INET6)
						{
							packlen_pheader=sprintf(pheader,"PROXY TCP6 %s %s %d %d\r\n",(char *)&(addrinfo_in.address_clean),(char *)&addrinfo_out,addrinfo_in.port,proxyinfo.port);
							send(*socket_out,pheader,packlen_pheader,0);
						}
					}
				}
				if(proxyinfo.rewrite==1)
				{
					inbound_info.address=realloc(inbound_info.address,strlen(proxyinfo.address)+1);
					strcpy(inbound_info.address,proxyinfo.address);
					inbound_info.port=proxyinfo.port;
					packlen_rewrited=packet_write(rewrited,inbound_info);
					send(*socket_out,rewrited,packlen_rewrited,0);
				}
				else
				{
					send(*socket_out,inbound,packlen_inbound,0);
				}
				config_proxy_search_destroy(&proxyinfo);
				packet_destroy(inbound_info);
				return 0;
			case NET_ENORECORD:
			case NET_ECONNECT:
				if(inbound_info.nextstate==1)
				{
					packlen_rewrited=make_motd(rewrited,"[Proxy] Server Temporary Unavailable.",inbound_info.version);
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoresolve\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port);
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoconnect\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port);
					}
				}
				else if(inbound_info.nextstate==2)
				{
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port,inbound_info.username);
						packlen_rewrited=make_kickreason(rewrited,"Proxy(Internal): Temporary failed on resolving address for the target server, please try again later.");
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in->log.level,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",(char *)&(addrinfo_in.address),addrinfo_in.port,inbound_info.address,proxyinfo.address,proxyinfo.port,inbound_info.username);
						packlen_rewrited=make_kickreason(rewrited,"Proxy(Internal): Failed on connecting to the target server, please try again later.");
					}
				}
				send(socket_in,rewrited,packlen_rewrited,0);
				close(socket_in);
				config_proxy_search_destroy(&proxyinfo);
				packet_destroy(inbound_info);
				return 4;
		}
	}
}
