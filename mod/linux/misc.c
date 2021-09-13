/*
	misc.c: Misc Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta1
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <string.h>
int backbone(int socket_in, int * socket_out, char * logfile, unsigned short runmode, conf conf_in, struct sockaddr_in addrinfo_in)
{
	unsigned char inbound[BUFSIZ],outbound[BUFSIZ],rewrited[BUFSIZ],pheader[105];
	int packlen_inbound,packlen_outbound,packlen_rewrited,packlen_pheader;
	struct sockaddr_in addr_outbound;
	memset(inbound,0,BUFSIZ);
	memset(outbound,0,BUFSIZ);
	memset(rewrited,0,BUFSIZ);
	memset(pheader,0,105);
	packlen_inbound=recv(socket_in,inbound,BUFSIZ,0);
	if(packlen_inbound==0)
	{
		close(socket_in);
		return 1;
	}
	if(ismcproto(inbound,packlen_inbound)==0)
	{
		mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, status: reject_unidentproto\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port));
		close(socket_in);
		return 2;
	}
	if(inbound[0]==0xFE)
	{
		int motd_version=legacy_motd_protocol_identify(inbound);
		if(motd_version==PVER_M_LEGACY3)
		{
			unsigned char tmp[BUFSIZ];
			int packlen_tmp;
			int packet_should_length=0x20;
			int is_host_found=0;
			while(packlen_inbound<packet_should_length)
			{
				bzero(tmp,BUFSIZ);
				packlen_tmp=recv(socket_in,tmp,BUFSIZ,MSG_DONTWAIT);
				if(packlen_tmp>0)
				{
					packlen_inbound=datcat(inbound,packlen_inbound,tmp,packlen_tmp);
				}
				if((inbound[0x1F]!=0)&&(is_host_found==0))
				{
					is_host_found=1;
					packet_should_length=packet_should_length+inbound[0x1F]*2+4;
				}
			}
			p_motd_legacy inbound_info=packet_read_legacy_motd(inbound,packlen_inbound);
			conf_map * proxyinfo=getproxyinfo(&conf_in,inbound_info.address);
			if(proxyinfo==NULL)
			{
				if(conf_in.enable_default==0)
				{
					mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),inbound_info.address);
					packlen_rewrited=make_motd_legacy(inbound_info.version,"[Proxy] Use a legit address to play!",motd_version,rewrited);
					send(socket_in,rewrited,packlen_rewrited,0);
					close(socket_in);
					return 3;
				}
				else if(conf_in.enable_default==1)
				{
					proxyinfo=&(conf_in.relay_default);
				}
			}
			int mkoutbound_status,outmsg_level;
			if(proxyinfo->to_inet_hybridmode==1)
			{
				net_srvrecord srvrecords[128];
				if(net_srvresolve(proxyinfo->to_inet_addr,srvrecords)>0)
				{
					strcpy(proxyinfo->to_inet_addr,srvrecords[0].target);
					proxyinfo->to_inet_port=srvrecords[0].port;
					proxyinfo->to_inet_hybridmode=0;
				}
			}
			mkoutbound_status=0;
			void * connaddr=net_resolve(proxyinfo->to_inet_addr,AF_INET);
			if(connaddr==NULL)
			{
				mkoutbound_status=NET_ENORECORD;
			}
			*socket_out=net_socket(NETSOCK_CONN,AF_INET,connaddr,proxyinfo->to_inet_port,0);
			if(*socket_out==-1)
			{
				mkoutbound_status=NET_ECONNECT;
			}
			char * connaddr_strp=inet_ntoa(*((struct in_addr *)connaddr));
			free(connaddr);
			connaddr=NULL;
			char * connaddr_str=(char *)malloc(strlen(connaddr_strp)+1);
			strcpy(connaddr_str,connaddr_strp);
			connaddr_strp=NULL;
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
					mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: accept\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port);
					if(proxyinfo->enable_pheader==1)
					{
						packlen_pheader=sprintf(pheader,"PROXY TCP4 %s %s %d %d\r\n",inet_ntoa(addrinfo_in.sin_addr),connaddr_str,ntohs(addrinfo_in.sin_port),proxyinfo->to_inet_port);
						send(*socket_out,pheader,packlen_pheader,0);
					}
					if(proxyinfo->enable_rewrite==1)
					{
						strcpy(inbound_info.address,proxyinfo->to_inet_addr);
						inbound_info.port=proxyinfo->to_inet_port;
						packlen_rewrited=packet_write_legacy_motd(inbound_info,rewrited);
						send(*socket_out,rewrited,packlen_rewrited,0);
					}
					else
					{
						send(*socket_out,inbound,packlen_inbound,0);
					}
					return 0;
				case NET_ENORECORD:
				case NET_ECONNECT:
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoresolve\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port);
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoconnect\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port);
					}
					packlen_rewrited=make_motd_legacy(inbound_info.version,"[Proxy] Server Temporary Unavailable.",motd_version,rewrited);
					send(socket_in,rewrited,packlen_rewrited,0);
					close(socket_in);
					return 4;
			}
		}
		else
		{
			mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: motd, status: reject_motdrelay_oldclient\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port));
			packlen_rewrited=make_motd_legacy(0,"Proxy: Please use direct connect.",legacy_motd_protocol_identify(inbound),rewrited);
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		}
	}
	else if(inbound[0]==2)
	{
		int login_version=handshake_protocol_identify(inbound,packlen_inbound);
		if(login_version==PVER_L_LEGACY1)
		{
			mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: game, status: reject_gamerelay_oldclient\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port));
			packlen_rewrited=make_kickreason_legacy("Proxy: Unsupported client, use 12w04a or later!",rewrited);
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		}
		else if(login_version==PVER_L_LEGACY3)
		{
			mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: game, status: reject_gamerelay_12w17a\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port));
			packlen_rewrited=make_kickreason_legacy("Proxy: Unsupported client, use 12w18a or later!",rewrited);
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		}
		else if((login_version==PVER_L_LEGACY2)||(login_version==PVER_L_LEGACY4))
		{
			p_login_legacy inbound_info=packet_read_legacy_login(inbound,packlen_inbound,login_version);
			conf_map * proxyinfo=getproxyinfo(&conf_in,inbound_info.address);
			if(proxyinfo==NULL)
			{
				if(conf_in.enable_default==0)
				{
					mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),inbound_info.address,inbound_info.username);
					packlen_rewrited=make_kickreason_legacy("Proxy: Please use a legit name to connect!",rewrited);
					send(socket_in,rewrited,packlen_rewrited,0);
					close(socket_in);
					return 3;
				}
				else if(conf_in.enable_default==1)
				{
					proxyinfo=&(conf_in.relay_default);
				}
			}
			int mkoutbound_status,outmsg_level;
			if(proxyinfo->to_inet_hybridmode==1)
			{
				net_srvrecord srvrecords[128];
				if(net_srvresolve(proxyinfo->to_inet_addr,srvrecords)>0)
				{
					strcpy(proxyinfo->to_inet_addr,srvrecords[0].target);
					proxyinfo->to_inet_port=srvrecords[0].port;
					proxyinfo->to_inet_hybridmode=0;
				}
			}
			mkoutbound_status=0;
			void * connaddr=net_resolve(proxyinfo->to_inet_addr,AF_INET);
			if(connaddr==NULL)
			{
				mkoutbound_status=NET_ENORECORD;
			}
			*socket_out=net_socket(NETSOCK_CONN,AF_INET,connaddr,proxyinfo->to_inet_port,0);
			if(*socket_out==-1)
			{
				mkoutbound_status=NET_ECONNECT;
			}
			char * connaddr_strp=inet_ntoa(*((struct in_addr *)connaddr));
			free(connaddr);
			connaddr=NULL;
			char * connaddr_str=(char *)malloc(strlen(connaddr_strp)+1);
			strcpy(connaddr_str,connaddr_strp);
			connaddr_strp=NULL;
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
					mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: accept, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,inbound_info.username);
					if(proxyinfo->enable_pheader==1)
					{
						packlen_pheader=sprintf(pheader,"PROXY TCP4 %s %s %d %d\r\n",inet_ntoa(addrinfo_in.sin_addr),connaddr_str,ntohs(addrinfo_in.sin_port),proxyinfo->to_inet_port);
						send(*socket_out,pheader,packlen_pheader,0);
					}
					if(proxyinfo->enable_rewrite==1)
					{
						strcpy(inbound_info.address,proxyinfo->to_inet_addr);
						inbound_info.port=proxyinfo->to_inet_port;
						packlen_rewrited=packet_write_legacy_login(inbound_info,rewrited);
						send(*socket_out,rewrited,packlen_rewrited,0);
					}
					else
					{
						send(*socket_out,inbound,packlen_inbound,0);
					}
					return 0;
				case NET_ENORECORD:
				case NET_ECONNECT:
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,inbound_info.username);
						packlen_rewrited=make_kickreason_legacy("Proxy(Internal): Temporary failed on resolving address for the target server, please try again later.",rewrited);
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,inbound_info.username);
						packlen_rewrited=make_kickreason_legacy("Proxy(Internal): Failed on connecting to the target server, please try again later.",rewrited);
					}
					send(socket_in,rewrited,packlen_rewrited,0);
					close(socket_in);
					return 4;
			}
		}
	}
	else
	{
		if((inbound[packlen_inbound-1]==1)||(inbound[packlen_inbound-1]==2))
		{
			int packlen_inbound_part1,packlen_inbound_part2;
			unsigned char inbound_part2[BUFSIZ];
			bzero(inbound_part2,BUFSIZ);
			packlen_inbound_part1=packlen_inbound;
			packlen_inbound_part2=recv(socket_in,inbound_part2,BUFSIZ,0);
			packlen_inbound=datcat(inbound,packlen_inbound_part1,inbound_part2,packlen_inbound_part2);
		}
		p_handshake inbound_info=packet_read(inbound);
		if(inbound_info.version==0)
		{
			if(inbound[inbound[0]]==1)
			{
				mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: motd, status: reject_motdrelay_13w41*\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port));
				packlen_rewrited=make_motd(inbound_info.version,"[Proxy] Use 13w42a or later to play!",rewrited);
			}
			else if(inbound[inbound[0]]==2)
			{
				mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: game, status: reject_gamerelay_13w41*\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port));
				packlen_rewrited=make_kickreason("Proxy: Unsupported client, use 13w42a or later!",rewrited);
			}
			send(socket_in,rewrited,packlen_rewrited,0);
			close(socket_in);
			return 5;
		}
		conf_map * proxyinfo=getproxyinfo(&conf_in,inbound_info.address);
		if(proxyinfo==NULL)
		{
			if(conf_in.enable_default==0)
			{
				if(inbound_info.nextstate==1)
				{
					mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),inbound_info.address);
					packlen_rewrited=make_motd(inbound_info.version,"[Proxy] Use a legit address to play!",rewrited);
				}
				else if(inbound_info.nextstate==2)
				{
					mksysmsg(0,logfile,runmode,conf_in.loglevel,1,"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),inbound_info.address,inbound_info.username);
					packlen_rewrited=make_kickreason("Proxy: Please use a legit name to connect!",rewrited);
				}
				send(socket_in,rewrited,packlen_rewrited,0);
				close(socket_in);
				return 3;
			}
			else if(conf_in.enable_default==1)
			{
				proxyinfo=&(conf_in.relay_default);
			}
		}
		int mkoutbound_status,outmsg_level;
		if(proxyinfo->to_inet_hybridmode==1)
		{
			net_srvrecord srvrecords[128];
			if(net_srvresolve(proxyinfo->to_inet_addr,srvrecords)>0)
			{
				strcpy(proxyinfo->to_inet_addr,srvrecords[0].target);
				proxyinfo->to_inet_port=srvrecords[0].port;
				proxyinfo->to_inet_hybridmode=0;
			}
		}
		mkoutbound_status=0;
		void * connaddr=net_resolve(proxyinfo->to_inet_addr,AF_INET);
		if(connaddr==NULL)
		{
			mkoutbound_status=NET_ENORECORD;
		}
		*socket_out=net_socket(NETSOCK_CONN,AF_INET,connaddr,proxyinfo->to_inet_port,0);
		if(*socket_out==-1)
		{
			mkoutbound_status=NET_ECONNECT;
		}
		char * connaddr_strp=inet_ntoa(*((struct in_addr *)connaddr));
		free(connaddr);
		connaddr=NULL;
		char * connaddr_str=(char *)malloc(strlen(connaddr_strp)+1);
		strcpy(connaddr_str,connaddr_strp);
		connaddr_strp=NULL;
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
					mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: accept\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port);
				}
				else if(inbound_info.nextstate==2)
				{
					mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: accept, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,inbound_info.username);
				}
				if(proxyinfo->enable_pheader==1)
				{
					packlen_pheader=sprintf(pheader,"PROXY TCP4 %s %s %d %d\r\n",inet_ntoa(addrinfo_in.sin_addr),connaddr_str,ntohs(addrinfo_in.sin_port),proxyinfo->to_inet_port);
					send(*socket_out,pheader,packlen_pheader,0);
				}
				if(proxyinfo->enable_rewrite==1)
				{
					strcpy(inbound_info.address,proxyinfo->to_inet_addr);
					inbound_info.port=proxyinfo->to_inet_port;
					packlen_rewrited=packet_write(inbound_info,rewrited);
					send(*socket_out,rewrited,packlen_rewrited,0);
				}
				else
				{
					send(*socket_out,inbound,packlen_inbound,0);
				}
				return 0;
			case NET_ENORECORD:
			case NET_ECONNECT:
				if(inbound_info.nextstate==1)
				{
					packlen_rewrited=make_motd(inbound_info.version,"[Proxy] Server Temporary Unavailable.",rewrited);
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoresolve\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port);
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoconnect\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port);
					}
				}
				else if(inbound_info.nextstate==2)
				{
					if(mkoutbound_status==NET_ENORECORD)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,inbound_info.username);
						packlen_rewrited=make_kickreason("Proxy(Internal): Temporary failed on resolving address for the target server, please try again later.",rewrited);
					}
					else if(mkoutbound_status==NET_ECONNECT)
					{
						mksysmsg(0,logfile,runmode,conf_in.loglevel,outmsg_level,"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",inet_ntoa(addrinfo_in.sin_addr),ntohs(addrinfo_in.sin_port),proxyinfo->from,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,inbound_info.username);
						packlen_rewrited=make_kickreason("Proxy(Internal): Failed on connecting to the target server, please try again later.",rewrited);
					}
				}
				send(socket_in,rewrited,packlen_rewrited,0);
				close(socket_in);
				return 4;
		}
	}
}
