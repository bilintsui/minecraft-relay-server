/*
	mcrelay.c: Main source code for Minecraft Relay Server
	A component of Minecraft Relay Server.
	

	Minecraft Relay Server, version 1.1-beta3
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <sys/stat.h>
#include "mod/basic.h"
#include "mod/config.h"
#include "mod/network.h"
#include "mod/proto_legacy.h"
#include "mod/proto_modern.h"
struct conf config;
char configfile[512],cwd[512],config_logfull[BUFSIZ];
void deal_sigterm()
{
	unlink("/tmp/mcrelay.pid");
	exit(0);
}
void deal_sigusr1()
{
	struct conf config_new;
	char time_str[32],configfile_full[BUFSIZ];
	FILE * logfd=fopen(config_logfull,"a");
	bzero(time_str,32);
	gettime(time_str);
	fprintf(logfd,"[%s] [INFO] Reload config from file: %s\n",time_str,configfile);
	bzero(configfile_full,BUFSIZ);
	sprintf(configfile_full,"%s/%s",cwd,configfile);
	switch(config_load(configfile_full,&config_new))
	{
		case 0:
			config=config_new;
			if(config.log[0]!='/')
			{
				sprintf(config_logfull,"%s/%s",cwd,config.log);
			}
			else
			{
				sprintf(config_logfull,"%s",config.log);
			}
			fprintf(logfd,"[%s] [INFO] Configuration reloaded.\n",time_str);
			break;
		case 1:
			fprintf(logfd,"[%s] [WARN] Cannot read config file: %s, will keep your old configurations.\n",time_str,configfile);
			break;
		case 2:
			fprintf(logfd,"[%s] [WARN] Error in configurations: Argument \"runmode\" is missing, will keep your old configurations.\n",time_str);
			break;
		case 3:
			fprintf(logfd,"[%s] [WARN] Error in configurations: Argument \"log\" is missing, will keep your old configurations.\n",time_str);
			break;
		case 4:
			fprintf(logfd,"[%s] [WARN] Error in configurations: Argument \"bind\" is missing or invalid, will keep your old configurations.\n",time_str);
			break;
		case 5:
			fprintf(logfd,"[%s] [WARN] Error in configurations: You don't have any valid record for relay, will keep your old configurations.\n",time_str);
			break;
	}
	fclose(logfd);
}
int main(int argc, char ** argv)
{
	char time_str[32];
	char *bindip,*connip;
	char **addresses;
	int socket_inbound_server,strulen,socket_inbound_client,connip_resolved;
	struct sockaddr_in addr_inbound_server,addr_inbound_client;
	struct sockaddr_un uddr_inbound_server,uddr_inbound_client;
	unsigned short bindport,connport;
	signal(SIGTERM,deal_sigterm);
	signal(SIGINT,deal_sigterm);
	connip_resolved=0;
	bzero(cwd,512);
	getcwd(cwd,512);
	if(argc!=2)
	{
		fprintf(stderr,"Minecraft Relay Server [Version:1.1-beta3]\n(C) 2020 Bilin Tsui. All rights reserved.\n\nUsage: %s <arguments|config_file>\n\nArguments\n\t-r:\tReload config on the running instance.\n\t-t:\tTerminate the running instance\n\nSee more, watch: https://github.com/bilintsui/minecraft-relay-server\n",argv[0]);
		return 22;
	}
	FILE * pidfd=fopen("/tmp/mcrelay.pid","r");
	int prevpid;
	char * ptr_argv1=argv[1];
	if(*ptr_argv1=='-')
	{
		ptr_argv1++;
		if(strcmp(ptr_argv1,"r")==0)
		{
			if(pidfd==NULL)
			{
				fprintf(stderr,"[CRIT] Error: Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGUSR1)==0)
			{
				printf("[INFO] Successfully send reload signal to currently running process.\n");
				return 0;
			}
			else
			{
				fprintf(stderr,"[CRIT] Failed on send reload signal to currently running process.\n");
				return 3;
			}
		}
		else if(strcmp(ptr_argv1,"t")==0)
		{
			if(pidfd==NULL)
			{
				fprintf(stderr,"[CRIT] Error: Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGTERM)==0)
			{
				fprintf(stdout,"[INFO] Successfully send terminate signal to currently running process.\n");
				return 0;
			}
			else
			{
				fprintf(stderr,"[CRIT] Failed on send terminate signal to currently running process.\n");
				return 3;
			}
		}
	}
	else
	{
		if(pidfd!=NULL)
		{
			fscanf(pidfd,"%d",&prevpid);
			if(kill(prevpid,0)==0)
			{
				fprintf(stderr,"[CRIT] You cannot running multiple instances in one time. Previous running process PID: %d.\n",prevpid);
				return 1;
			}
		}
	}
	fprintf(stdout,"Minecraft Relay Server [Version:1.1-beta3]\n(C) 2020 Bilin Tsui. All rights reserved.\n\n");
	bindip="0.0.0.0";
	bindport=25565;
	bzero(configfile,512);
	strcpy(configfile,argv[1]);
	fprintf(stdout,"[INFO] Loading configurations from file: %s\n\n",configfile);
	switch(config_load(configfile,&config))
	{
		case 0:
			if(config.log[0]!='/')
			{
				sprintf(config_logfull,"%s/%s",cwd,config.log);
			}
			else
			{
				sprintf(config_logfull,"%s",config.log);
			}
			break;
		case 1:
			fprintf(stderr,"[CRIT] Cannot read config file: %s\n",configfile);
			return 2;
		case 2:
			fprintf(stderr,"[CRIT] Error in configurations: Argument \"runmode\" is missing.\n");
			return 22;
		case 3:
			fprintf(stderr,"[CRIT] Error in configurations: Argument \"log\" is missing.\n");
			return 22;
		case 4:
			fprintf(stderr,"[CRIT] Error in configurations: Argument \"bind\" is missing or invalid.\n");
			return 22;
		case 5:
			fprintf(stderr,"[CRIT] Error in configurations: You don't have any valid record for relay.\n");
			return 22;
	}
	if(config.bind.type==TYPE_INET)
	{
		if(inet_addr(config.bind.inet_addr)==-1)
		{
			fprintf(stdout,"[WARN] Bad argument: bind_address. Use default address %s.\n",bindip);
		}
		else
		{
			bindip=config.bind.inet_addr;
		}
		if((config.bind.inet_port<1)||(config.bind.inet_port>65535))
		{
			fprintf(stdout,"[WARN] Bad argument: bind_port. Use default port %d.\n",bindport);
		}
		else
		{
			bindport=config.bind.inet_port;
		}
		socket_inbound_server=socket(AF_INET,SOCK_STREAM,0);
		addr_inbound_server=net_mksockaddr_in(AF_INET,htonl(inet_addr(bindip)),bindport);
		strulen=sizeof(struct sockaddr_in);
		fprintf(stdout,"[INFO] Binding on %s:%d...\n",inet_ntoa(addr_inbound_server.sin_addr),ntohs(addr_inbound_server.sin_port));
		if(bind(socket_inbound_server,(struct sockaddr *)&addr_inbound_server,strulen)==-1){fprintf(stderr,"[CRIT] Bind Failed!\n");return 2;}
		fprintf(stdout,"[INFO] Bind Successful.\n\n");
	}
	else if(config.bind.type==TYPE_UNIX)
	{
		unlink(config.bind.unix_path);
		socket_inbound_server=socket(AF_UNIX,SOCK_STREAM,0);
		uddr_inbound_server=net_mksockaddr_un(config.bind.unix_path);
		strulen=sizeof(uddr_inbound_server);
		fprintf(stdout,"[INFO] Binding on %s...\n",uddr_inbound_server.sun_path);
		if(bind(socket_inbound_server,(struct sockaddr *)&uddr_inbound_server,strulen)==-1){fprintf(stderr,"[CRIT] Bind Failed!\n");return 2;}
		if(chmod(config.bind.unix_path,S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH)==-1){fprintf(stderr,"[CRIT] Set Permission Failed!\n");return 13;}
		fprintf(stdout,"[INFO] Bind Successful.\n\n");
	}
	fprintf(stdout,"[INFO] For more information, watch log file: %s\n",config.log);
	int pid;
	if(config.runmode==2)
	{
		pid=fork();
		if(pid>0)
		{
			FILE * pidfd=fopen("/tmp/mcrelay.pid","w");
			fprintf(pidfd,"%d",pid);
			fclose(pidfd);
			fprintf(stdout,"[INFO] Server running on PID: %d\n",pid);
			return 0;
		}
		else if(pid<0)
		{
			return 10;
		}
		setsid();
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		chdir("/");
		umask(0);
	}
	else
	{
		pid=getpid();
		FILE * pidfd=fopen("/tmp/mcrelay.pid","w");
		fprintf(pidfd,"%d",pid);
		fclose(pidfd);
	}
	signal(SIGUSR1,deal_sigusr1);
	signal(SIGCHLD,SIG_IGN);
	while(1)
	{
		while(listen(socket_inbound_server,1)==-1);
		bzero(time_str,32);
		gettime(time_str);
		if(config.bind.type==TYPE_INET)
		{
			socket_inbound_client=accept(socket_inbound_server,(struct sockaddr *)&addr_inbound_client,&strulen);
		}
		else if(config.bind.type==TYPE_UNIX)
		{
			socket_inbound_client=accept(socket_inbound_server,(struct sockaddr *)&uddr_inbound_client,&strulen);
		}
		pid=fork();
		if(pid>0)
		{
			close(socket_inbound_client);
		}
		else if(pid<0)
		{
			break;
		}
		else
		{
			signal(SIGUSR1,SIG_DFL);
			close(socket_inbound_server);
			unsigned char inbound[BUFSIZ],outbound[BUFSIZ],rewrited[BUFSIZ];
			int socket_outbound,packlen_inbound,packlen_outbound,packlen_rewrited;
			struct sockaddr_in addr_outbound;
			struct sockaddr_un uddr_outbound;
			bzero(inbound,BUFSIZ);
			bzero(outbound,BUFSIZ);
			bzero(rewrited,BUFSIZ);
			packlen_inbound=recv(socket_inbound_client,inbound,BUFSIZ,0);
			FILE * logfd=fopen(config_logfull,"a");
			if(inbound[0]==0xFE)
			{
				int motd_version=legacy_motd_protocol_identify(inbound);
				if(motd_version==PVER_M_LEGACY3)
				{
					struct p_motd_legacy inbound_info=packet_read_legacy_motd(inbound,packlen_inbound);
					struct conf_map * proxyinfo=getproxyinfo(&config,inbound_info.address);
					if(proxyinfo==NULL)
					{
						packlen_rewrited=make_motd_legacy(inbound_info.version,"[Proxy] Use a legit address to play!",motd_version,rewrited);
						send(socket_inbound_client,rewrited,packlen_rewrited,0);
						shutdown(socket_inbound_client,SHUT_RDWR);
						close(socket_inbound_client);
						return 0;
					}
					else
					{
						int mkoutbound_status;
						if(proxyinfo->to_type==TYPE_INET)
						{
							if(proxyinfo->to_inet_hybridmode==1)
							{
								struct stru_net_srvrecord srvrecords[128];
								if(net_srvresolve(proxyinfo->to_inet_addr,srvrecords)>0)
								{
									strcpy(proxyinfo->to_inet_addr,srvrecords[0].target);
									proxyinfo->to_inet_port=srvrecords[0].port;
								}
							}
							mkoutbound_status=net_mkoutbound(proxyinfo->to_type,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,&socket_outbound);
						}
						else if(proxyinfo->to_type==TYPE_UNIX)
						{
							mkoutbound_status=net_mkoutbound(proxyinfo->to_type,proxyinfo->to_unix_path,0,&socket_outbound);
						}
						if(mkoutbound_status!=0)
						{
							packlen_rewrited=make_motd_legacy(inbound_info.version,"[Proxy] Server Temporary Unavailable.",motd_version,rewrited);
							send(socket_inbound_client,rewrited,packlen_rewrited,0);
							shutdown(socket_inbound_client,SHUT_RDWR);
							close(socket_inbound_client);
							return 0;
						}
						else
						{
							if(config.bind.type==TYPE_UNIX)
							{
								fprintf(logfd,"[%s] [INFO] status, host: %s\n",time_str,inbound_info.address);
							}
							else if(config.bind.type==TYPE_INET)
							{
								fprintf(logfd,"[%s] [INFO] status from %s:%d, host: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.address);
							}
							if(proxyinfo->enable_rewrite==1)
							{
								strcpy(inbound_info.address,proxyinfo->to_inet_addr);
								inbound_info.port=proxyinfo->to_inet_port;
								packlen_rewrited=packet_write_legacy_motd(inbound_info,rewrited);
								send(socket_outbound,rewrited,packlen_rewrited,0);
							}
							else
							{
								send(socket_outbound,inbound,packlen_inbound,0);
							}
						}
					}
				}
				else
				{
					packlen_rewrited=make_motd_legacy(0,"Proxy: Please use direct connect.",legacy_motd_protocol_identify(inbound),rewrited);
					send(socket_inbound_client,rewrited,packlen_rewrited,0);
					shutdown(socket_inbound_client,SHUT_RDWR);
					close(socket_inbound_client);
					return 0;
				}
			}
			else if(inbound[0]==2)
			{
				int login_version=handshake_protocol_identify(inbound,packlen_inbound);
				if(login_version==PVER_L_LEGACY1)
				{
					packlen_rewrited=make_kickreason_legacy("Proxy: Unsupported client, use 12w04a or later!",rewrited);
					send(socket_inbound_client,rewrited,packlen_rewrited,0);
					shutdown(socket_inbound_client,SHUT_RDWR);
					close(socket_inbound_client);
					return 0;
				}
				else if(login_version==PVER_L_LEGACY3)
				{
					packlen_rewrited=make_kickreason_legacy("Proxy: Unsupported client, use 12w18a or later!",rewrited);
					send(socket_inbound_client,rewrited,packlen_rewrited,0);
					shutdown(socket_inbound_client,SHUT_RDWR);
					close(socket_inbound_client);
					return 0;
				}
				else
				{
					struct p_login_legacy inbound_info=packet_read_legacy_login(inbound,packlen_inbound,login_version);
					struct conf_map * proxyinfo=getproxyinfo(&config,inbound_info.address);
					if(proxyinfo==NULL)
					{
						packlen_rewrited=make_kickreason_legacy("Proxy: Please use a legit name to connect!",rewrited);
						send(socket_inbound_client,rewrited,packlen_rewrited,0);
						shutdown(socket_inbound_client,SHUT_RDWR);
						close(socket_inbound_client);
						return 0;
					}
					else
					{
						int mkoutbound_status;
						if(proxyinfo->to_type==TYPE_INET)
						{
							if(proxyinfo->to_inet_hybridmode==1)
							{
								struct stru_net_srvrecord srvrecords[128];
								if(net_srvresolve(proxyinfo->to_inet_addr,srvrecords)>0)
								{
									strcpy(proxyinfo->to_inet_addr,srvrecords[0].target);
									proxyinfo->to_inet_port=srvrecords[0].port;
								}
							}
							mkoutbound_status=net_mkoutbound(proxyinfo->to_type,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,&socket_outbound);
						}
						else if(proxyinfo->to_type==TYPE_UNIX)
						{
							mkoutbound_status=net_mkoutbound(proxyinfo->to_type,proxyinfo->to_unix_path,0,&socket_outbound);
						}
						if(mkoutbound_status==0)
						{
							if(config.bind.type==TYPE_UNIX)
							{
								fprintf(logfd,"[%s] [INFO] login, host: %s, username: %s\n",time_str,inbound_info.address,inbound_info.username);
							}
							else if(config.bind.type==TYPE_INET)
							{
								fprintf(logfd,"[%s] [INFO] login from %s:%d, host: %s, username: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.address,inbound_info.username);
							}
							if(proxyinfo->enable_rewrite==1)
							{
								strcpy(inbound_info.address,proxyinfo->to_inet_addr);
								inbound_info.port=proxyinfo->to_inet_port;
								packlen_rewrited=packet_write_legacy_login(inbound_info,rewrited);
								send(socket_outbound,rewrited,packlen_rewrited,0);
							}
							else
							{
								send(socket_outbound,inbound,packlen_inbound,0);
							}
						}
						else if(mkoutbound_status==1)
						{
							packlen_rewrited=make_kickreason_legacy("Proxy(Internal): Temporary failed on resolving address for the target server, please try again later.",rewrited);
							send(socket_inbound_client,rewrited,packlen_rewrited,0);
							shutdown(socket_inbound_client,SHUT_RDWR);
							close(socket_inbound_client);
							return 0;
						}
						else if(mkoutbound_status==2)
						{
							packlen_rewrited=make_kickreason_legacy("Proxy(Internal): Failed on connecting to the target server, please try again later.",rewrited);
							send(socket_inbound_client,rewrited,packlen_rewrited,0);
							shutdown(socket_inbound_client,SHUT_RDWR);
							close(socket_inbound_client);
							return 0;
						}
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
					packlen_inbound_part2=recv(socket_inbound_client,inbound_part2,BUFSIZ,0);
					packlen_inbound=datcat(inbound,packlen_inbound_part1,inbound_part2,packlen_inbound_part2);
				}
				struct p_handshake inbound_info=packet_read(inbound);
				if(inbound_info.version==0)
				{
					if(inbound_info.nextstate==1)
					{
						packlen_rewrited=make_motd(inbound_info.version,"[Proxy] Use 13w42a or later to play!",rewrited);
					}
					else if(inbound_info.nextstate==2)
					{
						packlen_rewrited=make_kickreason("Proxy: Unsupported client, use 13w42a or later!",rewrited);
					}
					send(socket_inbound_client,rewrited,packlen_rewrited,0);
					shutdown(socket_inbound_client,SHUT_RDWR);
					close(socket_inbound_client);
					return 0;
				}
				struct conf_map * proxyinfo=getproxyinfo(&config,inbound_info.address);
				if(proxyinfo==NULL)
				{
					if(inbound_info.nextstate==1)
					{
						packlen_rewrited=make_motd(inbound_info.version,"[Proxy] Use a legit address to play!",rewrited);
					}
					else if(inbound_info.nextstate==2)
					{
						packlen_rewrited=make_kickreason("Proxy: Please use a legit name to connect!",rewrited);
					}
					send(socket_inbound_client,rewrited,packlen_rewrited,0);
					shutdown(socket_inbound_client,SHUT_RDWR);
					close(socket_inbound_client);
					return 0;
				}
				else
				{
					int mkoutbound_status;
					if(proxyinfo->to_type==TYPE_INET)
					{
						if(proxyinfo->to_inet_hybridmode==1)
						{
							struct stru_net_srvrecord srvrecords[128];
							if(net_srvresolve(proxyinfo->to_inet_addr,srvrecords)>0)
							{
								strcpy(proxyinfo->to_inet_addr,srvrecords[0].target);
								proxyinfo->to_inet_port=srvrecords[0].port;
							}
						}
						mkoutbound_status=net_mkoutbound(proxyinfo->to_type,proxyinfo->to_inet_addr,proxyinfo->to_inet_port,&socket_outbound);
					}
					else if(proxyinfo->to_type==TYPE_UNIX)
					{
						mkoutbound_status=net_mkoutbound(proxyinfo->to_type,proxyinfo->to_unix_path,0,&socket_outbound);
					}
					if(mkoutbound_status==0)
					{
						if(inbound_info.nextstate==1)
						{
							if(config.bind.type==TYPE_UNIX)
							{
								fprintf(logfd,"[%s] [INFO] status, host: %s\n",time_str,inbound_info.address);
							}
							else if(config.bind.type==TYPE_INET)
							{
								fprintf(logfd,"[%s] [INFO] status from %s:%d, host: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.address);
							}
							
						}
						else if(inbound_info.nextstate==2)
						{
							if(config.bind.type==TYPE_UNIX)
							{
								fprintf(logfd,"[%s] [INFO] login, host: %s, username: %s\n",time_str,inbound_info.address,inbound_info.username);
							}
							else if(config.bind.type==TYPE_INET)
							{
								fprintf(logfd,"[%s] [INFO] login from %s:%d, host: %s, username: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.address,inbound_info.username);
							}
						}
						if(proxyinfo->enable_rewrite==1)
						{
							strcpy(inbound_info.address,proxyinfo->to_inet_addr);
							inbound_info.port=proxyinfo->to_inet_port;
							packlen_rewrited=packet_write(inbound_info,rewrited);
							send(socket_outbound,rewrited,packlen_rewrited,0);
						}
						else
						{
							send(socket_outbound,inbound,packlen_inbound,0);
						}
					}
					else if(mkoutbound_status==1)
					{
						if(inbound_info.nextstate==1)
						{
							packlen_rewrited=make_motd(inbound_info.version,"[Proxy] Server Temporary Unavailable.",rewrited);
						}
						else if(inbound_info.nextstate==2)
						{
							packlen_rewrited=make_kickreason("Proxy(Internal): Temporary failed on resolving address for the target server, please try again later.",rewrited);
						}
						send(socket_inbound_client,rewrited,packlen_rewrited,0);
						shutdown(socket_inbound_client,SHUT_RDWR);
						close(socket_inbound_client);
						return 0;
					}
					else if(mkoutbound_status==2)
					{
						if(inbound_info.nextstate==1)
						{
							packlen_rewrited=make_motd(inbound_info.version,"[Proxy] Server Temporary Unavailable.",rewrited);
						}
						else if(inbound_info.nextstate==2)
						{
							packlen_rewrited=make_kickreason("Proxy(Internal): Failed on connecting to the target server, please try again later.",rewrited);
						}
						send(socket_inbound_client,rewrited,packlen_rewrited,0);
						shutdown(socket_inbound_client,SHUT_RDWR);
						close(socket_inbound_client);
						return 0;
					}
				}
			}
			fclose(logfd);
			if(net_relay(&socket_inbound_client,&socket_outbound)==0)
			{
				return 0;
			}
		}
	}
}
