/*
	mcrelay.c: Main source code for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1-beta2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "mod/basic.h"
#include "mod/config.h"
#include "mod/proto_legacy.h"
#include "mod/proto_modern.h"
int main(int argc, char * argv[])
{
	char str[INET_ADDRSTRLEN],time_str[32];
	char *bindip,*connip;
	char **addresses;
	int socket_inbound_server,strulen,socket_inbound_client,connip_resolved;
	struct sockaddr_in addr_inbound_server,addr_inbound_client;
	struct sockaddr_un uddr_inbound_server,uddr_inbound_client;
	struct conf config;
	unsigned short bindport,connport;
	connip_resolved=0;
	printf("Minecraft Relay Server [Version:1.1-beta2]\n(C) 2020 Bilin Tsui. All rights reserved.\n\n");
	if(argc!=2)
	{
		printf("Usage: %s config_file\n\nSee more, watch: https://github.com/bilintsui/minecraft-relay-server\n",argv[0]);
		return 1;
	}
	bindip="0.0.0.0";
	bindport=25565;
	printf("[INFO] Loading configurations from file: %s\n\n",argv[1]);
	config=config_load(argv[1]);
	if(config.log[0]!='/')
	{
		char cwd[512],log_full[BUFSIZ];
		bzero(cwd,512);
		bzero(log_full,BUFSIZ);
		getcwd(cwd,BUFSIZ);
		sprintf(log_full,"%s/%s",cwd,config.log);
		strcpy(config.log,log_full);
	}
	if(config.bind.type==TYPE_INET)
	{
		if(inet_addr(config.bind.inet_addr)==-1)
		{
			printf("[WARN] Bad argument: bind_address. Use default address %s.\n",bindip);
		}
		else
		{
			bindip=config.bind.inet_addr;
		}
		if((config.bind.inet_port<1)||(config.bind.inet_port>65535))
		{
			printf("[WARN] Bad argument: bind_port. Use default port %d.\n",bindport);
		}
		else
		{
			bindport=config.bind.inet_port;
		}
		socket_inbound_server=socket(AF_INET,SOCK_STREAM,0);
		addr_inbound_server=genSockConf(AF_INET,htonl(inet_addr(bindip)),bindport);
		strulen=sizeof(struct sockaddr_in);
		printf("[INFO] Binding on %s:%d...\n",inet_ntoa(addr_inbound_server.sin_addr),ntohs(addr_inbound_server.sin_port));
		if(bind(socket_inbound_server,(struct sockaddr *)&addr_inbound_server,strulen)==-1){printf("[CRIT] Bind Failed!\n");return 2;}
		printf("[INFO] Bind Successful.\n\n");
	}
	else if(config.bind.type==TYPE_UNIX)
	{
		unlink(config.bind.unix_path);
		socket_inbound_server=socket(AF_UNIX,SOCK_STREAM,0);
		uddr_inbound_server.sun_family=AF_UNIX;
		strcpy(uddr_inbound_server.sun_path,config.bind.unix_path);
		strulen=sizeof(uddr_inbound_server);
		printf("[INFO] Binding on %s...\n",uddr_inbound_server.sun_path);
		if(bind(socket_inbound_server,(struct sockaddr *)&uddr_inbound_server,strulen)==-1){printf("[CRIT] Bind Failed!\n");return 2;}
		if(chmod(config.bind.unix_path,S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH)==-1){printf("[CRIT] Set Permission Failed!\n");return 13;}
		printf("[INFO] Bind Successful.\n\n");
	}
	printf("[INFO] For more information, watch log file: %s\n",config.log);
	int pid;
	pid=fork();
	if(pid>0)
	{
		printf("[INFO] Server running on PID: %d\n",pid);
		exit(0);
	}
	else if(pid<0)
	{
		exit(10);
	}
	setsid();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	chdir("/");
	umask(0);
	signal(SIGCHLD, SIG_IGN);
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
			close(socket_inbound_server);
			unsigned char inbound[BUFSIZ],outbound[BUFSIZ],rewrited[BUFSIZ];
			int socket_outbound,packlen_inbound,packlen_outbound,packlen_rewrited;
			struct sockaddr_in addr_outbound;
			struct sockaddr_un uddr_outbound;
			bzero(inbound,BUFSIZ);
			bzero(outbound,BUFSIZ);
			bzero(rewrited,BUFSIZ);
			packlen_inbound=recv(socket_inbound_client,inbound,BUFSIZ,0);
			if((inbound[packlen_inbound-1]==1)||(inbound[packlen_inbound-1]==2))
			{
				int packlen_inbound_part1,packlen_inbound_part2;
				unsigned char inbound_part2[BUFSIZ];
				bzero(inbound_part2,BUFSIZ);
				packlen_inbound_part1=packlen_inbound;
				packlen_inbound_part2=recv(socket_inbound_client,inbound_part2,BUFSIZ,0);
				packlen_inbound=datcat(inbound,packlen_inbound_part1,inbound_part2,packlen_inbound_part2);
			}
			if(inbound[0]==2)
			{
				packlen_rewrited=make_kickreason_legacy("Proxy: Unsupported client, use 13w42a or later!",rewrited);
				send(socket_inbound_client,rewrited,packlen_rewrited,0);
				shutdown(socket_inbound_client,SHUT_RDWR);
				close(socket_inbound_client);
				return 3;
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
				return 3;
			}
			int rec_relay,found_relay;
			found_relay=0;
			FILE * logfd=fopen(config.log,"a");
			for(rec_relay=0;rec_relay<config.relay_count;rec_relay++)
			{
				if(strcmp(config.relay[rec_relay].from,inbound_info.addr)==0)
				{	
					found_relay=1;
					if(config.relay[rec_relay].to_type==TYPE_INET)
					{
						socket_outbound=socket(AF_INET,SOCK_STREAM,0);
						if(inet_addr(config.relay[rec_relay].to_inet_addr)==-1)
						{
							char ** addresses=getaddresses(config.relay[rec_relay].to_inet_addr);
							if(addresses==NULL)
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
								return 4;
							}
							else
							{
								addr_outbound=genSockConf(AF_INET,htonl(inet_addr(inet_ntop(AF_INET,addresses[0],str,sizeof(str)))),config.relay[rec_relay].to_inet_port);
								if(connect(socket_outbound,(struct sockaddr*)&addr_outbound,sizeof(struct sockaddr))==-1)
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
									return 5;
								}
								else
								{
									if(inbound_info.nextstate==1)
									{
										if(config.bind.type==TYPE_UNIX)
										{
											fprintf(logfd,"[%s] [INFO] status, host: %s\n",time_str,inbound_info.addr);
										}
										else if(config.bind.type==TYPE_INET)
										{
											fprintf(logfd,"[%s] [INFO] status from %s:%d, host: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.addr);
										}
										
									}
									else if(inbound_info.nextstate==2)
									{
										if(config.bind.type==TYPE_UNIX)
										{
											fprintf(logfd,"[%s] [INFO] login, host: %s, username: %s\n",time_str,inbound_info.addr,inbound_info.user);
										}
										else if(config.bind.type==TYPE_INET)
										{
											fprintf(logfd,"[%s] [INFO] login from %s:%d, host: %s, username: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.addr,inbound_info.user);
										}
									}
								}
							}
						}
						else
						{
							addr_outbound=genSockConf(AF_INET,htonl(inet_addr(config.relay[rec_relay].to_inet_addr)),config.relay[rec_relay].to_inet_port);
							if(connect(socket_outbound,(struct sockaddr*)&addr_outbound,sizeof(struct sockaddr))==-1)
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
								return 5;
							}
							else
							{
								if(inbound_info.nextstate==1)
								{
									if(config.bind.type==TYPE_UNIX)
									{
										fprintf(logfd,"[%s] [INFO] status, host: %s\n",time_str,inbound_info.addr);
									}
									else if(config.bind.type==TYPE_INET)
									{
										fprintf(logfd,"[%s] [INFO] status from %s:%d, host: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.addr);
									}
									
								}
								else if(inbound_info.nextstate==2)
								{
									if(config.bind.type==TYPE_UNIX)
									{
										fprintf(logfd,"[%s] [INFO] login, host: %s, username: %s\n",time_str,inbound_info.addr,inbound_info.user);
									}
									else if(config.bind.type==TYPE_INET)
									{
										fprintf(logfd,"[%s] [INFO] login from %s:%d, host: %s, username: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.addr,inbound_info.user);
									}
								}
							}
						}
					}
					else if(config.relay[rec_relay].to_type==TYPE_UNIX)
					{
						socket_outbound=socket(AF_UNIX,SOCK_STREAM,0);
						uddr_outbound.sun_family=AF_UNIX;
						strcpy(uddr_outbound.sun_path,config.relay[rec_relay].to_unix_path);
						if(connect(socket_outbound,(struct sockaddr*)&uddr_outbound,sizeof(struct sockaddr))==-1)
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
							return 5;
						}
						else
						{
							if(inbound_info.nextstate==1)
							{
								if(config.bind.type==TYPE_UNIX)
								{
									fprintf(logfd,"[%s] [INFO] status, host: %s\n",time_str,inbound_info.addr);
								}
								else if(config.bind.type==TYPE_INET)
								{
									fprintf(logfd,"[%s] [INFO] status from %s:%d, host: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.addr);
								}
								
							}
							else if(inbound_info.nextstate==2)
							{
								if(config.bind.type==TYPE_UNIX)
								{
									fprintf(logfd,"[%s] [INFO] login, host: %s, username: %s\n",time_str,inbound_info.addr,inbound_info.user);
								}
								else if(config.bind.type==TYPE_INET)
								{
									fprintf(logfd,"[%s] [INFO] login from %s:%d, host: %s, username: %s\n",time_str,inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port),inbound_info.addr,inbound_info.user);
								}
							}
						}
					}
					break;
				}
			}
			fclose(logfd);
			if(found_relay==0)
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
				return 6;
			}
			if(config.relay[rec_relay].to_type==TYPE_INET)
			{
				if(config.relay[rec_relay].enable_rewrite==1)
				{
					packlen_rewrited=packet_rewrite(inbound,rewrited,config.relay[rec_relay].to_inet_addr,config.relay[rec_relay].to_inet_port);
					send(socket_outbound,rewrited,packlen_rewrited,0);
				}
				else
				{
					send(socket_outbound,inbound,packlen_inbound,0);
				}
			}
			else if(config.relay[rec_relay].to_type==TYPE_UNIX)
			{
				send(socket_outbound,inbound,packlen_inbound,0);
			}
			while(1)
			{
				packlen_inbound=recv(socket_inbound_client,inbound,BUFSIZ,MSG_DONTWAIT);
				if(packlen_inbound>0)
				{
					send(socket_outbound,inbound,packlen_inbound,0);
					bzero(inbound,BUFSIZ);
				}
				else if(packlen_inbound==0)
				{
					shutdown(socket_inbound_client,SHUT_RDWR);
					shutdown(socket_outbound,SHUT_RDWR);
					close(socket_inbound_client);
					close(socket_outbound);
					return 0;
				}
				packlen_outbound=recv(socket_outbound,outbound,BUFSIZ,MSG_DONTWAIT);
				if(packlen_outbound>0)
				{
					send(socket_inbound_client,outbound,packlen_outbound,0);
					bzero(outbound,BUFSIZ);
				}
				else if(packlen_outbound==0)
				{
					shutdown(socket_inbound_client,SHUT_RDWR);
					shutdown(socket_outbound,SHUT_RDWR);
					close(socket_inbound_client);
					close(socket_outbound);
					return 0;
				} 
			}
		}
	}
}
