/*
	main.c: Main source code for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "log.h"
#include "misc.h"

const char * version_str="1.2-beta4";
const char * year_str="2020-2023";
const short version_internal=66;
char global_buffer[BUFSIZ];
char * cwd=NULL;
char * argoffset_configfile=NULL;
char * configfile=NULL;
char * configfile_full=NULL;
char * config_logfull=NULL;
conf * config=NULL;
short config_netpriority_enabled=1;
sa_family_t config_netpriority_protocol=AF_INET6;
unsigned short config_runmode=1;
void deal_sigterm()
{
	unlink("/tmp/mcrelay.pid");
	exit(0);
}
void deal_sigusr1()
{
	unsigned short config_maxlevel=config->log.level;
	char * config_logfull_old=(char *)malloc(strlen(config_logfull)+1);
	if(config_logfull_old==NULL)
	{
		return;
	}
	strcpy(config_logfull_old,config_logfull);
	mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,2,"Reloading config from file: %s\n",configfile);
	conf * config_new=config_read(configfile_full);
	switch(errno)
	{
		case 0:
			config_destroy(config);
			config=config_new;
			if(config->log.filename[0]!='/')
			{
				sprintf(global_buffer,"%s/%s",cwd,config->log.filename);
				config_logfull=(char *)realloc(config_logfull,strlen(global_buffer)+1);
				strcpy(config_logfull,global_buffer);
				memset(global_buffer,0,strlen(global_buffer)+1);
			}
			else
			{
				config_logfull=(char *)realloc(config_logfull,strlen(config->log.filename)+1);
				strcpy(config_logfull,config->log.filename);
			}
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,2,"Configuration reloaded.\n");
			break;
		case CONF_EROPENFAIL:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Cannot read config file: %s\n",configfile);
			break;
		case CONF_EROPENLARGE:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: File too large (5MB), will keep your old configurations.\n");
			break;
		case CONF_ERMEMORY:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Failed to allocate memory when reading file, will keep your old configurations.\n");
			break;
		case CONF_ERPARSE:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Not a valid JSON format, will keep your old configurations.\n");
			break;
		case CONF_ECMEMORY:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in processing configurations: Failed to allocate memory while internal processing, will keep your old configurations.\n");
			break;
		case CONF_ECNETPRIORITYPROTOCOL:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Entry \"netpriority.protocol\" must be IPv4 or IPv6 (case sensitive), will keep your old configurations.\n");
			break;
		case CONF_ECLISTENPORT:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Entry \"listen.port\" must be an unsigned short integer (0-65535), will keep your old configurations.\n");
			break;
		case CONF_ECPROXY:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Entry \"proxy\" is missing, will keep your old configurations.\n");
			break;
		case CONF_ECPROXYDUP:
			if(config_new==NULL)
			{
				mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Duplication found in proxy virtual hostnames, will keep your old configurations.\n");
			}
			else
			{
				mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Duplication found in proxy virtual hostnames. Affected: \"%s\", will keep your old configurations.\n",config_new);
				free(config_new);
			}
			break;
		default:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in processing configurations: Unknown error occured, code: %d, will keep your old configurations\n",errno);
			break;
	}
	free(config_logfull_old);
	return;
}
int main(int argc, char ** argv)
{
	char helpmsg[]="<arguments|config_file>\n\nArguments\n\t-r / --reload:\tReload config on the running instance.\n\t-t / --stop:\tTerminate the running instance.\n\t-f / --forking:\tMade the process become daemonize.\n\t-v / --version:\tShow current mcrelay version.\n\nSee more, watch: https://github.com/bilintsui/minecraft-relay-server";
	snprintf(global_buffer,BUFSIZ,"Minecraft Relay Server [Version %s/%d]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,version_internal,year_str);
	char * headmsg=(char *)malloc(strlen(global_buffer)+1);
	if(headmsg==NULL)
	{
		return 12;
	}
	strcpy(headmsg,global_buffer);
	memset(global_buffer,0,strlen(global_buffer)+1);
	int socket_inbound_server,socket_inbound_client;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr_inbound_client;
	int strulen=sizeof(addr_inbound_client);
	signal(SIGTERM,deal_sigterm);
	signal(SIGINT,deal_sigterm);
	memset(global_buffer,0,BUFSIZ);
	getcwd(global_buffer,BUFSIZ);
	cwd=(char *)malloc(strlen(global_buffer)+1);
	strcpy(cwd,global_buffer);
	memset(global_buffer,0,strlen(global_buffer)+1);
	if(argc<2)
	{
		mksysmsg(1,"",0,255,0,headmsg);
		mksysmsg(1,"",0,255,0,"Usage: %s %s\n",strrchr(argv[0],'/')?strrchr(argv[0],'/')+1:argv[0],helpmsg);
		return 22;
	}
	argoffset_configfile=argv[1];
	FILE * pidfd=NULL;
	int prevpid=0;
	char * ptr_argv1=argv[1];
	if(*ptr_argv1=='-')
	{
		ptr_argv1++;
		if((strcmp(ptr_argv1,"r")==0)||(strcmp(ptr_argv1,"-reload")==0))
		{
			pidfd=fopen("/tmp/mcrelay.pid","r");
			if(pidfd==NULL)
			{
				mksysmsg(1,"",0,255,0,headmsg);
				mksysmsg(0,"",0,255,0,"Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGUSR1)==0)
			{
				mksysmsg(1,"",0,255,2,headmsg);
				mksysmsg(0,"",0,255,2,"Successfully send reload signal to currently running process.\n");
				return 0;
			}
			else
			{
				mksysmsg(1,"",0,255,0,headmsg);
				mksysmsg(0,"",0,255,0,"Failed on send reload signal to currently running process.\n");
				return 3;
			}
		}
		else if((strcmp(ptr_argv1,"t")==0)||(strcmp(ptr_argv1,"-stop")==0))
		{
			pidfd=fopen("/tmp/mcrelay.pid","r");
			if(pidfd==NULL)
			{
				mksysmsg(1,"",0,255,0,headmsg);
				mksysmsg(0,"",0,255,0,"Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGTERM)==0)
			{
				mksysmsg(1,"",0,255,2,headmsg);
				mksysmsg(0,"",0,255,2,"Successfully send terminate signal to currently running process.\n");
				return 0;
			}
			else
			{
				mksysmsg(1,"",0,255,0,headmsg);
				mksysmsg(0,"",0,255,0,"Failed on send terminate signal to currently running process.\n");
				return 3;
			}
		}
		else if((strcmp(ptr_argv1,"f")==0)||(strcmp(ptr_argv1,"-forking")==0))
		{
			config_runmode=2;
			argoffset_configfile=argv[2];
		}
		else if((strcmp(ptr_argv1,"v")==0)||(strcmp(ptr_argv1,"-version")==0))
		{
			mksysmsg(1,"",0,255,2,"v%s(%d)\n",version_str,version_internal);
			return 0;
		}
		else
		{
			mksysmsg(1,"",0,255,0,headmsg);
			mksysmsg(1,"",0,255,0,"Error: Invalid option \"-%s\"\n\nUsage: %s %s\n",ptr_argv1,strrchr(argv[0],'/')?strrchr(argv[0],'/')+1:argv[0],helpmsg);
			return 22;
		}
	}
	else
	{
		pidfd=fopen("/tmp/mcrelay.pid","r");
		if(pidfd!=NULL)
		{
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,0)==0)
			{
				mksysmsg(1,"",0,255,0,headmsg);
				mksysmsg(0,"",0,255,0,"You cannot running multiple instances in one time. Previous running process PID: %d.\n",prevpid);
				return 1;
			}
		}
	}
	mksysmsg(1,"",0,255,2,headmsg);
	if(argoffset_configfile==NULL)
	{
		mksysmsg(0,"",0,255,0,"Config filename can not be empty!\n",configfile);
		return 22;
	}
	configfile=(char *)malloc(strlen(argoffset_configfile)+1);
	strcpy(configfile,argoffset_configfile);
	if(configfile[0]!='/')
	{
		sprintf(global_buffer,"%s/%s",cwd,configfile);
		configfile_full=(char *)malloc(strlen(global_buffer)+1);
		strcpy(configfile_full,global_buffer);
		memset(global_buffer,0,strlen(global_buffer)+1);
	}
	else
	{
		configfile_full=(char *)malloc(strlen(configfile)+1);
		strcpy(configfile_full,configfile);
	}
	mksysmsg(0,"",0,255,2,"Loading configurations from file: %s\n\n",configfile);
	config=config_read(configfile_full);
	switch(errno)
	{
		case 0:
			if(config->log.filename[0]!='/')
			{
				sprintf(global_buffer,"%s/%s",cwd,config->log.filename);
				config_logfull=(char *)malloc(strlen(global_buffer)+1);
				strcpy(config_logfull,global_buffer);
				memset(global_buffer,0,strlen(global_buffer)+1);
			}
			else
			{
				config_logfull=(char *)malloc(strlen(config->log.filename)+1);
				strcpy(config_logfull,config->log.filename);
			}
			config_netpriority_enabled=config->netpriority.enabled;
			config_netpriority_protocol=config->netpriority.protocol;
			break;
		case CONF_EROPENFAIL:
			mksysmsg(0,"",0,255,0,"Cannot read config file: %s\n",configfile);
			return 2;
		case CONF_EROPENLARGE:
			mksysmsg(0,"",0,255,0,"Error in configurations: File too large (5MB).\n");
			return 27;
		case CONF_ERMEMORY:
			mksysmsg(0,"",0,255,0,"Error in configurations: Failed to allocate memory when reading file.\n");
			return 12;
		case CONF_ERPARSE:
			mksysmsg(0,"",0,255,0,"Error in configurations: Not a valid JSON format.\n");
			return 38;
		case CONF_ECMEMORY:
			mksysmsg(0,"",0,255,0,"Error in processing configurations: Failed to allocate memory while internal processing.\n");
			return 12;
		case CONF_ECNETPRIORITYPROTOCOL:
			mksysmsg(0,"",0,255,0,"Error in configurations: Entry \"netpriority.protocol\" must be IPv4 or IPv6 (case sensitive).\n");
			return 22;
		case CONF_ECLISTENPORT:
			mksysmsg(0,"",0,255,0,"Error in configurations: Entry \"listen.port\" must be an unsigned short integer (0-65535).\n");
			return 22;
		case CONF_ECPROXY:
			mksysmsg(0,"",0,255,0,"Error in configurations: Entry \"proxy\" is missing!\n");
			return 22;
		case CONF_ECPROXYDUP:
			if(config==NULL)
			{
				mksysmsg(0,"",0,255,0,"Error in configurations: Duplication found in proxy virtual hostnames.\n");
			}
			else
			{
				mksysmsg(0,"",0,255,0,"Error in configurations: Duplication found in proxy virtual hostnames. Affected: \"%s\".\n",config);
				free(config);
			}
			return 22;
		default:
			mksysmsg(0,"",0,255,0,"Error in processing configurations: Unknown error occured, code: %d\n",errno);
			return 255;
	}
	FILE * tmpfd=fopen(config_logfull,"a");
	if(tmpfd==NULL)
	{
		mksysmsg(0,"",0,255,0,"Error: Cannot write log to \"%s\".\n",config->log.filename);
		return 13;
	}
	else
	{
		fclose(tmpfd);
	}
	net_addr bindaddr=net_resolve_dual(config->listen.address,config_netpriority_protocol,config_netpriority_enabled);
	if(bindaddr.family==0)
	{
		mksysmsg(0,config_logfull,config_runmode,config->log.level,0,"Error: Invalid bind address!\n");
	}
	if(config->listen.port==0)
	{
		mksysmsg(0,config_logfull,config_runmode,config->log.level,0,"Error: Invalid bind port!\n");
		return 14;
	}
	net_addrp bindaddrp=net_ntop(bindaddr.family,&(bindaddr.addr),1);
	mksysmsg(0,config_logfull,config_runmode,config->log.level,2,"Binding on %s:%d...\n",(char *)&bindaddrp,config->listen.port);
	socket_inbound_server=net_socket(NETSOCK_BIND,bindaddr.family,&(bindaddr.addr),config->listen.port,1);
	if(socket_inbound_server==-1)
	{
		mksysmsg(0,config_logfull,config_runmode,config->log.level,0,"Bind Failed!\n");
		return 2;
	}
	mksysmsg(0,config_logfull,config_runmode,config->log.level,2,"Bind Successful.\n\n");
	mksysmsg(0,"",config_runmode,config->log.level,2,"For more information, watch log file: %s\n\n",config->log.filename);
	int pid;
	if(config_runmode==2)
	{
		pid=fork();
		if(pid>0)
		{
			FILE * pidfd=fopen("/tmp/mcrelay.pid","w");
			fprintf(pidfd,"%d",pid);
			fclose(pidfd);
			mksysmsg(0,"",0,config->log.level,2,"Server running on PID: %d\n",pid);
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
		socket_inbound_client=accept(socket_inbound_server,(struct sockaddr *)&addr_inbound_client,&strulen);
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
			net_addrbundle addrbundle_inbound_client;
			addrbundle_inbound_client.family=*((sa_family_t *)&addr_inbound_client);
			void * addr_inbound_client_addroffset=NULL;
			switch(addrbundle_inbound_client.family)
			{
				case AF_INET:
					addrbundle_inbound_client.address=net_ntop(AF_INET,&(((struct sockaddr_in *)&addr_inbound_client)->sin_addr),1);
					addrbundle_inbound_client.address_clean=net_ntop(AF_INET,&(((struct sockaddr_in *)&addr_inbound_client)->sin_addr),0);
					addrbundle_inbound_client.port=ntohs(((struct sockaddr_in *)&addr_inbound_client)->sin_port);
					break;
				case AF_INET6:
					addr_inbound_client_addroffset=(unsigned char *)&(((struct sockaddr_in6 *)&addr_inbound_client)->sin6_addr);
					if(memcmp(addr_inbound_client_addroffset,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xFF\xFF",12)==0)
					{
						addrbundle_inbound_client.family=AF_INET;
						addr_inbound_client_addroffset=addr_inbound_client_addroffset+12;
					}
					addrbundle_inbound_client.address=net_ntop(addrbundle_inbound_client.family,addr_inbound_client_addroffset,1);
					addrbundle_inbound_client.address_clean=net_ntop(addrbundle_inbound_client.family,addr_inbound_client_addroffset,0);
					addrbundle_inbound_client.port=ntohs(((struct sockaddr_in6 *)&addr_inbound_client)->sin6_port);
					break;
			}
			signal(SIGUSR1,SIG_DFL);
			close(socket_inbound_server);
			int socket_outbound;
			if(backbone(socket_inbound_client,&socket_outbound,config_logfull,config_runmode,config,addrbundle_inbound_client,config_netpriority_enabled))
			{
				return 0;
			}
			net_relay(socket_inbound_client,socket_outbound);
			return 0;
		}
	}
}
