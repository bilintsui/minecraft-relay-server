/*
	main.c: Main source code for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta1
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
const char * version_str="1.2-beta1";
const char * year_str="2020-2021";
const short version_internal=46;
conf config;
char configfile[512],cwd[512],config_logfull[BUFSIZ];
unsigned short config_runmode=1;
char * argoffset_configfile=NULL;
void deal_sigterm()
{
	unlink("/tmp/mcrelay.pid");
	exit(0);
}
void deal_sigusr1()
{
	conf config_new;
	char config_logfull_old[BUFSIZ],configfile_full[BUFSIZ];
	unsigned short config_maxlevel=config.loglevel;
	bzero(config_logfull_old,BUFSIZ);
	strcpy(config_logfull_old,config_logfull);
	mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,2,"Reloading config from file: %s\n",configfile);
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
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,2,"Configuration reloaded.\n\n");
			break;
		case CONF_EOPENFILE:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Cannot read config file: %s, will keep your old configurations.\n\n",configfile);
			break;
		case CONF_ENOLOGFILE:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Argument \"log\" is missing, will keep your old configurations.\n\n");
			break;
		case CONF_ENOLOGLEVEL:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Argument \"loglevel\" is missing or not a valid short integer, will keep your old configurations.\n\n");
			break;
		case CONF_EINVALIDBIND:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Argument \"bind\" is missing or invalid, will keep your old configurations.\n\n");
			break;
		case CONF_EPROXYNOFIND:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: You don't have any valid record for relay, will keep your old configurations.\n\n");
			break;
		case CONF_EPROXYDUP:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Duplicate proxy record in config line %d, will keep your old configurations.\n\n",errno);
			break;
		case CONF_EDEFPROXYDUP:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Duplicate default proxy record in config line %d, will keep your old configurations.\n\n",errno);
			break;
	}
}
int main(int argc, char ** argv)
{
	char helpmsg[]="<arguments|config_file>\n\nArguments\n\t-r / --reload:\tReload config on the running instance.\n\t-t / --stop:\tTerminate the running instance.\n\t-f / --forking:\tMade the process become daemonize.\n\t-v / --version:\tShow current mcrelay version.\n\nSee more, watch: https://github.com/bilintsui/minecraft-relay-server";
	int strulen=sizeof(struct sockaddr);
	int socket_inbound_server,socket_inbound_client;
	struct sockaddr_in addr_inbound_server,addr_inbound_client;
	signal(SIGTERM,deal_sigterm);
	signal(SIGINT,deal_sigterm);
	bzero(cwd,512);
	getcwd(cwd,512);
	if(argc<2)
	{
		mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\nUsage: %s %s\n",version_str,year_str,strsplit_reverse(argv[0],'/'),helpmsg);
		return 22;
	}
	argoffset_configfile=argv[1];
	FILE * pidfd=fopen("/tmp/mcrelay.pid","r");
	int prevpid;
	char * ptr_argv1=argv[1];
	if(*ptr_argv1=='-')
	{
		ptr_argv1++;
		if((strcmp(ptr_argv1,"r")==0)||(strcmp(ptr_argv1,"-reload")==0))
		{
			if(pidfd==NULL)
			{
				mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
				mksysmsg(0,"",0,255,0,"Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGUSR1)==0)
			{
				mksysmsg(1,"",0,255,2,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
				mksysmsg(0,"",0,255,2,"Successfully send reload signal to currently running process.\n");
				return 0;
			}
			else
			{
				mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
				mksysmsg(0,"",0,255,0,"Failed on send reload signal to currently running process.\n");
				return 3;
			}
		}
		else if((strcmp(ptr_argv1,"t")==0)||(strcmp(ptr_argv1,"-stop")==0))
		{
			if(pidfd==NULL)
			{
				mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
				mksysmsg(0,"",0,255,0,"Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGTERM)==0)
			{
				mksysmsg(1,"",0,255,2,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
				mksysmsg(0,"",0,255,2,"Successfully send terminate signal to currently running process.\n");
				return 0;
			}
			else
			{
				mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
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
			mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\nError: Invalid option \"-%s\"\n\nUsage: %s %s\n",version_str,year_str,ptr_argv1,strsplit_reverse(argv[0],'/'),helpmsg);
			return 22;
		}
	}
	else
	{
		if(pidfd!=NULL)
		{
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,0)==0)
			{
				mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
				mksysmsg(0,"",0,255,0,"You cannot running multiple instances in one time. Previous running process PID: %d.\n",prevpid);
				return 1;
			}
		}
	}
	mksysmsg(1,"",0,255,2,"Minecraft Relay Server [Version %s]\n(C) %s Bilin Tsui. All rights reserved.\n\n",version_str,year_str);
	bzero(configfile,512);
	if(argoffset_configfile==NULL)
	{
		mksysmsg(0,"",0,255,0,"Config filename can not be empty!\n",configfile);
		return 22;
	}
	strcpy(configfile,argoffset_configfile);
	mksysmsg(0,"",0,255,2,"Loading configurations from file: %s\n\n",configfile);
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
		case CONF_EOPENFILE:
			mksysmsg(0,"",0,255,0,"Cannot read config file: %s\n",configfile);
			return 2;
		case CONF_ENOLOGFILE:
			mksysmsg(0,"",0,255,0,"Error in configurations: Argument \"log\" is missing.\n");
			return 22;
		case CONF_ENOLOGLEVEL:
			mksysmsg(0,"",0,255,0,"Error in configurations: Argument \"loglevel\" is missing or not a valid short integer.\n");
			return 22;
		case CONF_EINVALIDBIND:
			mksysmsg(0,"",0,255,0,"Error in configurations: Argument \"bind\" is missing or invalid.\n");
			return 22;
		case CONF_EPROXYNOFIND:
			mksysmsg(0,"",0,255,0,"Error in configurations: You don't have any valid record for relay.\n");
			return 22;
		case CONF_EPROXYDUP:
			mksysmsg(0,"",0,255,0,"Error in configurations: Duplicate proxy record in config line %d.\n",errno);
			return 22;
		case CONF_EDEFPROXYDUP:
			mksysmsg(0,"",0,255,0,"Error in configurations: Duplicate default proxy record in config line %d.\n",errno);
			return 22;
	}
	FILE * tmpfd=fopen(config_logfull,"a");
	if(tmpfd==NULL)
	{
		mksysmsg(0,"",0,255,0,"Error: Cannot write log to \"%s\".\n",config.log);
		return 13;
	}
	else
	{
		fclose(tmpfd);
	}
	void * bindaddr=net_resolve(config.bind.inet_addr,AF_INET);
	if(bindaddr==NULL)
	{
		mksysmsg(0,config_logfull,config_runmode,config.loglevel,0,"Error: Invalid bind address!\n");
		return 14;
	}
	if(config.bind.inet_port==0)
	{
		mksysmsg(0,config_logfull,config_runmode,config.loglevel,0,"Error: Invalid bind port!\n");
		return 14;
	}
	mksysmsg(0,config_logfull,config_runmode,config.loglevel,2,"Binding on %s:%d...\n",config.bind.inet_addr,config.bind.inet_port);
	socket_inbound_server=net_socket(NETSOCK_BIND,AF_INET,bindaddr,config.bind.inet_port,1);
	free(bindaddr);
	bindaddr=NULL;
	if(socket_inbound_server==-1)
	{
		mksysmsg(0,config_logfull,config_runmode,config.loglevel,0,"Bind Failed!\n");
		return 2;
	}
	mksysmsg(0,config_logfull,config_runmode,config.loglevel,2,"Bind Successful.\n\n");
	mksysmsg(0,"",config_runmode,config.loglevel,2,"For more information, watch log file: %s\n\n",config.log);
	int pid;
	if(config_runmode==2)
	{
		pid=fork();
		if(pid>0)
		{
			FILE * pidfd=fopen("/tmp/mcrelay.pid","w");
			fprintf(pidfd,"%d",pid);
			fclose(pidfd);
			mksysmsg(0,"",0,config.loglevel,2,"Server running on PID: %d\n",pid);
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
			signal(SIGUSR1,SIG_DFL);
			close(socket_inbound_server);
			int socket_outbound;
			if(backbone(socket_inbound_client,&socket_outbound,config_logfull,config_runmode,config,addr_inbound_client))
			{
				return 0;
			}
			net_relay(socket_inbound_client,socket_outbound);
			return 0;
		}
	}
}
