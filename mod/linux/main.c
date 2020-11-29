/*
	main.c: Main source code for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
const char version_str[]="1.1.2";
struct conf config;
char configfile[512],cwd[512],config_logfull[BUFSIZ];
unsigned short config_runmode;
void deal_sigterm()
{
	unlink("/tmp/mcrelay.pid");
	exit(0);
}
void deal_sigusr1()
{
	struct conf config_new;
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
		case 1:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Cannot read config file: %s, will keep your old configurations.\n\n",configfile);
			break;
		case 2:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Argument \"runmode\" is missing, will keep your old configurations.\n\n");
			break;
		case 3:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Argument \"log\" is missing, will keep your old configurations.\n\n");
			break;
		case 4:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Argument \"loglevel\" is missing or not a valid short integer, will keep your old configurations.\n\n");
			break;
		case 5:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: Argument \"bind\" is missing or invalid, will keep your old configurations.\n\n");
			break;
		case 6:
			mksysmsg(0,config_logfull_old,config_runmode,config_maxlevel,1,"Error in configurations: You don't have any valid record for relay, will keep your old configurations.\n\n");
			break;
	}
}
int main(int argc, char ** argv)
{
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
		mksysmsg(1,"",0,255,0,"Minecraft Relay Server [Version:%s]\n(C) 2020 Bilin Tsui. All rights reserved.\n\nUsage: %s <arguments|config_file>\n\nArguments\n\t-r:\tReload config on the running instance.\n\t-t:\tTerminate the running instance\n\nSee more, watch: https://github.com/bilintsui/minecraft-relay-server\n",version_str,argv[0]);
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
				mksysmsg(0,"",0,255,0,"Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGUSR1)==0)
			{
				mksysmsg(0,"",0,255,2,"Successfully send reload signal to currently running process.\n");
				return 0;
			}
			else
			{
				mksysmsg(0,"",0,255,0,"Failed on send reload signal to currently running process.\n");
				return 3;
			}
		}
		else if(strcmp(ptr_argv1,"t")==0)
		{
			if(pidfd==NULL)
			{
				mksysmsg(0,"",0,255,0,"Cannot read /tmp/mcrelay.pid.\n");
				return 2;
			}
			fscanf(pidfd,"%d",&prevpid);
			fclose(pidfd);
			if(kill(prevpid,SIGTERM)==0)
			{
				mksysmsg(0,"",0,255,2,"Successfully send terminate signal to currently running process.\n");
				return 0;
			}
			else
			{
				mksysmsg(0,"",0,255,0,"Failed on send terminate signal to currently running process.\n");
				return 3;
			}
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
				mksysmsg(0,"",0,255,0,"You cannot running multiple instances in one time. Previous running process PID: %d.\n",prevpid);
				return 1;
			}
		}
	}
	mksysmsg(1,"",0,255,2,"Minecraft Relay Server [Version:%s]\n(C) 2020 Bilin Tsui. All rights reserved.\n\n",version_str);
	bindip="0.0.0.0";
	bindport=25565;
	bzero(configfile,512);
	strcpy(configfile,argv[1]);
	mksysmsg(0,"",0,255,2,"Loading configurations from file: %s\n\n",configfile);
	switch(config_load(configfile,&config))
	{
		case 0:
			config_runmode=config.runmode;
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
			mksysmsg(0,"",0,255,0,"Cannot read config file: %s\n",configfile);
			return 2;
		case 2:
			mksysmsg(0,"",0,255,0,"Error in configurations: Argument \"runmode\" is missing.\n");
			return 22;
		case 3:
			mksysmsg(0,"",0,255,0,"Error in configurations: Argument \"log\" is missing.\n");
			return 22;
		case 4:
			mksysmsg(0,"",0,255,0,"Error in configurations: Argument \"loglevel\" is missing or not a valid short integer.\n");
			return 22;
		case 5:
			mksysmsg(0,"",0,255,0,"Error in configurations: Argument \"bind\" is missing or invalid.\n");
			return 22;
		case 6:
			mksysmsg(0,"",0,255,0,"Error in configurations: You don't have any valid record for relay.\n");
			return 22;
	}
	if(config.bind.type==TYPE_INET)
	{
		if(inet_addr(config.bind.inet_addr)==-1)
		{
			mksysmsg(0,config_logfull,config_runmode,config.loglevel,1,"Bad argument: bind_address. Use default address %s.\n",bindip);
		}
		else
		{
			bindip=config.bind.inet_addr;
		}
		if((config.bind.inet_port<1)||(config.bind.inet_port>65535))
		{
			mksysmsg(0,config_logfull,config_runmode,config.loglevel,1,"Bad argument: bind_port. Use default port %d.\n",bindport);
		}
		else
		{
			bindport=config.bind.inet_port;
		}
		socket_inbound_server=socket(AF_INET,SOCK_STREAM,0);
		addr_inbound_server=net_mksockaddr_in(AF_INET,htonl(inet_addr(bindip)),bindport);
		strulen=sizeof(struct sockaddr_in);
		mksysmsg(0,config_logfull,config_runmode,config.loglevel,2,"Binding on %s:%d...\n","0.0.0.0",25565);
		if(bind(socket_inbound_server,(struct sockaddr *)&addr_inbound_server,strulen)==-1)
		{
			mksysmsg(0,config_logfull,config_runmode,config.loglevel,0,"Bind Failed!\n");
			return 2;
		}
		mksysmsg(0,config_logfull,config_runmode,config.loglevel,2,"Bind Successful.\n\n");
	}
	else if(config.bind.type==TYPE_UNIX)
	{
		unlink(config.bind.unix_path);
		socket_inbound_server=socket(AF_UNIX,SOCK_STREAM,0);
		uddr_inbound_server=net_mksockaddr_un(config.bind.unix_path);
		strulen=sizeof(uddr_inbound_server);
		mksysmsg(0,config_logfull,config_runmode,config.loglevel,2,"Binding on %s...\n",uddr_inbound_server.sun_path);
		if(bind(socket_inbound_server,(struct sockaddr *)&uddr_inbound_server,strulen)==-1)
		{
			mksysmsg(0,config_logfull,config_runmode,config.loglevel,0,"Bind Failed!\n");
			return 2;
		}
		if(chmod(config.bind.unix_path,S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH)==-1)
		{
			mksysmsg(0,config_logfull,config_runmode,config.loglevel,0,"Set Permission Failed!\n");
			return 13;
		}
		mksysmsg(0,config_logfull,config_runmode,config.loglevel,2,"Bind Successful.\n\n");
	}
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
			int socket_outbound;
			backbone(socket_inbound_client,&socket_outbound,config_logfull,config_runmode,config,addr_inbound_client);
			net_relay(socket_inbound_client,socket_outbound);
			return 0;
		}
	}
}