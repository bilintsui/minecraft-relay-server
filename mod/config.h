/*
	config.h: Functions for Config reading on Minecraft Relay Server
	A component of Minecraft Relay Server.
	
	Minecraft Relay Server, version 1.1-beta2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Freedom Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define TYPE_UNIX 1
#define TYPE_INET 2
struct conf_bind
{
	unsigned short type;
	char unix_path[BUFSIZ],inet_addr[BUFSIZ];
	unsigned short inet_port;
};
struct conf_map
{
	unsigned short enable_rewrite;
	char from[512],to_unix_path[512],to_inet_addr[512];
	unsigned short to_type;
	unsigned short to_inet_port;
};
struct conf
{
	char log[512];
	struct conf_bind bind;
	int relay_count;
	struct conf_map relay[128];
};
struct conf config_load(char * filename)
{
	char rec_char,buffer[128][BUFSIZ],tmp_buffer[BUFSIZ],key[512],value[512],key2[512],value2[512],key3[512],value3[512];
	int line_reccount=0;
	int line_count=0;
	int rec_relay=0;
	int sscanf_status;
	struct conf result;
	FILE * conffd=fopen(filename,"r");
	if(conffd==NULL)
	{
		printf("[CRIT] Cannot read config file: %s\n",filename);
		exit(2);
	}
	unsigned char charnow[2];
	charnow[1]='\0';
	while((charnow[0]=fgetc(conffd))!=0xFF)
	{
		if((charnow[0]!=10)&&(charnow[0]!=13))
		{
			strcat(buffer[line_count],charnow);
		}
		else
		{
			while((charnow[0]=fgetc(conffd))!=0xFF)
			{
				if((charnow[0]!=10)&&(charnow[0]!=13))
				{
					line_count++;
					strcat(buffer[line_count],charnow);
					break;
				}
			}
		}
	}
	fclose(conffd);
	for(line_reccount=0;line_reccount<line_count;line_reccount++)
	{
		sscanf(buffer[line_reccount],"%s%s",key,value);
		if(strcmp(key,"log")==0)
		{
			strcpy(result.log,value);
		}
		else if(strcmp(key,"bind")==0)
		{
			char * token=strtok(value,":");
			strcpy(key2,token);
			token=strtok(NULL,":");
			strcpy(value2,token);
			if(strcmp(key2,"unix")==0)
			{
				result.bind.type=TYPE_UNIX;
				strcpy(result.bind.unix_path,value2);
			}
			else
			{
				result.bind.type=TYPE_INET;
				strcpy(result.bind.inet_addr,key2);
				result.bind.inet_port=atoi(value2);
			}
		}
		else if(strcmp(key,"proxy_pass")==0)
		{
			int enable_rewrite;
			if(strcmp(value,"rewrite")==0)
			{
				enable_rewrite=1;
			}
			else if(strcmp(value,"relay")==0)
			{
				enable_rewrite=0;
			}
			else
			{
				continue;
			}
			strcpy(tmp_buffer,buffer[line_reccount+1]);
			while(tmp_buffer[0]=='\t')
			{
				result.relay[rec_relay].enable_rewrite=enable_rewrite;
				if(sscanf(tmp_buffer,"%s%s",key2,value2)!=2)
				{
					line_reccount++;
					strcpy(tmp_buffer,buffer[line_reccount+1]);
					continue;
				}
				strcpy(result.relay[rec_relay].from,key2);
				char * token=strtok(value2,":");
				strcpy(key3,token);
				token=strtok(NULL,":");
				if(token==NULL)
				{
					line_reccount++;
					strcpy(tmp_buffer,buffer[line_reccount+1]);
					continue;
				}
				strcpy(value3,token);
				if(strcmp(key3,"unix")==0)
				{
					result.relay[rec_relay].to_type=TYPE_UNIX;
					strcpy(result.relay[rec_relay].to_unix_path,value3);
				}
				else
				{
					result.relay[rec_relay].to_type=TYPE_INET;
					strcpy(result.relay[rec_relay].to_inet_addr,key3);
					if((atoi(value3)<1)||(atoi(value3)>65535))
					{
						line_reccount++;
						strcpy(tmp_buffer,buffer[line_reccount+1]);
						continue;
					}
					else
					{
						result.relay[rec_relay].to_inet_port=atoi(value3);
					}
				}
				rec_relay++;
				line_reccount++;
				strcpy(tmp_buffer,buffer[line_reccount+1]);
			}
			result.relay_count=rec_relay;
		}
	}
	if(strcmp(result.log,"")==0)
	{
		printf("[CRIT] Error in configurations: Argument \"log\" is missing.\n");
		exit(22);
	}
	if(!((strcmp(result.bind.unix_path,"")!=0)||((strcmp(result.bind.inet_addr,"")!=0)&&(result.bind.inet_port!=0))))
	{
		printf("%d,%d,%d\n",strcmp(result.bind.unix_path,""),strcmp(result.bind.inet_addr,""),result.bind.inet_port);
		printf("[CRIT] Erorr in configurations: Argument \"bind\" is missing or invalid.\n");
		exit(22);
	}
	if(result.relay_count==0)
	{
		printf("[CRIT] Erorr in configurations: You don't have any valid record for relay.\n");
		exit(22);
	}
	return result;
}
