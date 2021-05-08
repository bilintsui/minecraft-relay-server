/*
	config.c: Functions for Config reading on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.4
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	unsigned short to_inet_hybridmode;
};
struct conf
{
	unsigned short runmode;
	char log[512];
	unsigned short loglevel;
	struct conf_bind bind;
	int relay_count;
	struct conf_map relay[128];
	int enable_default;
	struct conf_map relay_default;
};
struct conf_map * getproxyinfo(struct conf * source, unsigned char * proxyname)
{
	int proxyname_length=strlen(proxyname);
	int detected_length = proxyname_length;
	while(proxyname[detected_length-1]=='.')
	{
		detected_length--;
		if(detected_length==0)
		{
			break;
		}
	}
	unsigned char * real_proxyname=(unsigned char *)malloc(detected_length+1);
	memset(real_proxyname,0,detected_length+1);
	memcpy(real_proxyname,proxyname,detected_length);
	int recidx;
	for(recidx=0;recidx<source->relay_count;recidx++)
	{
		if(strcmp(source->relay[recidx].from,real_proxyname)==0)
		{
			free(real_proxyname);
			real_proxyname=NULL;
			return &(source->relay[recidx]);
		}
	}
	return NULL;
}
void config_dump(struct conf * source)
{
	printf("Config Detail:\n");
	printf("\n[COMMON]\n");
	switch(source->runmode)
	{
		case 1:
			printf("Runmode\t\tSimple\n");
			break;
		case 2:
			printf("Runmode\t\tForking\n");
	}
	printf("Log file\t%s\n",source->log);
	printf("Log level\t%d\n",source->loglevel);
	printf("Relay Count\t%d\n",source->relay_count);
	switch(source->enable_default)
	{
		case 0:
			printf("Default Server\tDisabled\n");
			break;
		case 1:
			printf("Default Server\tEnabled\n");
			break;
	}
	printf("\n[BIND]\n");
	switch(source->bind.type)
	{
		case TYPE_UNIX:
			printf("Type\t\tUNIX Socket\n");
			printf("Path\t\t%s\n",source->bind.unix_path);
			break;
		case TYPE_INET:
			printf("Type\t\tInternet Socket\n");
			printf("Address\t\t%s\n",source->bind.inet_addr);
			printf("Port\t\t%d\n",source->bind.inet_port);
			break;
	}
	for(int i=0;i<source->relay_count;i++)
	{
		printf("\n[RELAY #%d]\n",i+1);
		switch(source->relay[i].enable_rewrite)
		{
			case 0:
				printf("Rewrite\t\tDisabled\n");
				break;
			case 1:
				printf("Rewrite\t\tEnabled\n");
				break;
		}
		printf("vhost\t\t%s\n",source->relay[i].from);
		switch(source->relay[i].to_type)
		{
			case TYPE_UNIX:
				printf("Type\t\tUNIX Socket\n");
				printf("Path\t\t%s\n",source->relay[i].to_unix_path);
				break;
			case TYPE_INET:
				printf("Type\t\tInternet Socket\n");
				printf("Address\t\t%s\n",source->relay[i].to_inet_addr);
				switch(source->relay[i].to_inet_hybridmode)
				{
					case 0:
						printf("Port\t\t%d\n",source->relay[i].to_inet_port);
						printf("SRV Resolve\tDisabled\n");
						break;
					case 1:
						printf("SRV Resolve\tEnabled\n");
						break;
				}
				break;
		}
	}
	if(source->enable_default==1)
	{
		printf("\n[DEFAULT RELAY]\n");
		switch(source->relay_default.to_type)
		{
			case TYPE_UNIX:
				printf("Type\t\tUNIX Socket\n");
				printf("Path\t%s\n",source->relay_default.to_unix_path);
				break;
			case TYPE_INET:
				printf("Type\t\tInternet Socket\n");
				printf("Address\t\t%s\n",source->relay_default.to_inet_addr);
				switch(source->relay_default.to_inet_hybridmode)
				{
					case 0:
						printf("Port\t\t%d\n",source->relay_default.to_inet_port);
						printf("SRV Resolve\tDisabled\n");
						break;
					case 1:
						printf("SRV Resolve\tEnabled\n");
						break;
				}
				break;
		}
	}
	printf("\n");
}
int config_load(char * filename, struct conf * result)
{
	char rec_char,buffer[128][BUFSIZ],tmp_buffer[BUFSIZ],key[512],value[512],key2[512],value2[512];
	char * tmpptr;
	int loglevel_found=0;
	int line_reccount=0;
	int line_count=0;
	int rec_relay=0;
	bzero(buffer,sizeof(buffer));
	FILE * conffd=fopen(filename,"r");
	if(conffd==NULL)
	{
		return CONF_EOPENFILE;
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
	for(line_reccount=0;line_reccount<=line_count;line_reccount++)
	{
		bzero(tmp_buffer,sizeof(tmp_buffer));
		bzero(key,sizeof(key));
		bzero(value,sizeof(value));
		bzero(key2,sizeof(key2));
		bzero(value2,sizeof(value2));
		tmpptr=buffer[line_reccount];
		if(strsplit_fieldcount(tmpptr,' ')!=2)
		{
			continue;
		}
		tmpptr=strsplit(tmpptr,' ',key);
		tmpptr=strsplit(tmpptr,' ',value);
		if(strcmp(key,"runmode")==0)
		{
			if(strcmp(value,"simple")==0)
			{
				result->runmode=1;
			}
			else if(strcmp(value,"forking")==0)
			{
				result->runmode=2;
			}
		}
		else if(strcmp(key,"log")==0)
		{
			strcpy(result->log,value);
		}
		else if(strcmp(key,"loglevel")==0)
		{
			loglevel_found=1;
			if(sscanf(value,"%hd",&result->loglevel)==0)
			{
				loglevel_found=0;
			}
		}
		else if(strcmp(key,"bind")==0)
		{
			tmpptr=value;
			tmpptr=strsplit(tmpptr,':',key2);
			tmpptr=strsplit(tmpptr,':',value2);
			if(strcmp(key2,"unix")==0)
			{
				result->bind.type=TYPE_UNIX;
				strcpy(result->bind.unix_path,value2);
			}
			else
			{
				result->bind.type=TYPE_INET;
				strcpy(result->bind.inet_addr,key2);
				result->bind.inet_port=basic_atosu(value2);
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
			tmpptr=tmp_buffer;
			while(*tmpptr=='\t')
			{
				tmpptr++;
				result->relay[rec_relay].enable_rewrite=enable_rewrite;
				if(strsplit_fieldcount(tmpptr,' ')!=2)
				{
					line_reccount++;
					strcpy(tmp_buffer,buffer[line_reccount+1]);
					continue;
				}
				tmpptr=strsplit(tmpptr,' ',result->relay[rec_relay].from);
				if(getproxyinfo(result,result->relay[rec_relay].from)!=NULL)
				{
					errno=line_reccount+2;
					return CONF_EPROXYDUP;
				}
				if(strsplit_fieldcount(tmpptr,':')==1)
				{
					result->relay[rec_relay].to_type=TYPE_INET;
					result->relay[rec_relay].to_inet_hybridmode=1;
					tmpptr=strsplit(tmpptr,':',result->relay[rec_relay].to_inet_addr);
					result->relay[rec_relay].to_inet_port=25565;
					rec_relay++;
					line_reccount++;
					strcpy(tmp_buffer,buffer[line_reccount+1]);
					tmpptr=tmp_buffer;
					continue;
				}
				result->relay[rec_relay].to_inet_hybridmode=0;
				bzero(key2,sizeof(key2));
				bzero(value2,sizeof(value2));
				tmpptr=strsplit(tmpptr,':',key2);
				tmpptr=strsplit(tmpptr,':',value2);
				if(strcmp(key2,"unix")==0)
				{
					result->relay[rec_relay].to_type=TYPE_UNIX;
					strcpy(result->relay[rec_relay].to_unix_path,value2);
				}
				else
				{
					result->relay[rec_relay].to_type=TYPE_INET;
					strcpy(result->relay[rec_relay].to_inet_addr,key2);
					int port=basic_atosu(value2);
					if(port==0)
					{
						line_reccount++;
						strcpy(tmp_buffer,buffer[line_reccount+1]);
						continue;
					}
					else
					{
						result->relay[rec_relay].to_inet_port=port;
					}
				}
				rec_relay++;
				line_reccount++;
				strcpy(tmp_buffer,buffer[line_reccount+1]);
				tmpptr=tmp_buffer;
				result->relay_count=rec_relay;
			}
		}
		else if(strcmp(key,"default")==0)
		{
			struct conf_map relay_default;
			bzero(&relay_default,sizeof(relay_default));
			tmpptr=value;
			if(result->enable_default==1)
			{
				errno=line_reccount+1;
				return CONF_EDEFPROXYDUP;
			}
			relay_default.enable_rewrite=0;
			strcpy(relay_default.from,"*");
			if(strsplit_fieldcount(tmpptr,':')==1)
			{
				relay_default.to_inet_hybridmode=1;
				relay_default.to_type=TYPE_INET;
				tmpptr=strsplit(tmpptr,':',relay_default.to_inet_addr);
				relay_default.to_inet_port=25565;
			}
			else if(strsplit_fieldcount(tmpptr,':')==2)
			{
				relay_default.to_inet_hybridmode=0;
				tmpptr=strsplit(tmpptr,':',key2);
				tmpptr=strsplit(tmpptr,':',value2);
				if(strcmp(key2,"unix")==0)
				{
					relay_default.to_type=TYPE_UNIX;
					strcpy(relay_default.to_unix_path,value2);
				}
				else
				{
					relay_default.to_type=TYPE_INET;
					strcpy(relay_default.to_inet_addr,key2);
					int port=basic_atosu(value2);
					if(port==0)
					{
						continue;
					}
					else
					{
						relay_default.to_inet_port=port;
					}
				}
			}
			else
			{
				continue;
			}
			memcpy(&(result->relay_default),&relay_default,sizeof(relay_default));
			result->enable_default=1;
		}
	}
	if((result->runmode!=1)&&(result->runmode!=2))
	{
		return CONF_EBADRUNMODE;
	}
	if(strcmp(result->log,"")==0)
	{
		return CONF_ENOLOGFILE;
	}
	if(loglevel_found==0)
	{
		return CONF_ENOLOGLEVEL;
	}
	if(!((strcmp(result->bind.unix_path,"")!=0)||((strcmp(result->bind.inet_addr,"")!=0)&&(inet_addr(result->bind.inet_addr)!=-1)&&(result->bind.inet_port!=0))))
	{
		return CONF_EINVALIDBIND;
	}
	if(result->relay_count==0)
	{
		return CONF_EPROXYNOFIND;
	}
	return 0;
}

