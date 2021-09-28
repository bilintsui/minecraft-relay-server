/*
	config2.c: 2nd Generation Functions for Config reading on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
short config_jsonbool(cJSON * src, short defaultvalue)
{
	if(src==NULL)
	{
		return defaultvalue;
	}
	if(cJSON_IsBool(src))
	{
		return cJSON_IsTrue(src);
	}
	else if(cJSON_IsNumber(src))
	{
		return (src->valueint!=0);
	}
	else
	{
		return defaultvalue;
	}
}
void config_destroy(conf2 * target)
{
	if(target!=NULL)
	{
		if(target->log.filename!=NULL)
		{
			free(target->log.filename);
			target->log.filename=NULL;
		}
		if(target->listen.address!=NULL)
		{
			free(target->listen.address);
			target->listen.address=NULL;
		}
		free(target);
		if(target->proxy!=NULL)
		{
			cJSON_Delete(target->proxy);
			target->proxy=NULL;
		}
	}
}
cJSON * config_proxy_parse(cJSON * src)
{
	cJSON * single=NULL;
	cJSON_ArrayForEach(single,src)
	{
		cJSON * single_vhost=cJSON_GetObjectItemCaseSensitive(single,"vhost");
		if(single_vhost==NULL)
		{
			cJSON_DetachItemViaPointer(src,single);
			continue;
		}
		if(!cJSON_IsArray(single_vhost))
		{
			if(!cJSON_IsString(single_vhost))
			{
				cJSON_DetachItemViaPointer(src,single);
				continue;
			}
			char * vhost=(char *)calloc(1,strlen(single_vhost->valuestring)+1);
			strcpy(vhost,single_vhost->valuestring);
			cJSON_DeleteItemFromObjectCaseSensitive(single,"vhost");
			single_vhost=cJSON_AddArrayToObject(single,"vhost");
			cJSON * item_vhost=cJSON_CreateString(vhost);
			free(vhost);
			cJSON_AddItemToArray(single_vhost,item_vhost);
		}
		cJSON * single_address=cJSON_GetObjectItemCaseSensitive(single,"address");
		if(single_address==NULL)
		{
			cJSON_DetachItemViaPointer(src,single);
			continue;
		}
		if(!cJSON_IsString(single_address))
		{
			cJSON_DetachItemViaPointer(src,single);
			continue;
		}
		cJSON * single_port=cJSON_GetObjectItemCaseSensitive(single,"port");
		if(single_port!=NULL)
		{
			if(!cJSON_IsNumber(single_port))
			{
				cJSON_DetachItemViaPointer(src,single);
				continue;
			}
			int port=single_port->valueint;
			if((port<0)||(port>65535))
			{
				cJSON_DetachItemViaPointer(src,single);
				continue;
			}
		}
	}
	cJSON * result=cJSON_Duplicate(src,1);
	cJSON_Delete(src);
	int dupdet_count=0;
	char ** vhost_namelist=NULL;
	cJSON * rec_result=NULL;
	cJSON_ArrayForEach(rec_result,result)
	{
		cJSON * result_vhostname=cJSON_GetObjectItemCaseSensitive(rec_result,"vhost");
		cJSON * rec_result_vhostname=NULL;
		cJSON_ArrayForEach(rec_result_vhostname,result_vhostname)
		{
			if(dupdet_count==0)
			{
				vhost_namelist=(char **)calloc(1,sizeof(char **));
				if(vhost_namelist==NULL)
				{
					cJSON_Delete(result);
					result=NULL;
					errno=CONF_ECMEMORY;
					return NULL;
				}
				vhost_namelist[dupdet_count]=(char *)calloc(1,strlen(rec_result_vhostname->valuestring)+1);
				if(vhost_namelist[dupdet_count]==NULL)
				{
					free(vhost_namelist);
					vhost_namelist==NULL;
					cJSON_Delete(result);
					result=NULL;
					errno=CONF_ECMEMORY;
					return NULL;
				}
				strcpy(vhost_namelist[dupdet_count],rec_result_vhostname->valuestring);
				dupdet_count++;
				continue;
			}
			for(int i=0;i<dupdet_count;i++)
			{
				if(strcmp(vhost_namelist[i],rec_result_vhostname->valuestring)==0)
				{
					for(int j=0;j<dupdet_count;j++)
					{
						free(vhost_namelist[j]);
						vhost_namelist[j]=NULL;
					}
					free(vhost_namelist);
					vhost_namelist=NULL;
					cJSON_Delete(result);
					result=NULL;
					errno=CONF_ECPROXYDUP;
					return NULL;
				}
				else
				{
					char ** vhost_namelist_new=(char **)realloc(vhost_namelist,(dupdet_count+1)*sizeof(char **));
					if(vhost_namelist_new==NULL)
					{
						for(int j=0;j<dupdet_count;j++)
						{
							free(vhost_namelist[j]);
							vhost_namelist[j]=NULL;
						}
						free(vhost_namelist);
						vhost_namelist=NULL;
						cJSON_Delete(result);
						result=NULL;
						errno=CONF_ECMEMORY;
						return NULL;
					}
					vhost_namelist=vhost_namelist_new;
					vhost_namelist_new=NULL;
					vhost_namelist[dupdet_count]=(char *)calloc(1,strlen(rec_result_vhostname->valuestring)+1);
					if(vhost_namelist[dupdet_count]==NULL)
					{
						for(int j=0;j<dupdet_count;j++)
						{
							free(vhost_namelist[j]);
							vhost_namelist[j]=NULL;
						}
						free(vhost_namelist);
						vhost_namelist=NULL;
						cJSON_Delete(result);
						result=NULL;
						errno=CONF_ECMEMORY;
						return NULL;
					}
					strcpy(vhost_namelist[dupdet_count],rec_result_vhostname->valuestring);
					dupdet_count++;
					break;
				}
			}
		}
	}
	return result;
}
conf2 * config_read(char * filename)
{
	if(filename==NULL)
	{
		errno=CONF_EARGNULL;
		return NULL;
	}
	unsigned char * config_raw=NULL;
	if(freadall(filename,&config_raw)==0)
	{
		switch(errno)
		{
			case FREADALL_ENOREAD:
				errno=CONF_EROPENFAIL;
				break;
			case FREADALL_ELARGE:
				errno=CONF_EROPENLARGE;
				break;
			case FREADALL_ECALLOC:
			case FREADALL_EREALLOC:
				errno=CONF_ERMEMORY;
				break;
		}
		return NULL;
	}
	cJSON * config_json=cJSON_Parse(config_raw);
	free(config_raw);
	config_raw=NULL;
	if(config_json==NULL)
	{
		errno=CONF_ERPARSE;
		return NULL;
	}
	conf2 * result=(conf2 *)calloc(1,sizeof(conf2));
	if(result==NULL)
	{
		cJSON_Delete(config_json);
		config_json=NULL;
		errno=CONF_ECMEMORY;
		return NULL;
	}
	result->netpriority.enabled=1;
	result->netpriority.protocol=AF_INET6;
	cJSON * config_json_netpriority=cJSON_GetObjectItemCaseSensitive(config_json,"netpriority");
	if(config_json_netpriority!=NULL)
	{
		result->netpriority.enabled=config_jsonbool(cJSON_GetObjectItemCaseSensitive(config_json_netpriority,"enabled"),1);
		cJSON * config_json_netpriority_protocol=cJSON_GetObjectItemCaseSensitive(config_json_netpriority,"protocol");
		if(cJSON_IsString(config_json_netpriority_protocol))
		{
			if(strcmp(config_json_netpriority_protocol->valuestring,"IPv4")==0)
			{
				result->netpriority.protocol=AF_INET;
			}
			else if(strcmp(config_json_netpriority_protocol->valuestring,"IPv6")==0)
			{
				result->netpriority.protocol=AF_INET6;
			}
			else
			{
				cJSON_Delete(config_json);
				config_json=NULL;
				config_destroy(result);
				errno=CONF_ECNETPRIORITYPROTOCOL;
				return NULL;
			}
		}
	}
	char * config_default_log_filename="/var/log/mcrelay/access.log";
	result->log.filename=(char *)calloc(1,strlen(config_default_log_filename)+1);
	if(result->log.filename==NULL)
	{
		cJSON_Delete(config_json);
		config_json=NULL;
		config_destroy(result);
		errno=CONF_ECMEMORY;
		return NULL;
	}
	strcpy(result->log.filename,config_default_log_filename);
	result->log.level=2;
	result->log.binary=0;
	cJSON * config_json_log=cJSON_GetObjectItemCaseSensitive(config_json,"log");
	if(config_json_log!=NULL)
	{
		cJSON * config_json_log_filename=cJSON_GetObjectItemCaseSensitive(config_json_log,"filename");
		if(config_json_log_filename!=NULL)
		{
			if(cJSON_IsString(config_json_log_filename))
			{
				if(config_json_log_filename->valuestring!=NULL)
				{
					char * result_log_filename_new=(char *)realloc(result->log.filename,strlen(config_json_log_filename->valuestring)+1);
					if(result_log_filename_new==NULL)
					{
						cJSON_Delete(config_json);
						config_json=NULL;
						config_destroy(result);
						errno=CONF_ECMEMORY;
						return NULL;
					}
					result->log.filename=result_log_filename_new;
					strcpy(result->log.filename,config_json_log_filename->valuestring);
				}
			}
		}
		cJSON * config_json_log_level=cJSON_GetObjectItemCaseSensitive(config_json_log,"level");
		if(config_json_log_level!=NULL)
		{
			if(cJSON_IsNumber(config_json_log_level))
			{
				result->log.level=config_json_log_level->valueint;
			}
		}
		result->log.binary=config_jsonbool(cJSON_GetObjectItemCaseSensitive(config_json_log,"binary"),0);
	}
	char * config_default_listen_address="::";
	result->listen.address=(char *)calloc(1,strlen(config_default_listen_address)+1);
	if(result->listen.address==NULL)
	{
		cJSON_Delete(config_json);
		config_json=NULL;
		config_destroy(result);
		errno=CONF_ECMEMORY;
		return NULL;
	}
	strcpy(result->listen.address,config_default_listen_address);
	result->listen.port=25565;
	cJSON * config_json_listen=cJSON_GetObjectItemCaseSensitive(config_json,"listen");
	if(config_json_listen!=NULL)
	{
		cJSON * config_json_listen_address=cJSON_GetObjectItemCaseSensitive(config_json_listen,"address");
		if(config_json_listen_address!=NULL)
		{
			if(cJSON_IsString(config_json_listen_address))
			{
				if(config_json_listen_address->valuestring!=NULL)
				{
					char * result_listen_address_new=(char *)realloc(result->listen.address,strlen(config_json_listen_address->valuestring)+1);
					if(result_listen_address_new==NULL)
					{
						cJSON_Delete(config_json);
						config_json=NULL;
						config_destroy(result);
						errno=CONF_ECMEMORY;
						return NULL;
					}
					result->listen.address=result_listen_address_new;
					strcpy(result->listen.address,config_json_listen_address->valuestring);
				}
			}
		}
		cJSON * config_json_listen_port=cJSON_GetObjectItemCaseSensitive(config_json_listen,"port");
		if(config_json_listen_port!=NULL)
		{
			if(cJSON_IsNumber(config_json_listen_port))
			{
				int port=config_json_listen_port->valueint;
				if((port<0)||(port>65535))
				{
					cJSON_Delete(config_json);
					config_json=NULL;
					config_destroy(result);
					errno=CONF_ECLISTENPORT;
					return NULL;
				}
				result->listen.port=port;
			}
		}
	}
	cJSON * config_json_proxy=cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(config_json,"proxy"),1);
	if(config_json_proxy==NULL)
	{
		cJSON_Delete(config_json);
		config_json=NULL;
		config_destroy(result);
		errno=CONF_ECPROXY;
		return NULL;
	}
	cJSON_Delete(config_json);
	if(!cJSON_IsArray(config_json_proxy))
	{
		cJSON_Delete(config_json_proxy);
		config_json_proxy=NULL;
		config_destroy(result);
		errno=CONF_ECPROXY;
		return NULL;
	}
	if(!cJSON_GetArraySize(config_json_proxy))
	{
		cJSON_Delete(config_json_proxy);
		config_json_proxy=NULL;
		config_destroy(result);
		errno=CONF_ECPROXY;
		return NULL;
	}
	config_json_proxy=config_proxy_parse(config_json_proxy);
	if(config_json_proxy==NULL)
	{
		config_destroy(result);
		return NULL;
	}
	result->proxy=config_json_proxy;
	return result;
}
void config_dumper(conf2 * src)
{
	printf("Config Detail:\n");
	printf("\n[NETPRIORITY]\n");
	if(src->netpriority.enabled)
	{
		printf("Enabled\t\ttrue\n");
	}
	else
	{
		printf("Enabled\t\tfalse\n");
	}
	if(src->netpriority.protocol==AF_INET)
	{
		printf("Protocol\tIPv4\n");
	}
	else if(src->netpriority.protocol==AF_INET6)
	{
		printf("Protocol\tIPv6\n");
	}
	printf("\n[LOG]\n");
	printf("Filename\t%s\n",src->log.filename);
	printf("Level\t\t%d\n",src->log.level);
	if(src->log.binary)
	{
		printf("Binary\t\ttrue\n");
	}
	else
	{
		printf("Binary\t\tfalse\n");
	}
	printf("\n[LISTEN]\n");
	printf("Address\t\t%s\n",src->listen.address);
	printf("Port\t\t%d\n",src->listen.port);
	cJSON * proxy=src->proxy;
	cJSON * single=NULL;
	int proxy_count=1;
	cJSON_ArrayForEach(single,proxy)
	{
		printf("\n[PROXY #%d]\n",proxy_count);
		cJSON * single_vhost=cJSON_GetObjectItemCaseSensitive(single,"vhost");
		cJSON * recvhost=NULL;
		int vhost_count=1;
		cJSON_ArrayForEach(recvhost,single_vhost)
		{
			if(cJSON_IsString(recvhost))
			{
				printf("vHost #%d\t%s\n",vhost_count,recvhost->valuestring);
				vhost_count++;
			}
		}
		printf("Address\t\t%s\n",cJSON_GetObjectItemCaseSensitive(single,"address")->valuestring);
		cJSON * single_port=cJSON_GetObjectItemCaseSensitive(single,"port");
		if(single_port==NULL)
		{
			printf("Port\t\t<SRV>\n");
		}
		else
		{
			printf("Port\t\t%d\n",single_port->valueint);
		}
		if(config_jsonbool(cJSON_GetObjectItemCaseSensitive(single,"rewrite"),0))
		{
			printf("Rewrite\t\ttrue\n");
		}
		else
		{
			printf("Rewrite\t\tfalse\n");
		}
		if(config_jsonbool(cJSON_GetObjectItemCaseSensitive(single,"pheader"),0))
		{
			printf("PHeader\t\ttrue\n");
		}
		else
		{
			printf("PHeader\t\tfalse\n");
		}
		proxy_count++;
	}
}
conf2_proxy config_proxy_search(conf2 * src, const char * targetvhost)
{
	conf2_proxy result;
	memset(&result,0,sizeof(result));
	if((src==NULL)||(targetvhost==NULL))
	{
		return result;
	}
	cJSON * proxylist=src->proxy;
	if(proxylist==NULL)
	{
		return result;
	}
	cJSON * rec_proxylist=NULL;
	cJSON_ArrayForEach(rec_proxylist,proxylist)
	{
		cJSON * vhostnames=cJSON_GetObjectItemCaseSensitive(rec_proxylist,"vhost");
		if(vhostnames==NULL)
		{
			return result;
		}
		cJSON * rec_vhostname=NULL;
		cJSON_ArrayForEach(rec_vhostname,vhostnames)
		{
			if(cJSON_IsString(rec_vhostname))
			{
				if(strcmp(rec_vhostname->valuestring,targetvhost)==0)
				{
					result.valid=1;
					result.address=cJSON_GetObjectItemCaseSensitive(rec_proxylist,"address")->valuestring;
					cJSON * target_port=cJSON_GetObjectItemCaseSensitive(rec_proxylist,"port");
					if(target_port==NULL)
					{
						result.srvenabled=1;
					}
					else
					{
						result.port=target_port->valueint;
					}
					result.rewrite=config_jsonbool(cJSON_GetObjectItemCaseSensitive(rec_proxylist,"rewrite"),0);
					result.pheader=config_jsonbool(cJSON_GetObjectItemCaseSensitive(rec_proxylist,"pheader"),0);
					return result;
				}
			}
		}
	}
	return result;
}
