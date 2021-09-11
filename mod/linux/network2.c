/*
	network2.c: Network Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta1
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
size_t net_getaddrsize(sa_family_t family)
{
	switch(family)
	{
		case AF_INET:
			return sizeof(uint32_t);
		case AF_INET6:
			return sizeof(char)*16;
		default:
			return 0;
	}
}
sa_family_t net_getaltfamily(sa_family_t family)
{
	switch(family)
	{
		case AF_INET:
			return AF_INET6;
		case AF_INET6:
			return AF_INET;
		default:
			return 0;
	}
}
void * net_resolve2(char * hostname, sa_family_t family)
{
	if((family!=AF_INET)&&(family!=AF_INET6))
	{
		errno=NET_EARGFAMILY;
		return NULL;
	}
	void * result=malloc(net_getaddrsize(family));
	if(result==NULL)
	{
		errno=NET_EMALLOC;
		return NULL;
	}
	if(inet_pton(family,hostname,result)==1)
	{
		return result;
	}
	struct hostent * response=gethostbyname2(hostname,family);
	if(response==NULL)
	{
		errno=NET_ENORECORD;
		free(result);
		return NULL;
	}
	memcpy(result,response->h_addr_list[0],net_getaddrsize(family));
	return result;
}
net_addr net_resolve_dual(char * hostname, sa_family_t primary_family, short dual)
{
	net_addr result;
	result.family=0;
	result.err=0;
	memset(&(result.addr),0,sizeof(result.addr));
	if((primary_family!=AF_INET)&&(primary_family!=AF_INET6))
	{
		result.err=NET_EARGFAMILY;
		return result;
	}
	void * resolved=net_resolve2(hostname,primary_family);
	if(resolved!=NULL)
	{
		result.family=primary_family;
		memcpy(&(result.addr),resolved,net_getaddrsize(result.family));
		free(resolved);
		return result;
	}
	if(!dual)
	{
		result.err=errno;
		return result;
	}
	resolved=net_resolve2(hostname,net_getaltfamily(primary_family));
	if(resolved!=NULL)
	{
		result.family=net_getaltfamily(primary_family);
		memcpy(&(result.addr),resolved,net_getaddrsize(result.family));
		free(resolved);
		return result;
	}
	result.err=errno;
	return result;
}
int net_socket(short action, sa_family_t family, void * address, u_int16_t port)
{
	if((action!=NETSOCK_BIND)&&(action!=NETSOCK_CONN))
	{
		errno=NET_EARGACTION;
		return -1;
	}
	if((family!=AF_INET)&&(family!=AF_INET6))
	{
		errno=NET_EARGFAMILY;
		return -1;
	}
	if(address==NULL)
	{
		errno=NET_EARGADDR;
		return -1;
	}
	void * serv_addr;
	int stru_size;
	if(family==AF_INET)
	{
		stru_size=sizeof(struct sockaddr_in);
		serv_addr=malloc(stru_size);
		if(serv_addr==NULL)
		{
			errno=NET_EMALLOC;
			return -1;
		}
		memset(serv_addr,0,stru_size);
		struct sockaddr_in * addr=serv_addr;
		addr->sin_family=AF_INET;
		addr->sin_port=htons(port);
		memcpy(&(addr->sin_addr.s_addr),address,sizeof(u_int32_t));
	}
	else if(family==AF_INET6)
	{
		stru_size=sizeof(struct sockaddr_in6);
		serv_addr=malloc(stru_size);
		if(serv_addr==NULL)
		{
			errno=NET_EMALLOC;
			return -1;
		}
		memset(serv_addr,0,stru_size);
		struct sockaddr_in6 * addr=serv_addr;
		addr->sin6_family=AF_INET6;
		addr->sin6_port=htons(port);
		memcpy(&(addr->sin6_addr),address,sizeof(char)*16);
	}
	int result=socket(family,SOCK_STREAM,0);
	if(result==-1)
	{
		errno=NET_ESOCKET;
		return -1;
	}
	if(action==NETSOCK_BIND)
	{
		if(bind(result,serv_addr,stru_size)==-1)
		{
			close(result);
			errno=NET_EBIND;
			return -1;
		}
		else
		{
			if(listen(result,5)==-1)
			{
				close(result);
				errno=NET_ELISTEN;
				return -1;
			}
		}
	}
	else if(action==NETSOCK_CONN)
	{
		if(connect(result,serv_addr,stru_size)==-1)
		{
			close(result);
			errno=NET_ECONNECT;
			return -1;
		}
	}
	return result;
}
