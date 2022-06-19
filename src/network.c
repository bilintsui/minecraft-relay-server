/*
	network.c: Network Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "network.h"

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
net_addrp net_ntop(sa_family_t family, void * src, short v6addition)
{
	net_addrp pre_result;
	memset(&pre_result,0,sizeof(pre_result));
	if(((family!=AF_INET)&&(family!=AF_INET6))||(src==NULL)||(inet_ntop(family,src,(char *)&pre_result,sizeof(pre_result))==NULL))
	{
		return pre_result;
	}
	if((v6addition)&&(family==AF_INET6))
	{
		net_addrp result;
		memset(&result,0,sizeof(result));
		sprintf((char *)&result,"[%s]",(char *)&pre_result);
		return result;
	}
	return pre_result;
}
int net_relay(int socket_in, int socket_out)
{
	char buffer[BUFSIZ];
	struct epoll_event ev,events[2];
	int epfd,nfds,i,read_bytes,socket_peer;
	epfd=epoll_create(2);
	ev.data.fd=socket_in;
	ev.events=EPOLLIN;
	epoll_ctl(epfd,EPOLL_CTL_ADD,socket_in,&ev);
	ev.data.fd=socket_out;
	ev.events=EPOLLIN;
	epoll_ctl(epfd,EPOLL_CTL_ADD,socket_out,&ev);
	while(1)
	{
		nfds=epoll_wait(epfd,events,2,-1);
		for(i=0;i<nfds;i++)
		{
			if(events[i].events&EPOLLIN)
			{
				if(events[i].data.fd==socket_in)
				{
					socket_peer=socket_out;
				}
				else if(events[i].data.fd==socket_out)
				{
					socket_peer=socket_in;
				}
				read_bytes=BUFSIZ;
				while(read_bytes==BUFSIZ)
				{
					read_bytes=recv(events[i].data.fd,buffer,BUFSIZ,0);
					if(read_bytes==0)
					{
						close(socket_peer);
						return 0;
					}
					if(read_bytes>0)
					{
						send(socket_peer,buffer,read_bytes,0);
					}
				}
			}
		}
	}
}
void * net_resolve(char * hostname, sa_family_t family)
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
	void * resolved=net_resolve(hostname,primary_family);
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
	resolved=net_resolve(hostname,net_getaltfamily(primary_family));
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
int net_socket(short action, sa_family_t family, void * address, in_port_t port, short reuseaddr)
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
	void * serv_addr=NULL;
	int stru_size=0;
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
		free(serv_addr);
		errno=NET_ESOCKET;
		return -1;
	}
	if(reuseaddr)
	{
		int socket_opt=1;
		if(setsockopt(result,SOL_SOCKET,SO_REUSEADDR,&socket_opt,sizeof(socket_opt))==-1)
		{
			free(serv_addr);
			close(result);
			errno=NET_EREUSEADDR;
			return -1;
		}
	}
	if(action==NETSOCK_BIND)
	{
		if(bind(result,serv_addr,stru_size)==-1)
		{
			free(serv_addr);
			close(result);
			errno=NET_EBIND;
			return -1;
		}
		else
		{
			if(listen(result,5)==-1)
			{
				free(serv_addr);
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
			free(serv_addr);
			close(result);
			errno=NET_ECONNECT;
			return -1;
		}
	}
	free(serv_addr);
	return result;
}
int net_srvresolve(char * query_name, net_srvrecord * target)
{
	char query_name_full[256];
	memset(query_name_full,0,256);
	sprintf(query_name_full,"_minecraft._tcp.%s",query_name);
	struct
	{
		unsigned short priority,weight,port;
		char target[128];
	} records[128],records_minpriority[128],records_maxweight[128];
	memset(records,0,sizeof(records));
	res_init();
	unsigned char query_buffer[1024];
	int response=res_query(query_name_full,C_IN,ns_t_srv,query_buffer,sizeof(query_buffer));
	if(response==-1)
	{
		return -1;
	}
	ns_msg nsMsg;
	ns_initparse(query_buffer,response,&nsMsg);
	unsigned short priority_min=65535;
	unsigned short weight_max=0;
	int rec_record=0;
	int max_record=ns_msg_count(nsMsg,ns_s_an);
	if(max_record==0)
	{
		return 0;
	}
	for(rec_record=0;rec_record<max_record;rec_record++)
	{
		ns_rr rr;
		ns_parserr(&nsMsg,ns_s_an,rec_record,&rr);
		records[rec_record].priority=ntohs(*((unsigned short *)ns_rr_rdata(rr)+0));
		records[rec_record].weight=ntohs(*((unsigned short *)ns_rr_rdata(rr)+1));
		records[rec_record].port=ntohs(*((unsigned short *)ns_rr_rdata(rr)+2));
		dn_expand(ns_msg_base(nsMsg),ns_msg_end(nsMsg),ns_rr_rdata(rr)+6,records[rec_record].target,sizeof(records[rec_record].target));
		if(records[rec_record].priority<priority_min)
		{
			priority_min=records[rec_record].priority;
		}
	}
	int max_record_minpriority=0;
	for(rec_record=0;rec_record<max_record;rec_record++)
	{
		if(records[rec_record].priority==priority_min)
		{
			records_minpriority[max_record_minpriority]=records[rec_record];
			if(records_minpriority[max_record_minpriority].weight>weight_max)
			{
				weight_max=records_minpriority[max_record_minpriority].weight;
			}
			max_record_minpriority++;
		}
	}
	int rec_record_minpriority=0;
	int max_record_maxweight=0;
	for(rec_record_minpriority=0;rec_record_minpriority<max_record_minpriority;rec_record_minpriority++)
	{
		if(records_minpriority[rec_record_minpriority].weight==weight_max)
		{
			strcpy(target[max_record_maxweight].target,records_minpriority[rec_record_minpriority].target);
			target[max_record_maxweight].port=records_minpriority[rec_record_minpriority].port;
			max_record_maxweight++;
		}
	}
	return max_record_maxweight;
}
