/*
	network.c: Network Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.5
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <unistd.h>
struct stru_net_srvrecord
{
	char target[128];
	unsigned short port;
};
char ** net_resolve(char * hostname)
{
	struct hostent * resolve_result;
	resolve_result = gethostbyname2(hostname,AF_INET);
	if(resolve_result == NULL)
	{
		return NULL;
	}
	return (resolve_result->h_addr_list);
}
int net_srvresolve(char * query_name, struct stru_net_srvrecord * target)
{
	char query_name_full[256];
	bzero(query_name_full,256);
	sprintf(query_name_full,"_minecraft._tcp.%s",query_name);
	struct
	{
		unsigned short priority,weight,port;
		char target[128];
	} records[128],records_minpriority[128],records_maxweight[128];
	bzero(records,sizeof(records));
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
struct sockaddr_in net_mksockaddr_in(unsigned short family, void * addr, unsigned short port)
{
	int strusize=0;
	if(family==AF_INET)
	{
		strusize=sizeof(in_addr_t);
	}
	struct sockaddr_in result;
	result.sin_family=family;
	memcpy(&(result.sin_addr.s_addr),addr,strusize);
	result.sin_port=htons(port);
	return result;
}
struct sockaddr_un net_mksockaddr_un(char * path)
{
	struct sockaddr_un result;
	result.sun_family=AF_UNIX;
	strcpy(result.sun_path,path);
	return result;
}
int net_mkoutbound(int dst_type, char * dst_addr, unsigned short dst_port, int * dst_socket)
{
	void * conninfo=NULL;
	if(dst_type==TYPE_INET)
	{
		*dst_socket=socket(AF_INET,SOCK_STREAM,0);
		in_addr_t connaddr=0;
		if(!inet_pton(AF_INET,dst_addr,&connaddr))
		{
			char ** addresses=net_resolve(dst_addr);
			if(addresses==NULL)
			{
				return 1;
			}
			else
			{
				conninfo=malloc(sizeof(struct sockaddr_in));
				*(struct sockaddr_in *)conninfo=net_mksockaddr_in(AF_INET,addresses[0],dst_port);
			}
		}
		else
		{
			conninfo=malloc(sizeof(struct sockaddr_in));
			*(struct sockaddr_in *)conninfo=net_mksockaddr_in(AF_INET,&connaddr,dst_port);
		}
	}
	else if(dst_type==TYPE_UNIX)
	{
		*dst_socket=socket(AF_UNIX,SOCK_STREAM,0);
		conninfo=malloc(sizeof(struct sockaddr_un));
		*(struct sockaddr_un *)conninfo=net_mksockaddr_un(dst_addr);
	}
	int status=connect(*dst_socket,(struct sockaddr *)conninfo,sizeof(struct sockaddr));
	free(conninfo);
	if(status==-1)
	{
		return 2;
	}
	else
	{
		return 0;
	}
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
