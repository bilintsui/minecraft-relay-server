/*
	network.h: Network Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.
	Requires: mod/basic.h, please manually include it in main source code. Also require libresolv.so, use option: -lresolv in gcc compile.
	
	Minecraft Relay Server, version 1.1.1
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
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
struct sockaddr_in net_mksockaddr_in(unsigned short family, unsigned long addr, unsigned short port)
{
	struct sockaddr_in result;
	result.sin_family=family;
	result.sin_addr.s_addr=htonl(addr);
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
	char str[INET_ADDRSTRLEN];
	if(dst_type==TYPE_INET)
	{
		*dst_socket=socket(AF_INET,SOCK_STREAM,0);
		if(inet_addr(dst_addr)==-1)
		{
			char ** addresses=net_resolve(dst_addr);
			if(addresses==NULL)
			{
				return 1;
			}
			else
			{
				struct sockaddr_in conninfo=net_mksockaddr_in(AF_INET,htonl(inet_addr(inet_ntop(AF_INET,addresses[0],str,sizeof(str)))),dst_port);
				if(connect(*dst_socket,(struct sockaddr*)&conninfo,sizeof(struct sockaddr))==-1)
				{
					return 2;
				}
				else
				{
					return 0;
				}
			}
		}
		else
		{
			struct sockaddr_in conninfo=net_mksockaddr_in(AF_INET,htonl(inet_addr(dst_addr)),dst_port);
			if(connect(*dst_socket,(struct sockaddr*)&conninfo,sizeof(struct sockaddr))==-1)
			{
				return 2;
			}
			else
			{
				return 0;
			}
		}
	}
	else if(dst_type==TYPE_UNIX)
	{
		struct sockaddr_un conninfo;
		conninfo.sun_family=AF_UNIX;
		strcpy(conninfo.sun_path,dst_addr);
		if(connect(*dst_socket,(struct sockaddr*)&conninfo,sizeof(struct sockaddr))==-1)
		{
			return 2;
		}
		else
		{
			return 0;
		}
	}
}
int net_relay(int * ptr_inboundsocket, int * ptr_outboundsocket)
{
	int packlen_inbound,packlen_outbound;
	char inbound[BUFSIZ],outbound[BUFSIZ];
	int socket_inbound_client=*ptr_inboundsocket;
	int socket_outbound=*ptr_outboundsocket;
	bzero(inbound,BUFSIZ);
	bzero(outbound,BUFSIZ);
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
