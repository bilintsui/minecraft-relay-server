/*
	Minecraft Relay Server, version 1.0
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Freedom Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
char ** getaddresses(char * hostname)
{
	struct hostent * resolve_result;
	resolve_result = gethostbyname2(hostname,AF_INET);
	if(resolve_result == NULL)
	{
		return NULL;
	}
	return (resolve_result->h_addr_list);
}
int packet_rewrite(unsigned char * source, char * target, unsigned char * server_address, unsigned int server_port)
{
	char fmldetect[BUFSIZ];
	unsigned char char_now,server_port_high,server_port_low,packet_size_new_high,packet_size_new_low;
	unsigned int packet_size, packet_offset_version,current_offset,packet_offset_address,server_address_length_old,server_address_length,packet_offset_port,packet_size_new,packet_offset_nextpacket,packet_size_nextpacket,whole_size;
	packet_size=source[0]+source[1]*256;
	packet_offset_version=2;
	for(current_offset=2;current_offset<=packet_size;current_offset++)
	{
		char_now=target[current_offset]=source[current_offset];
		if(char_now<128)
		{
			packet_offset_address=current_offset+2;
			break;
		}
	}
	server_address_length_old=source[packet_offset_address-1];
	while(server_address[server_address_length]!=0)
	{
		target[packet_offset_address+server_address_length]=server_address[server_address_length];
		server_address_length++;
	}
	bzero(fmldetect,BUFSIZ);
	for(current_offset=0;current_offset<4;current_offset++)
	{
		fmldetect[current_offset]=source[packet_offset_address+server_address_length_old+current_offset-4];
	}
	if(strcmp(fmldetect,"FML")==0)
	{
		target[packet_offset_address+server_address_length]='\0';
		target[packet_offset_address+server_address_length+1]='F';
		target[packet_offset_address+server_address_length+2]='M';
		target[packet_offset_address+server_address_length+3]='L';
		target[packet_offset_address+server_address_length+4]='\0';
		server_address_length=server_address_length+5;
	}
	else if(strcmp(fmldetect,"ML2")==0)
	{
		target[packet_offset_address+server_address_length]='\0';
		target[packet_offset_address+server_address_length+1]='F';
		target[packet_offset_address+server_address_length+2]='M';
		target[packet_offset_address+server_address_length+3]='L';
		target[packet_offset_address+server_address_length+4]='2';
		target[packet_offset_address+server_address_length+5]='\0';
		server_address_length=server_address_length+6;
	}
	target[packet_offset_address-1]=server_address_length;
	packet_offset_port=packet_offset_address+server_address_length;
	server_port_high=server_port/256;
	server_port_low=server_port-server_port_high*256;
	target[packet_offset_port]=server_port_high;
	target[packet_offset_port+1]=server_port_low;
	target[packet_offset_port+2]=source[packet_size];
	packet_size_new=packet_offset_port+2;
	packet_size_new_high=packet_size_new/256;
	packet_size_new_low=packet_size_new-packet_size_new_high*256;
	target[0]=packet_size_new_low;
	target[1]=packet_size_new_high;
	packet_offset_nextpacket=packet_size+1;
	packet_size_nextpacket=source[packet_offset_nextpacket]+source[packet_offset_nextpacket+1]*256;
	for(current_offset=0;current_offset<=packet_size_nextpacket;current_offset++)
	{
		target[packet_offset_port+current_offset+3]=source[packet_offset_nextpacket+current_offset];
	}
	whole_size=packet_offset_port+packet_size_nextpacket+4;
	return whole_size;
}
struct sockaddr_in genSockConf(unsigned short family, unsigned long addr, unsigned short port)
{
	struct sockaddr_in result;
	result.sin_family=family;
	result.sin_addr.s_addr=htonl(addr);
	result.sin_port=htons(port);
	return result;
}
int main(int argc, char * argv[])
{
	char str[INET_ADDRSTRLEN];
	char * bindip,* connip;
	char ** addresses;
	int socket_inbound_server,strulen,socket_inbound_client,connip_resolved;
	struct sockaddr_in addr_inbound_server,addr_inbound_client;
	unsigned short bindport,connport;
	signal(SIGCHLD, SIG_IGN);
	connip_resolved=0;
	if(argc!=5)
	{
		printf("Usage: %s bind_address bind_port target_address target_port\n",argv[0]);
		return 1;
	}
	bindip="0.0.0.0";
	bindport=25565;
	if(inet_addr(argv[1])==-1)
	{
		printf("[WARN] Bad argument: bind_address. Use default address %s.\n",bindip);
	}
	else
	{
		bindip=argv[1];
	}
	if((atoi(argv[2])<=0)||(atoi(argv[2])>=65536))
	{
		printf("[WARN] Bad argument: bind_port. Use default port %d.\n",bindport);
	}
	else
	{
		bindport=atoi(argv[2]);
	}
	if(inet_addr(argv[3])==-1)
	{
		addresses=getaddresses(argv[3]);
		if(addresses==NULL)
		{
			printf("[ERROR] Bad argument: target_address.\n");
			return 1;
		}
		else
		{
			connip=inet_ntop(AF_INET,addresses[0],str,sizeof(str));
			connip_resolved=1;
		}
	}
	else
	{
		connip=argv[3];
	}
	if((atoi(argv[4])<=0)||(atoi(argv[4])>=65536))
	{
		printf("[ERROR] Bad argument: target_port.\n");
		return 1;
	}
	else
	{
		connport=atoi(argv[4]);
	}
	socket_inbound_server=socket(AF_INET,SOCK_STREAM,0);
	printf("Minecraft Relay Server [Version:1.0]\n(C) 2020 Bilin Tsui. All rights reserved.\n\n");
	addr_inbound_server=genSockConf(AF_INET,htonl(inet_addr(bindip)),bindport);
	strulen=sizeof(struct sockaddr_in);
	if(connip_resolved==1)
	{
		printf("[INFO] Resolved %s as %s\n",argv[3],connip);
	}
	printf("[INFO] Rewrite each handshake packet to %s:%d\n",argv[3],connport);
	printf("[INFO] Binding on %s:%d...\n",inet_ntoa(addr_inbound_server.sin_addr),ntohs(addr_inbound_server.sin_port));
	if(bind(socket_inbound_server,(struct sockaddr *)&addr_inbound_server,strulen)==-1){printf("[ERROR] Bind Failed!\n");return 2;}
	printf("[INFO] Bind Successful.\n\n");
	while(1)
	{
		while(listen(socket_inbound_server,1)==-1);
		socket_inbound_client=accept(socket_inbound_server,(struct sockaddr *)&addr_inbound_client,&strulen);
		int pid=fork();
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
			close(socket_inbound_server);
			printf("[INFO] Client %s:%d connected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
			char inbound[BUFSIZ],outbound[BUFSIZ],rewrited[BUFSIZ];
			int socket_outbound,packlen_inbound,packlen_outbound,packlen_first,packlen_second;
			struct sockaddr_in addr_outbound;
			bzero(inbound,BUFSIZ);
			bzero(outbound,BUFSIZ);
			bzero(rewrited,BUFSIZ);
			socket_outbound=socket(AF_INET,SOCK_STREAM,0);
			addr_outbound=genSockConf(AF_INET,htonl(inet_addr(connip)),connport);
			if(connect(socket_outbound,(struct sockaddr*)&addr_outbound,sizeof(struct sockaddr))==-1){printf("[WARN] Cannot connect to the target server, ditched connection with the client.\n");return 3;}
			recv(socket_inbound_client,inbound,BUFSIZ,0);
			packlen_inbound=packet_rewrite(inbound,rewrited,argv[3],connport);
			send(socket_outbound,rewrited,packlen_inbound,0);
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
					printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
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
					printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
					return 0;
				} 
			}
		}
	}
}
