/*
	Minecraft Relay Server, version 1.1-beta1
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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#define TYPE_UNIX 1
#define TYPE_INET 2
struct p_handshake
{
	int id_part1,version,version_fml,nextstate,id_part2;
	char * addr,* user;
	unsigned short port;
};
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
//	char log[512];
	struct conf_bind bind;
	int relay_count;
	struct conf_map relay[128];
};
int math_pow(int x,int y)
{
	int i,result;
	result=1;
	for(i=1;i<=y;i++)
	{
		result=result*x;
	}
	return result;
}
unsigned char * varint2int(unsigned char * source, unsigned int * output)
{
	unsigned char * recent_ptr=source;
	unsigned char recent_char;
	int data=0;
	int char_num=0;
	while(1)
	{
		recent_char=*recent_ptr;
		if(recent_char>=128)
		{
			data=data+((recent_char-128)*math_pow(128,char_num));
		}
		else
		{
			data=data+(recent_char*math_pow(128,char_num));
			recent_ptr++;
			break;
		}
		recent_ptr++;
		char_num++;
	}
	*output=data;
	return recent_ptr;
}
unsigned char * int2varint(int data, unsigned char * output)
{
	unsigned char * ptr_output=output;
	unsigned char current_byte;
	int data_old,data_new;
	data_old=data;
	int length=0;
	while(1)
	{
		if(data_old>=128)
		{
			data_new=data_old/128;
			current_byte=data_old-data_new*128+128;
			*ptr_output=current_byte;
			data_old=data_new;
			ptr_output++;
			length++;
		}
		else
		{
			current_byte=data_old;
			*ptr_output=current_byte;
			ptr_output++;
			length++;
			break;
		}
	}
	return ptr_output;
}
struct p_handshake packet_read(unsigned char * sourcepacket)
{
	struct p_handshake result;
	int size_part1,size_part2,addr_length,recidx,addr_length_new,user_length;
	unsigned char addr[BUFSIZ],user[BUFSIZ],addr_extra[BUFSIZ];
	char char_now;
	bzero(addr,BUFSIZ);
	bzero(user,BUFSIZ);
	bzero(addr_extra,BUFSIZ);
	sourcepacket=varint2int(sourcepacket,&size_part1);
	sourcepacket=varint2int(sourcepacket,&result.id_part1);
	sourcepacket=varint2int(sourcepacket,&result.version);
	sourcepacket=varint2int(sourcepacket,&addr_length);
	for(recidx=0;recidx<addr_length;recidx++)
	{
		addr[recidx]=*sourcepacket;
		sourcepacket++;
	}
	result.addr=addr;
	addr_length_new=strlen(addr);
	if(addr_length!=addr_length_new)
	{
		for(recidx=0;(recidx+addr_length_new+2)<=addr_length;recidx++)
		{
			addr_extra[recidx]=addr[addr_length_new+recidx+1];
			addr[addr_length_new+recidx+1]='\0';
		}
		if(strcmp(addr_extra,"FML")==0)
		{
			result.version_fml=1;
		}
		else if(strcmp(addr_extra,"FML2")==0)
		{
			result.version_fml=2;
		}
	}
	else
	{
		result.version_fml=0;
	}
	result.port=sourcepacket[0]*256+sourcepacket[1];
	sourcepacket=sourcepacket+2;
	sourcepacket=varint2int(sourcepacket,&result.nextstate);
	if(result.nextstate==2)
	{
		sourcepacket=varint2int(sourcepacket,&size_part2);
		sourcepacket=varint2int(sourcepacket,&result.id_part2);
		sourcepacket=varint2int(sourcepacket,&user_length);
		for(recidx=0;recidx<user_length;recidx++)
		{
			user[recidx]=*sourcepacket;
			sourcepacket++;
		}
		result.user=user;
	}
	return result;
}
int packet_rewrite(unsigned char * source, unsigned char * target, unsigned char * server_address, unsigned int server_port)
{
	int recidx,source_size1,source_id1,source_version,source_addrlen,source_addrlen_pure,source_exaddrlen,source_nextstate,source_size2,source_id2,source_userlen,target_size,target_size1,target_addrlen_pure,target_addrlen,target_size2;
	unsigned char source_addr[BUFSIZ],source_exaddr[BUFSIZ],source_user[BUFSIZ],target1[BUFSIZ],target2[BUFSIZ],target_port_high,target_port_low;
	unsigned short source_port;
	unsigned char * ptr_source,* ptr_source_addr_offset,* ptr_target,* ptr_target1,* ptr_target2;
	source_exaddrlen=0;
	bzero(source_addr,BUFSIZ);
	bzero(source_exaddr,BUFSIZ);
	bzero(source_user,BUFSIZ);
	bzero(target1,BUFSIZ);
	bzero(target2,BUFSIZ);
	ptr_source=source;
	ptr_target=target;
	ptr_target1=target1;
	ptr_target2=target2;
	ptr_source=varint2int(ptr_source,&source_size1);
	ptr_source=varint2int(ptr_source,&source_id1);
	ptr_source=varint2int(ptr_source,&source_version);
	ptr_source=varint2int(ptr_source,&source_addrlen);
	ptr_source_addr_offset=ptr_source;
	for(recidx=0;recidx<source_addrlen;recidx++)
	{
		source_addr[recidx]=*ptr_source;
		ptr_source++;
	}
	source_addrlen_pure=strlen(source_addr);
	if(source_addrlen!=source_addrlen_pure)
	{
		source_exaddrlen=source_addrlen-source_addrlen_pure;
		for(recidx=0;recidx<source_exaddrlen-1;recidx++)
		{
			source_exaddr[recidx]=ptr_source_addr_offset[recidx+source_addrlen_pure+1];
			ptr_source_addr_offset[recidx+source_addrlen_pure+1]='\0';
		}
	}
	source_port=ptr_source[0]*256+ptr_source[1];
	ptr_source=ptr_source+2;
	ptr_source=varint2int(ptr_source,&source_nextstate);
	ptr_source=varint2int(ptr_source,&source_size2);
	ptr_source=varint2int(ptr_source,&source_id2);
	ptr_source=varint2int(ptr_source,&source_userlen);
	for(recidx=0;recidx<source_userlen;recidx++)
	{
		source_user[recidx]=ptr_source[recidx];
	}
	target_addrlen_pure=strlen(server_address);
	target_addrlen=target_addrlen_pure+source_exaddrlen;
	ptr_target1=int2varint(source_id1,ptr_target1);
	ptr_target1=int2varint(source_version,ptr_target1);
	ptr_target1=int2varint(target_addrlen,ptr_target1);
	for(recidx=0;recidx<target_addrlen_pure;recidx++)
	{
		*ptr_target1=server_address[recidx];
		ptr_target1++;
	}
	if(source_exaddrlen!=0)
	{
		ptr_target1++;
		for(recidx=0;recidx<source_exaddrlen-1;recidx++)
		{
			*ptr_target1=source_exaddr[recidx];
			ptr_target1++;
		}
	}
	ptr_target1[0]=target_port_high=server_port/256;
	ptr_target1[1]=target_port_low=server_port-target_port_high*256;
	ptr_target1=ptr_target1+2;
	ptr_target1=int2varint(source_nextstate,ptr_target1);
	target_size1=ptr_target1-target1;
	ptr_target=int2varint(target_size1,ptr_target);
	for(recidx=0;recidx<target_size1;recidx++)
	{
		*ptr_target=target1[recidx];
		ptr_target++;
	}
	if(source_nextstate==2)
	{
		ptr_target2=int2varint(source_id2,ptr_target2);
		ptr_target2=int2varint(source_userlen,ptr_target2);
		for(recidx=0;recidx<source_userlen;recidx++)
		{
			*ptr_target2=source_user[recidx];
			ptr_target2++;
		}
		target_size2=ptr_target2-target2;
		ptr_target=int2varint(target_size2,ptr_target);
		for(recidx=0;recidx<target_size2;recidx++)
		{
			*ptr_target=target2[recidx];
			ptr_target++;
		}
	}
	target_size=ptr_target-target;
	return target_size;
}
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
//			strcpy(result.log,value);
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
/*	if(strcmp(result.log,"")==0)
	{
		printf("[CRIT] Error in configurations: Argument \"log\" is missing.\n");
		exit(22);
	}*/
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
	char *bindip,*connip;
	char **addresses;
	int socket_inbound_server,strulen,socket_inbound_client,connip_resolved;
	struct sockaddr_in addr_inbound_server,addr_inbound_client;
	struct sockaddr_un uddr_inbound_server,uddr_inbound_client;
	struct conf config;
	unsigned short bindport,connport;
	signal(SIGCHLD, SIG_IGN);
	connip_resolved=0;
	printf("Minecraft Relay Server [Version:1.1-beta1]\n(C) 2020 Bilin Tsui. All rights reserved.\n\n");
	if(argc!=2)
	{
		printf("Usage: %s config_file\n\nSee more, watch: https://github.com/bilintsui/minecraft-relay-server\n",argv[0]);
		return 1;
	}
	bindip="0.0.0.0";
	bindport=25565;
	printf("[INFO] Loading configurations from file: %s\n\n",argv[1]);
	config=config_load(argv[1]);
	if(config.bind.type==TYPE_INET)
	{
		if(inet_addr(config.bind.inet_addr)==-1)
		{
			printf("[WARN] Bad argument: bind_address. Use default address %s.\n",bindip);
		}
		else
		{
			bindip=config.bind.inet_addr;
		}
		if((config.bind.inet_port<1)||(config.bind.inet_port>65535))
		{
			printf("[WARN] Bad argument: bind_port. Use default port %d.\n",bindport);
		}
		else
		{
			bindport=config.bind.inet_port;
		}
		socket_inbound_server=socket(AF_INET,SOCK_STREAM,0);
		addr_inbound_server=genSockConf(AF_INET,htonl(inet_addr(bindip)),bindport);
		strulen=sizeof(struct sockaddr_in);
		printf("[INFO] Binding on %s:%d...\n",inet_ntoa(addr_inbound_server.sin_addr),ntohs(addr_inbound_server.sin_port));
		if(bind(socket_inbound_server,(struct sockaddr *)&addr_inbound_server,strulen)==-1){printf("[CRIT] Bind Failed!\n");return 2;}
		printf("[INFO] Bind Successful.\n\n");
	}
	else if(config.bind.type==TYPE_UNIX)
	{
		unlink(config.bind.unix_path);
		socket_inbound_server=socket(AF_UNIX,SOCK_STREAM,0);
		uddr_inbound_server.sun_family=AF_UNIX;
		strcpy(uddr_inbound_server.sun_path,config.bind.unix_path);
		strulen=sizeof(uddr_inbound_server);
		printf("[INFO] Binding on %s...\n",uddr_inbound_server.sun_path);
		if(bind(socket_inbound_server,(struct sockaddr *)&uddr_inbound_server,strulen)==-1){printf("[CRIT] Bind Failed!\n");return 2;}
		printf("[INFO] Bind Successful.\n\n");
	}
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
			if(config.bind.type==TYPE_INET)
			{
				printf("[INFO] Client %s:%d connected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
			}
			else if(config.bind.type==TYPE_UNIX)
			{
				printf("[INFO] Client connected.\n");
			}
			char inbound[BUFSIZ],outbound[BUFSIZ],rewrited[BUFSIZ];
			int socket_outbound,packlen_inbound,packlen_outbound,packlen_rewrited;
			struct sockaddr_in addr_outbound;
			struct sockaddr_un uddr_outbound;
			bzero(inbound,BUFSIZ);
			bzero(outbound,BUFSIZ);
			bzero(rewrited,BUFSIZ);
			packlen_inbound=recv(socket_inbound_client,inbound,BUFSIZ,0);
			struct p_handshake inbound_info=packet_read(inbound);
			int rec_relay,found_relay;
			found_relay=0;
			for(rec_relay=0;rec_relay<config.relay_count;rec_relay++)
			{
				if(strcmp(config.relay[rec_relay].from,inbound_info.addr)==0)
				{	
					found_relay=1;
					if(config.relay[rec_relay].to_type==TYPE_INET)
					{
						socket_outbound=socket(AF_INET,SOCK_STREAM,0);
						if(inet_addr(config.relay[rec_relay].to_inet_addr)==-1)
						{
							char ** addresses=getaddresses(config.relay[rec_relay].to_inet_addr);
							if(addresses==NULL)
							{
								printf("[WARN] Cannot resolve host: %s, ditched connection with the client.\n",config.relay[rec_relay].to_inet_addr);
								if(config.bind.type==TYPE_INET)
								{
									printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
								}
								else if(config.bind.type==TYPE_UNIX)
								{
									printf("[INFO] Client disconnected.\n");
								}
								shutdown(socket_inbound_client,SHUT_RDWR);
								close(socket_inbound_client);
								return 3;
							}
							else
							{
								addr_outbound=genSockConf(AF_INET,htonl(inet_addr(inet_ntop(AF_INET,addresses[0],str,sizeof(str)))),config.relay[rec_relay].to_inet_port);
								if(connect(socket_outbound,(struct sockaddr*)&addr_outbound,sizeof(struct sockaddr))==-1)
								{
									printf("[WARN] Cannot connect to the target server, ditched connection with the client.\n");
									if(config.bind.type==TYPE_INET)
									{
										printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
									}
									else if(config.bind.type==TYPE_UNIX)
									{
										printf("[INFO] Client disconnected.\n");
									}
									shutdown(socket_inbound_client,SHUT_RDWR);
									close(socket_inbound_client);
									return 4;
								}
							}
						}
						else
						{
							addr_outbound=genSockConf(AF_INET,htonl(inet_addr(config.relay[rec_relay].to_inet_addr)),config.relay[rec_relay].to_inet_port);
							if(connect(socket_outbound,(struct sockaddr*)&addr_outbound,sizeof(struct sockaddr))==-1)
							{
								printf("[WARN] Cannot connect to the target server, ditched connection with the client.\n");
								if(config.bind.type==TYPE_INET)
								{
									printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
								}
								else if(config.bind.type==TYPE_UNIX)
								{
									printf("[INFO] Client disconnected.\n");
								}
								shutdown(socket_inbound_client,SHUT_RDWR);
								close(socket_inbound_client);
								return 4;
							}
						}
					}
					else if(config.relay[rec_relay].to_type==TYPE_UNIX)
					{
						socket_outbound=socket(AF_UNIX,SOCK_STREAM,0);
						uddr_outbound.sun_family=AF_UNIX;
						strcpy(uddr_outbound.sun_path,config.relay[rec_relay].to_unix_path);
						if(connect(socket_outbound,(struct sockaddr*)&uddr_outbound,sizeof(struct sockaddr))==-1)
						{
							printf("[WARN] Cannot connect to the target socket, ditched connection with the client.\n");
							if(config.bind.type==TYPE_INET)
							{
								printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
							}
							else if(config.bind.type==TYPE_UNIX)
							{
								printf("[INFO] Client disconnected.\n");
							}
							shutdown(socket_inbound_client,SHUT_RDWR);
							close(socket_inbound_client);
							return 4;
						}
					}
					break;
				}
			}
			if(found_relay==0)
			{
				printf("[WARN] Client using an invalid hostname, ditched connection with the client.\n");
				if(config.bind.type==TYPE_INET)
				{
					printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
				}
				else if(config.bind.type==TYPE_UNIX)
				{
					printf("[INFO] Client disconnected.\n");
				}
				shutdown(socket_inbound_client,SHUT_RDWR);
				close(socket_inbound_client);
				return 4;
			}
			if(config.relay[rec_relay].to_type==TYPE_INET)
			{
				if(config.relay[rec_relay].enable_rewrite==1)
				{
					packlen_rewrited=packet_rewrite(inbound,rewrited,config.relay[rec_relay].to_inet_addr,config.relay[rec_relay].to_inet_port);
					send(socket_outbound,rewrited,packlen_rewrited,0);
				}
				else
				{
					send(socket_outbound,inbound,packlen_inbound,0);
				}
			}
			else if(config.relay[rec_relay].to_type==TYPE_UNIX)
			{
				send(socket_outbound,inbound,packlen_inbound,0);
			}
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
					if(config.bind.type==TYPE_INET)
					{
						printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
					}
					else if(config.bind.type==TYPE_UNIX)
					{
						printf("[INFO] Client disconnected.\n");
					}
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
					if(config.bind.type==TYPE_INET)
					{
						printf("[INFO] Client %s:%d disconnected.\n",inet_ntoa(addr_inbound_client.sin_addr),ntohs(addr_inbound_client.sin_port));
					}
					else if(config.bind.type==TYPE_UNIX)
					{
						printf("[INFO] Client disconnected.\n");
					}
					return 0;
				} 
			}
		}
	}
}
