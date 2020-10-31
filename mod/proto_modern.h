/*
	proto_modern.h: Functions for Modern Protocol (13w41a+) on Minecraft Relay Server
	A component of Minecraft Relay Server.
	Requires: mod/basic.h, please manually include it in main source code.
	
	Minecraft Relay Server, version 1.1-beta2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <stdio.h>
#include <string.h>
struct p_handshake
{
	unsigned long id_part1,version,version_fml,nextstate,id_part2;
	char * addr,* user;
	unsigned short port;
};
struct p_handshake packet_read(unsigned char * sourcepacket)
{
	struct p_handshake result;
	unsigned long size_part1,size_part2,addr_length,recidx,addr_length_new,user_length;
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
	sourcepacket=varint2int(sourcepacket,&size_part2);
	sourcepacket=varint2int(sourcepacket,&result.id_part2);
	if(result.nextstate==2)
	{
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
	int recidx;
	unsigned long source_size1,source_id1,source_version,source_addrlen,source_addrlen_pure,source_exaddrlen,source_nextstate,source_size2,source_id2,source_userlen,target_size,target_size1,target_addrlen_pure,target_addrlen,target_size2;
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
	ptr_target2=int2varint(source_id2,ptr_target2);
	if(source_nextstate==2)
	{
		ptr_target2=int2varint(source_userlen,ptr_target2);
		for(recidx=0;recidx<source_userlen;recidx++)
		{
			*ptr_target2=source_user[recidx];
			ptr_target2++;
		}
	}
	target_size2=ptr_target2-target2;
	ptr_target=int2varint(target_size2,ptr_target);
	for(recidx=0;recidx<target_size2;recidx++)
	{
		*ptr_target=target2[recidx];
		ptr_target++;
	}
	target_size=ptr_target-target;
	return target_size;
}
int make_message(unsigned char * source, unsigned char * target)
{
	int size,recidx,string_length,payload_size;
	unsigned char tmp[BUFSIZ];
	unsigned char * ptr_tmp=tmp;
	unsigned char * ptr_source=source;
	unsigned char * ptr_target=target;
	*ptr_tmp=0;
	ptr_tmp++;
	string_length=strlen(source);
	ptr_tmp=int2varint(string_length,ptr_tmp);
	for(recidx=0;recidx<string_length;recidx++)
	{
		*ptr_tmp=*ptr_source;
		ptr_tmp++;
		ptr_source++;
	}
	payload_size=ptr_tmp-tmp;
	ptr_tmp=tmp;
	ptr_target=int2varint(payload_size,ptr_target);
	for(recidx=0;recidx<payload_size;recidx++)
	{
		*ptr_target=*ptr_tmp;
		ptr_target++;
		ptr_tmp++;
	}
	size=ptr_target-target;
	return size;
}
int make_kickreason(unsigned char * source, unsigned char * target)
{
	int size;
	unsigned char input[BUFSIZ];
	sprintf(input,"{\"extra\":[{\"text\":\"%s\"}],\"text\":\"\"}",source);
	size=make_message(input,target);
	return size;
}
int make_motd(unsigned long version, unsigned char * description, unsigned char * target)
{
	int size;
	unsigned char input[BUFSIZ];
	sprintf(input,"{\"version\":{\"name\":\"\",\"protocol\":%ld},\"players\":{\"max\":0,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"%s\"}}",version,description);
	size=make_message(input,target);
	return size;
}
