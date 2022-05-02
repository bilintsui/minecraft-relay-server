/*
	protocols/handshake.c: Functions for Modern Protocol (13w41a and later) on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../basic.h"

#include "handshake.h"

size_t make_message(char * dst, const char * src)
{
	size_t size,string_length,payload_size;
	char tmp[BUFSIZ];
	char * ptr_tmp=tmp;
	char * ptr_dst=dst;
	*ptr_tmp=0;
	ptr_tmp++;
	string_length=strlen(src);
	ptr_tmp=int2varint(string_length,ptr_tmp);
	payload_size=ptr_tmp-tmp+string_length;
	memcpy(ptr_tmp,src,string_length);
	ptr_tmp=tmp;
	ptr_dst=int2varint(payload_size,ptr_dst);
	size=ptr_dst-dst+payload_size;
	memcpy(ptr_dst,ptr_tmp,payload_size);
	return size;
}
size_t make_kickreason(char * dst, const char * src)
{
	char input[BUFSIZ];
	sprintf(input,"{\"extra\":[{\"text\":\"%s\"}],\"text\":\"\"}",src);
	return make_message(dst,input);
}
size_t make_motd(char * dst, const char * src, varint_l ver)
{
	char input[BUFSIZ];
	sprintf(input,"{\"version\":{\"name\":\"\",\"protocol\":%lu},\"players\":{\"max\":0,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"%s\"}}",ver,src);
	return make_message(dst,input);
}
p_handshake packet_read(void * sourcepacket)
{
	p_handshake result;
	in_port_t port_netorder=0;
	void * address_extra_start, * part2_start;
	size_t address_length,address_length_pure,size_part1,size_part2,username_length;
	sourcepacket=varint2int(sourcepacket,&size_part1);
	sourcepacket=varint2int(sourcepacket,&result.id_part1);
	sourcepacket=varint2int(sourcepacket,&result.version);
	sourcepacket=varint2int(sourcepacket,&address_length);
	result.address=calloc(1,address_length+1);
	memcpy(result.address,sourcepacket,address_length);
	address_length_pure=strlen(result.address);
	if(address_length!=address_length_pure)
	{
		address_extra_start=sourcepacket+address_length_pure;
		if(memcmp(address_extra_start,"\0FML\0",5)==0)
		{
			memset(address_extra_start,0,5);
			result.address=realloc(result.address,address_length_pure+1);
			result.version_fml=1;
		}
		else if(memcmp(address_extra_start,"\0FML2\0",6)==0)
		{
			memset(address_extra_start,0,6);
			result.address=realloc(result.address,address_length_pure+1);
			result.version_fml=2;
		}
	}
	else
	{
		result.version_fml=0;
	}
	sourcepacket=sourcepacket+address_length;
	memcpy(&port_netorder,sourcepacket,sizeof(port_netorder));
	result.port=ntohs(port_netorder);
	sourcepacket=sourcepacket+sizeof(port_netorder);
	sourcepacket=varint2int(sourcepacket,&result.nextstate);
	if(result.nextstate==2)
	{
		sourcepacket=varint2int(sourcepacket,&size_part2);
		part2_start=sourcepacket;
		sourcepacket=varint2int(sourcepacket,&result.id_part2);
		sourcepacket=varint2int(sourcepacket,&username_length);
		result.username=calloc(1,username_length+1);
		memcpy(result.username,sourcepacket,username_length);
		sourcepacket=sourcepacket+username_length;
		result.signature_data_length=size_part2-(sourcepacket-part2_start);
		sourcepacket=varint2int(sourcepacket,NULL);
		if(result.signature_data_length)
		{
			result.signature_data_length--;
			result.signature_data=malloc(result.signature_data_length);
			memcpy(result.signature_data,sourcepacket,result.signature_data_length);
			sourcepacket=sourcepacket+result.signature_data_length;
		}
	}
	return result;
}
size_t packet_write(p_handshake source, void * target)
{
	in_port_t port_netorder=0;
	size_t address_length,address_length_pure,size,size_part1,size_part2,username_length;
	void * part1=malloc(BUFSIZ);
	void * part2=malloc(BUFSIZ);
	void * ptr_target=target;
	void * ptr_part1=part1;
	void * ptr_part2=part2;
	ptr_part1=int2varint(source.id_part1,ptr_part1);
	ptr_part1=int2varint(source.version,ptr_part1);
	address_length_pure=strlen(source.address);
	if(source.version_fml==1)
	{
		address_length=address_length_pure+5;
	}
	else if(source.version_fml==2)
	{
		address_length=address_length_pure+6;
	}
	ptr_part1=int2varint(address_length,ptr_part1);
	memcpy(ptr_part1,source.address,address_length_pure);
	if(source.version_fml==1)
	{
		memcpy(ptr_part1+address_length_pure,"\0FML\0",5);
	}
	else if(source.version_fml==2)
	{
		memcpy(ptr_part1+address_length_pure,"\0FML2\0",6);
	}
	ptr_part1=ptr_part1+address_length;
	port_netorder=htons(source.port);
	memcpy(ptr_part1,&port_netorder,sizeof(port_netorder));
	ptr_part1=ptr_part1+sizeof(port_netorder);
	ptr_part1=int2varint(source.nextstate,ptr_part1);
	size_part1=ptr_part1-part1;
	ptr_part2=int2varint(source.id_part2,ptr_part2);
	if(source.nextstate==2)
	{
		username_length=strlen(source.username);
		ptr_part2=int2varint(username_length,ptr_part2);
		memcpy(ptr_part2,source.username,username_length);
		ptr_part2=ptr_part2+username_length;
		if(source.signature_data_length)
		{
			memset(ptr_part2,1,1);
			ptr_part2++;
			memcpy(ptr_part2,source.signature_data,source.signature_data_length);
			ptr_part2=ptr_part2+source.signature_data_length;
		}
	}
	size_part2=ptr_part2-part2;
	ptr_target=int2varint(size_part1,ptr_target);
	memcpy(ptr_target,part1,size_part1);
	ptr_target=ptr_target+size_part1;
	ptr_target=int2varint(size_part2,ptr_target);
	memcpy(ptr_target,part2,size_part2);
	ptr_target=ptr_target+size_part2;
	size=ptr_target-target;
	free(part1);
	free(part2);
	return size;
}
void packet_destroy(p_handshake object)
{
	if(object.address!=NULL)
	{
		free(object.address);
		object.address=NULL;
	}
	if(object.signature_data!=NULL)
	{
		free(object.signature_data);
		object.signature_data=NULL;
	}
	if(object.username!=NULL)
	{
		free(object.username);
		object.username=NULL;
	}
}
