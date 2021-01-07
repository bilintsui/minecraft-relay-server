/*
	proto_modern.c: Functions for Modern Protocol (13w41a and later) on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.3
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
	unsigned long id_part1,version,nextstate,id_part2;
	unsigned char address[128],username[128];
	unsigned short version_fml,port;
};
struct p_handshake packet_read(unsigned char * sourcepacket)
{
	struct p_handshake result;
	unsigned long size_part1,address_length,address_length_pure,size_part2,username_length;
	unsigned char * address_extra_start;
	bzero(result.address,128);
	bzero(result.username,128);
	sourcepacket=varint2int(sourcepacket,&size_part1);
	sourcepacket=varint2int(sourcepacket,&result.id_part1);
	sourcepacket=varint2int(sourcepacket,&result.version);
	sourcepacket=varint2int(sourcepacket,&address_length);
	datcat(result.address,0,sourcepacket,address_length);
	address_length_pure=strlen(result.address);
	if(address_length!=address_length_pure)
	{
		address_extra_start=sourcepacket+address_length_pure+1;
		if(strcmp(address_extra_start,"FML")==0)
		{
			result.version_fml=1;
		}
		else if(strcmp(address_extra_start,"FML2")==0)
		{
			result.version_fml=2;
		}
	}
	else
	{
		result.version_fml=0;
	}
	sourcepacket=sourcepacket+address_length;
	result.port=sourcepacket[0]*256+sourcepacket[1];
	sourcepacket=sourcepacket+2;
	sourcepacket=varint2int(sourcepacket,&result.nextstate);
	sourcepacket=varint2int(sourcepacket,&size_part2);
	sourcepacket=varint2int(sourcepacket,&result.id_part2);
	sourcepacket=varint2int(sourcepacket,&username_length);
	datcat(result.username,0,sourcepacket,username_length);
	return result;
}
int packet_write(struct p_handshake source, unsigned char * target)
{
	int size;
	unsigned long address_length,size_part1,username_length,size_part2;
	unsigned char part1[512],part2[512],address[128];
	unsigned char * ptr_target=target;
	unsigned char * ptr_part1=part1;
	unsigned char * ptr_part2=part2;
	bzero(part1,512);
	bzero(part2,512);
	bzero(address,128);
	ptr_part1=int2varint(source.id_part1,ptr_part1);
	ptr_part1=int2varint(source.version,ptr_part1);
	address_length=datcat(address,0,source.address,strlen(source.address));
	if(source.version_fml==1)
	{
		address_length=datcat(address,address_length,"\0FML\0",5);
	}
	else if(source.version_fml==2)
	{
		address_length=datcat(address,address_length,"\0FML2\0",6);
	}
	ptr_part1=int2varint(address_length,ptr_part1);
	datcat(ptr_part1,0,address,address_length);
	ptr_part1=ptr_part1+address_length;
	ptr_part1[0]=source.port/256;
	ptr_part1[1]=source.port-ptr_part1[0]*256;
	ptr_part1=ptr_part1+2;
	ptr_part1=int2varint(source.nextstate,ptr_part1);
	size_part1=ptr_part1-part1;
	ptr_part2=int2varint(source.id_part2,ptr_part2);
	if(source.nextstate==2)
	{
		username_length=strlen(source.username);
		ptr_part2=int2varint(username_length,ptr_part2);
		datcat(ptr_part2,0,source.username,username_length);
		ptr_part2=ptr_part2+username_length;
	}
	size_part2=ptr_part2-part2;
	ptr_target=int2varint(size_part1,ptr_target);
	datcat(ptr_target,0,part1,size_part1);
	ptr_target=ptr_target+size_part1;
	ptr_target=int2varint(size_part2,ptr_target);
	datcat(ptr_target,0,part2,size_part2);
	ptr_target=ptr_target+size_part2;
	size=ptr_target-target;
	return size;
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
