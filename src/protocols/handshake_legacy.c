/*
	protocols/handshake_legacy.c: Functions for Legacy Protocol (13w39b and before) on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../basic.h"
#include "common.h"

#include "handshake_legacy.h"

size_t make_message_legacy(void * dst, void * src, size_t n)
{
	void * tmp=malloc(BUFSIZ);
	u_int8_t * ptr_src=src;
	u_int16_t * ptr_tmp=tmp;
	for(size_t i=0;i<n;i++)
	{
		*ptr_tmp=htons(*ptr_src);
		ptr_src++;
		ptr_tmp++;
	}
	memset(dst,0xFF,1);
	u_int16_t * ptr_dst=dst+1;
	*ptr_dst=htons(n);
	ptr_dst++;
	size_t tmp_length=((void *)ptr_tmp)-tmp;
	memcpy(ptr_dst,tmp,tmp_length);
	size_t dst_length=((void *)ptr_dst-dst)+tmp_length;
	free(tmp);
	return dst_length;
}
size_t make_kickreason_legacy(void * dst, void * src)
{
	return make_message_legacy(dst,src,strlen(src));
}
size_t make_motd_legacy(void * dst, void * src, int motd_version, unsigned int version)
{
	void * tmp=malloc(BUFSIZ);
	size_t tmp_length=0;
	switch(motd_version)
	{
		case PVER_LEGACYM1:
			strcpy(tmp,src);
			tmp_length=memcat(tmp,strlen(tmp),"\xA7",1);
			tmp_length=memcat(tmp,tmp_length,"0",1);
			tmp_length=memcat(tmp,tmp_length,"\xA7",1);
			tmp_length=memcat(tmp,tmp_length,"0",1);
			break;
		case PVER_LEGACYM2:
		case PVER_LEGACYM3:
			memset(tmp,0xA7,1);
			tmp_length=memcat(tmp,1,"1\0",2);
			tmp_length=tmp_length+sprintf(tmp+tmp_length,"%d",version)+1;
			tmp_length=memcat(tmp,tmp_length,"",1);
			tmp_length=memcat(tmp,tmp_length,src,strlen(src)+1);
			tmp_length=memcat(tmp,tmp_length,"0\0",2);
			tmp_length=memcat(tmp,tmp_length,"0",1);
			break;
		default:
			break;
	}
	size_t dst_length=make_message_legacy(dst,tmp,tmp_length);
	free(tmp);
	return dst_length;
}
p_login_legacy packet_read_legacy_login(unsigned char * sourcepacket, int sourcepacket_length, int login_version)
{
	p_login_legacy result;
	unsigned char source[BUFSIZ];
	unsigned char * ptr_source=source;
	int recidx,source_length;
	result.proto_ver=login_version;
	memset(source,0,BUFSIZ);
	memset(result.username,0,128);
	memset(result.address,0,128);
	source_length=packetshrink(sourcepacket,sourcepacket_length,source);
	if(login_version==PVER_LEGACYL2)
	{
		unsigned char login_field[512];
		unsigned char * ptr_login_field=login_field;
		memset(login_field,0,512);
		for(recidx=0;recidx<source[1];recidx++)
		{
			login_field[recidx]=source[2+recidx];
		}
		ptr_login_field=strtok_head(result.username,ptr_login_field,';');
		size_t fieldsize_address=strtok_tail(NULL,ptr_login_field,':',strlen(ptr_login_field));
		strncpy(result.address,ptr_login_field,fieldsize_address);
		result.address[fieldsize_address]='\0';
		ptr_login_field=ptr_login_field+fieldsize_address+1;
		result.port=atoi(ptr_login_field);
	}
	else
	{
		unsigned int username_length,address_length;
		if(login_version==PVER_LEGACYL1)
		{
			ptr_source=ptr_source+1;
		}
		else
		{
			result.version=source[1];
			ptr_source=ptr_source+2;
		}
		username_length=*ptr_source;
		ptr_source++;
		for(recidx=0;recidx<username_length;recidx++)
		{
			result.username[recidx]=*ptr_source;
			ptr_source++;
		}
		if(login_version==PVER_LEGACYL4)
		{
			address_length=*ptr_source;
			ptr_source++;
			for(recidx=0;recidx<address_length;recidx++)
			{
				result.address[recidx]=*ptr_source;
				ptr_source++;
			}
			result.port=ptr_source[0]*256+ptr_source[1];
		}
	}
	return result;
}
p_motd_legacy packet_read_legacy_motd(void * src)
{
	p_motd_legacy result;
	result.version=*(u_int8_t *)(src+0x1D);
	u_int16_t * ptr_src=src+0x1E;
	size_t address_length=ntohs(*ptr_src);
	ptr_src++;
	result.address=calloc(1,address_length+1);
	u_int8_t * ptr_address=result.address;
	for(size_t i=0;i<address_length;i++)
	{
		*ptr_address=ntohs(*ptr_src);
		ptr_src++;
		ptr_address++;
	}
	result.port=ntohl(*((u_int32_t *)ptr_src));
	return result;
}
int packet_write_legacy_login(p_login_legacy source, unsigned char * target)
{
	unsigned char tmp[BUFSIZ];
	unsigned int tmp_length,size;
	memset(tmp,0,BUFSIZ);
	target[0]=2;
	size=1;
	if(source.proto_ver==PVER_LEGACYL2)
	{
		unsigned char login_field[512],login_field_full[512];
		memset(login_field,0,512);
		memset(login_field_full,0,512);
		sprintf(login_field,"%s;%s:%d",source.username,source.address,source.port);
		unsigned int login_field_length=strlen(login_field);
		login_field_full[0]=login_field_length;
		unsigned int login_field_full_length=memcat(login_field_full,1,login_field,login_field_length);
		tmp_length=packetexpand(login_field_full,login_field_full_length,tmp);
		size=memcat(target,size,tmp,tmp_length);
	}
	else
	{
		if(source.proto_ver!=PVER_LEGACYL1)
		{
			target[1]=source.version;
			size=2;
		}
		unsigned char username[128];
		unsigned int username_length=strlen(source.username);
		username[0]=username_length;
		username_length=memcat(username,1,source.username,username_length);
		tmp_length=packetexpand(username,username_length,tmp);
		size=memcat(target,size,tmp,tmp_length);
		if(source.proto_ver==PVER_LEGACYL4)
		{
			unsigned char address[128];
			unsigned int address_length=strlen(source.address);
			address[0]=address_length;
			address_length=memcat(address,1,source.address,address_length);
			tmp_length=packetexpand(address,address_length,tmp);
			size=memcat(target,size,tmp,tmp_length);
			target[size]=0;
			target[size+1]=0;
			target[size+2]=source.port/256;
			target[size+3]=source.port-target[size+2]*256;
			size=size+4;
		}
	}
	return size;
}
size_t packet_write_legacy_motd(void * dst, p_motd_legacy src)
{
	memcpy(dst,"\xFE\x01\xFA\0\x0B\0M\0C\0|\0P\0i\0n\0g\0H\0o\0s\0t",0x1B);
	u_int16_t * ptr_dst=dst+0x1B;
	size_t address_length=strlen(src.address);
	*ptr_dst=htons(address_length*2+7);
	ptr_dst++;
	*((u_int8_t *)ptr_dst)=src.version;
	ptr_dst=((void *)ptr_dst)+1;
	*ptr_dst=htons(address_length);
	ptr_dst++;
	u_int8_t * ptr_address=src.address;
	u_int16_t tmp_data;
	for(size_t i=0;i<address_length;i++)
	{
		tmp_data=*ptr_address;
		*ptr_dst=htons(tmp_data);
		ptr_address++;
		ptr_dst++;
	}
	*((u_int32_t *)ptr_dst)=htonl(src.port);
	ptr_dst=(u_int16_t *)(((u_int32_t *)ptr_dst)+1);
	size_t size=(void *)ptr_dst-dst;
	return size;
}
void packet_destroy_legacy_motd(p_motd_legacy object)
{
	if(object.address!=NULL)
	{
		free(object.address);
	}
}
