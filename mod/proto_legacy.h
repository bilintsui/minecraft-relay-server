/*
	proto_legacy.h: Functions for Legacy Protocol (12w04a-13w39b) on Minecraft Relay Server
	A component of Minecraft Relay Server.
	Requires: mod/basic.h, please manually include it in main source code.
	
	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Freedom Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PVER_M_UNIDENT 0
#define PVER_M_LEGACY1 1
#define PVER_M_LEGACY2 2
#define PVER_M_LEGACY3 3
struct p_login_legacy
{
	int proto_ver;
	unsigned char username[128],address[128];
	unsigned short port,version;
};
struct p_motd_legacy
{
	unsigned char address[128];
	unsigned short port,version;
};
struct p_login_legacy packet_read_legacy_login(unsigned char * sourcepacket, int sourcepacket_length, int login_version)
{
	struct p_login_legacy result;
	unsigned char source[BUFSIZ];
	unsigned char * ptr_source=source;
	int recidx,source_length;
	result.proto_ver=login_version;
	bzero(source,BUFSIZ);
	bzero(result.username,128);
	bzero(result.address,128);
	source_length=packetshrink(sourcepacket,sourcepacket_length,source);
	if(login_version==PVER_L_LEGACY2)
	{
		unsigned char login_field[512];
		unsigned char * ptr_login_field=login_field;
		bzero(login_field,512);
		for(recidx=0;recidx<source[1];recidx++)
		{
			login_field[recidx]=source[2+recidx];
		}
		ptr_login_field=strsplit(ptr_login_field,';',result.username);
		ptr_login_field=strsplit(ptr_login_field,':',result.address);
		result.port=atoi(ptr_login_field);
	}
	else
	{
		unsigned int username_length,address_length;
		if(login_version==PVER_L_LEGACY1)
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
		if(login_version==PVER_L_LEGACY4)
		{
			address_length=*ptr_source;
			ptr_source++;
			for(recidx=0;recidx<username_length;recidx++)
			{
				result.address[recidx]=*ptr_source;
				ptr_source++;
			}
			result.port=ptr_source[0]*256+ptr_source[1];
		}
	}
	return result;
}
int legacy_motd_protocol_identify(unsigned char * source)
{
	int proto_version=0;
	if(source[1]==0)
	{
		proto_version=PVER_M_LEGACY1;
	}
	else if(source[1]==1)
	{
		if(source[2]==0)
		{
			proto_version=PVER_M_LEGACY2;
		}
		else if(source[2]==0xFA)
		{
			proto_version=PVER_M_LEGACY3;
		}
	}
	return proto_version;
}
struct p_motd_legacy packet_read_legacy_motd(unsigned char * sourcepacket, int sourcepacket_length)
{
	struct p_motd_legacy result;
	unsigned char tmp[BUFSIZ],source[BUFSIZ];
	unsigned char * ptr_source=source;
	int recidx,tmp_length,source_length,address_length;
	bzero(result.address,128);
	bzero(tmp,BUFSIZ);
	bzero(source,BUFSIZ);
	tmp_length=sourcepacket[0x1C];
	for(recidx=0;recidx<tmp_length;recidx++)
	{
		tmp[recidx]=sourcepacket[0x1D+recidx];
	}
	source_length=packetshrink(tmp,tmp_length,source);
	result.version=*ptr_source;
	ptr_source++;
	address_length=*ptr_source;
	ptr_source++;
	for(recidx=0;recidx<address_length;recidx++)
	{
		result.address[recidx]=*ptr_source;
		ptr_source++;
	}
	result.port=ptr_source[0]*256+ptr_source[1];
	return result;
}
int make_message_legacy(unsigned char * source, unsigned int source_length, unsigned char * target)
{
	int size,recidx,string_length;
	unsigned char tmp[256];
	unsigned char * ptr_tmp=tmp;
	unsigned char * ptr_source=source;
	unsigned char * ptr_target=target;
	for(recidx=0;recidx<source_length;recidx++)
	{
		*ptr_tmp=0;
		ptr_tmp++;
		*ptr_tmp=*ptr_source;
		ptr_tmp++;
		ptr_source++;
	}
	string_length=ptr_tmp-tmp;
	ptr_tmp=tmp;
	ptr_target[0]=0xFF;
	ptr_target[1]=0;
	ptr_target[2]=ptr_source-source;
	ptr_target=ptr_target+3;
	for(recidx=0;recidx<string_length;recidx++)
	{
		*ptr_target=*ptr_tmp;
		ptr_target++;
		ptr_tmp++;
	}
	size=ptr_target-target;
	ptr_target=target;
	return size;
}
int make_kickreason_legacy(unsigned char * source, unsigned char * target)
{
	int size=make_message_legacy(source,strlen(source),target);
	return size;
}
int make_motd_legacy(unsigned int version, unsigned char * description, int motd_version, unsigned char * target)
{
	int size,input_length;
	unsigned char input[BUFSIZ];
	unsigned char version_str[8];
	bzero(input,BUFSIZ);
	bzero(version_str,8);
	switch(motd_version)
	{
		case PVER_M_LEGACY1:
			strcpy(input,description);
			input_length=datcat(input,strlen(input),"\xa7",1);
			input_length=datcat(input,input_length,"0",1);
			input_length=datcat(input,input_length,"\xa7",1);
			input_length=datcat(input,input_length,"0",1);
			break;
		case PVER_M_LEGACY2:
		case PVER_M_LEGACY3:
			sprintf(version_str,"%d",version);
			input[0]=0xA7;
			input_length=datcat(input,1,"1\0",2);
			input_length=datcat(input,input_length,version_str,strlen(version_str)+1);
			input_length=datcat(input,input_length,"",1);
			input_length=datcat(input,input_length,description,strlen(description)+1);
			input_length=datcat(input,input_length,"0\0",2);
			input_length=datcat(input,input_length,"0",1);
			break;
		default:
			break;
	}
	size=make_message_legacy(input,input_length,target);
	return size;
}
