/*
	proto_legacy.c: Functions for Legacy Protocol (13w39b and before) on Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
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
	memset(input,0,BUFSIZ);
	memset(version_str,0,8);
	switch(motd_version)
	{
		case PVER_M_LEGACY1:
			strcpy(input,description);
			input_length=memcat(input,strlen(input),"\xa7",1);
			input_length=memcat(input,input_length,"0",1);
			input_length=memcat(input,input_length,"\xa7",1);
			input_length=memcat(input,input_length,"0",1);
			break;
		case PVER_M_LEGACY2:
		case PVER_M_LEGACY3:
			sprintf(version_str,"%d",version);
			input[0]=0xA7;
			input_length=memcat(input,1,"1\0",2);
			input_length=memcat(input,input_length,version_str,strlen(version_str)+1);
			input_length=memcat(input,input_length,"",1);
			input_length=memcat(input,input_length,description,strlen(description)+1);
			input_length=memcat(input,input_length,"0\0",2);
			input_length=memcat(input,input_length,"0",1);
			break;
		default:
			break;
	}
	size=make_message_legacy(input,input_length,target);
	return size;
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
	if(login_version==PVER_L_LEGACY2)
	{
		unsigned char login_field[512];
		unsigned char * ptr_login_field=login_field;
		memset(login_field,0,512);
		for(recidx=0;recidx<source[1];recidx++)
		{
			login_field[recidx]=source[2+recidx];
		}
		ptr_login_field=strtok_head(ptr_login_field,';',result.username);
		ptr_login_field=strtok_head(ptr_login_field,':',result.address);
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
p_motd_legacy packet_read_legacy_motd(unsigned char * sourcepacket, int sourcepacket_length)
{
	p_motd_legacy result;
	unsigned char tmp[BUFSIZ],source[BUFSIZ];
	unsigned char * ptr_source=source;
	int recidx,tmp_length,source_length,address_length;
	memset(result.address,0,128);
	memset(tmp,0,BUFSIZ);
	memset(source,0,BUFSIZ);
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
int packet_write_legacy_login(p_login_legacy source, unsigned char * target)
{
	unsigned char tmp[BUFSIZ];
	unsigned int tmp_length,size;
	memset(tmp,0,BUFSIZ);
	target[0]=2;
	size=1;
	if(source.proto_ver==PVER_L_LEGACY2)
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
		if(source.proto_ver!=PVER_L_LEGACY1)
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
		if(source.proto_ver==PVER_L_LEGACY4)
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
int packet_write_legacy_motd(p_motd_legacy source, unsigned char * target)
{
	unsigned int size,tmp_length,conststr_full_length;
	unsigned char tmp[BUFSIZ],conststr_full[128];
	unsigned char conststr[]="MC|PingHost";
	memset(tmp,0,BUFSIZ);
	memset(conststr_full,0,128);
	target[0]=0xFE;
	target[1]=1;
	target[2]=0xFA;
	size=3;
	conststr_full[0]=strlen(conststr);
	conststr_full_length=memcat(conststr_full,1,conststr,strlen(conststr));
	tmp_length=packetexpand(conststr_full,conststr_full_length,tmp);
	size=memcat(target,size,tmp,tmp_length);
	unsigned char pingfield[128],pingfield_full[128];
	unsigned int pingfield_length,pingfield_full_length;
	memset(pingfield,0,128);
	memset(pingfield_full,0,128);
	pingfield_length=packetexpand(source.address,strlen(source.address),pingfield);
	pingfield_full[0]=source.version;
	pingfield_full[1]=0;
	pingfield_full[2]=strlen(source.address);
	pingfield_full_length=3;
	pingfield_full_length=memcat(pingfield_full,pingfield_full_length,pingfield,pingfield_length);
	pingfield_full[pingfield_full_length]=0;
	pingfield_full[pingfield_full_length+1]=0;
	pingfield_full[pingfield_full_length+2]=source.port/256;
	pingfield_full[pingfield_full_length+3]=source.port-pingfield_full[pingfield_full_length+2]*256;
	pingfield_full_length=pingfield_full_length+4;
	target[size]=0;
	target[size+1]=pingfield_full_length;
	size=size+2;
	size=memcat(target,size,pingfield_full,pingfield_full_length);
	return size;
}
