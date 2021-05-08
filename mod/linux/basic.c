/*
	basic.c: Basic Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.1.4
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
void gettime(unsigned char * target)
{
	time_t timestamp;
	time(&timestamp);
	struct tm * times_gmt=gmtime(&timestamp);
	int mdgmt=times_gmt->tm_mday;
	int mingmt=(times_gmt->tm_hour)*60+(times_gmt->tm_min);
	struct tm * times_local=localtime(&timestamp);
	int mdlocal=times_local->tm_mday;
	int minlocal;
	if(mdgmt!=mdlocal)
	{
		minlocal=((times_local->tm_hour)+24)*60+(times_local->tm_min);
	}
	else
	{
		minlocal=(times_local->tm_hour)*60+(times_local->tm_min);
	}
	int mindiff=minlocal-mingmt;
	int hourdiff=mindiff/60;
	mindiff=mindiff-hourdiff*60;
	if(mindiff<0)
	{
		mindiff=-mindiff;
	}
	if(times_local->tm_isdst==1)
	{
		hourdiff=hourdiff-1;
	}
	if(hourdiff<0)
	{
		sprintf(target,"%04d-%02d-%02d %02d:%02d:%02d UTC-%02d:%02d",times_local->tm_year+1900,times_local->tm_mon+1,times_local->tm_mday,times_local->tm_hour,times_local->tm_min,times_local->tm_sec,-hourdiff,mindiff);
	}
	else
	{
		sprintf(target,"%04d-%02d-%02d %02d:%02d:%02d UTC+%02d:%02d",times_local->tm_year+1900,times_local->tm_mon+1,times_local->tm_mday,times_local->tm_hour,times_local->tm_min,times_local->tm_sec,hourdiff,mindiff);
	}
}
long math_pow(int x,int y)
{
	int i;
	long result;
	result=1;
	for(i=1;i<=y;i++)
	{
		result=result*x;
	}
	return result;
}
unsigned short basic_atosu(unsigned char * source)
{
	unsigned int result_pre=0;
	unsigned short result=0;
	unsigned char * ptr_source=source;
	unsigned char charnow;
	while(*ptr_source!=0)
	{
		if((*ptr_source<0x30)||(*ptr_source>0x39))
		{
			return 0;
		}
		charnow=(*ptr_source)-0x30;
		result_pre=result_pre*10+charnow;
		ptr_source++;
	}
	result=result_pre;
	if(result!=result_pre)
	{
		return 0;
	}
	else
	{
		return result;
	}
}
unsigned char * varint2int(unsigned char * source, unsigned long * output)
{
	unsigned char * recent_ptr=source;
	unsigned char recent_char;
	unsigned long data=0;
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
unsigned char * int2varint(unsigned long data, unsigned char * output)
{
	unsigned char * ptr_output=output;
	unsigned char current_byte;
	unsigned long data_old,data_new;
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
int datcat(char * dst, int dst_size, char * src, int src_size)
{
	int recidx,total_size;
	for(recidx=0;recidx<src_size;recidx++)
	{
		dst[dst_size+recidx]=src[recidx];
	}
	total_size=dst_size+src_size;
	return total_size;
}
int handshake_protocol_identify(unsigned char * source, unsigned int length)
{
	int protocol_version=0;
	int semicolon_found=0;
	int colon_found=0;
	int i;
	switch(source[0])
	{
		case 1:
			protocol_version=PVER_L_ORIGPRO;
			break;
		case 2:
			switch(source[1])
			{
				case 0:
					for(i=0;i<length;i++)
					{
						if(source[i]==';')
						{
							semicolon_found=1;
						}
						if(source[i]==':')
						{
							colon_found=1;
						}
					}
					if((semicolon_found==1)&&(colon_found==1))
					{
						protocol_version=PVER_L_LEGACY2;
					}
					else
					{
						protocol_version=PVER_L_LEGACY1;
					}
					break;
				case 0x1f:
					protocol_version=PVER_L_LEGACY3;
					break;
				default:
					protocol_version=PVER_L_LEGACY4;
					break;
			}
			break;
		default:
			if((source[source[0]]==1)||(source[source[0]]==2))
			{
				switch(source[2])
				{
					case 0:
						protocol_version=PVER_L_MODERN1;
						break;
					default:
						protocol_version=PVER_L_MODERN2;
						break;
				}
			}
			else
			{
				protocol_version=PVER_L_UNIDENT;
			}
			break;
	}
	return protocol_version;
}
int packetshrink(unsigned char * source, int source_length, unsigned char * target)
{
	int size,recidx;
	unsigned char * ptr_target=target;
	for(recidx=0;recidx<source_length;recidx++)
	{
		if(source[recidx]!=0)
		{
			*ptr_target=source[recidx];
			ptr_target++;
		}
	}
	size=ptr_target-target;
	return size;
}
int packetexpand(unsigned char * source, int source_length, unsigned char * target)
{
	int size,recidx;
	unsigned char * ptr_target=target;
	for(recidx=0;recidx<source_length;recidx++)
	{
		*ptr_target=0;
		ptr_target++;
		*ptr_target=source[recidx];
		ptr_target++;
	}
	size=ptr_target-target;
	return size;
}
unsigned char * strsplit(unsigned char * string, char delim, unsigned char * firstfield)
{
	int recidx,pos_delim,delim_found;
	unsigned char * ptr_string=string;
	delim_found=0;
	for(recidx=0;recidx<strlen(string);recidx++)
	{
		if(*ptr_string==delim)
		{
			pos_delim=recidx;
			delim_found=1;
			ptr_string++;
			break;
		}
		ptr_string++;
	}
	if(delim_found==0)
	{
		strcpy(firstfield,string);
		return ptr_string;
	}
	for(recidx=0;recidx<pos_delim;recidx++)
	{
		firstfield[recidx]=string[recidx];
	}
	return ptr_string;
}
unsigned char * strsplit_reverse(unsigned char * string, char delim)
{
	int recidx;
	unsigned char * ptr_string=string+strlen(string)-1;
	for(;ptr_string>=string;ptr_string--)
	{
		if(*ptr_string==delim)
		{
			return (ptr_string+1);
		}
	}
	return string;
}
int strsplit_fieldcount(unsigned char * string, char delim)
{
	int recidx,count;
	unsigned char * ptr_string=string;
	count=1;
	for(recidx=0;recidx<strlen(string);recidx++)
	{
		if(*ptr_string==delim)
		{
			count++;
		}
		ptr_string++;
	}
	return count;
}
int mksysmsg(unsigned short noprefix, char * logfile, unsigned short runmode, unsigned short maxlevel, unsigned short msglevel, char * format, ...)
{
	char level_str[8];
	int status;
	va_list varlist;
	if(msglevel>maxlevel)
	{
		return 0;
	}
	bzero(level_str,8);
	switch(msglevel)
	{
		case 0:
			strcpy(level_str,"CRIT");
			break;
		case 1:
			strcpy(level_str,"WARN");
			break;
		default:
			strcpy(level_str,"INFO");
			break;
	}
	va_start(varlist,format);
	if(strcmp(logfile,"")!=0)
	{
		char time_str[32];
		bzero(time_str,32);
		gettime(time_str);
		FILE * logfd=fopen(logfile,"a");
		if(noprefix==0)
		{
			fprintf(logfd,"[%s] [%s] ",time_str,level_str);
		}
		char format_output[BUFSIZ];
		bzero(format_output,BUFSIZ);
		for(int recidx=0;recidx<strlen(format);recidx++)
		{
			format_output[recidx]=format[recidx];
			if(format[recidx]=='\n')
			{
				break;
			}
		}
		status=vfprintf(logfd,format_output,varlist);
		fclose(logfd);
	}
	va_end(varlist);
	va_start(varlist,format);
	if(runmode!=2)
	{
		if(msglevel==0)
		{
			if(noprefix==0)
			{
				fprintf(stderr,"[%s] ",level_str);
			}
			status=vfprintf(stderr,format,varlist);
		}
		else
		{
			if(noprefix==0)
			{
				fprintf(stdout,"[%s] ",level_str);
			}
			status=vfprintf(stdout,format,varlist);
		}
	}
	va_end(varlist);
	if(status<0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
int legacy_motd_protocol_identify(unsigned char * source)
{
	int proto_version=PVER_M_UNIDENT;
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
int ismcproto(unsigned char * data_in, unsigned int data_length)
{
	int result=0;
	if(data_in[0]==0xFE)
	{
		if(legacy_motd_protocol_identify(data_in)!=PVER_M_UNIDENT)
		{
			result=1;
		}
	}
	else
	{
		if(handshake_protocol_identify(data_in,data_length)!=PVER_L_UNIDENT)
		{
			result=1;
		}
	}
	return result;
}
