/*
	basic.c: Basic Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020-2021 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
unsigned char * base64_encode(unsigned char * source, size_t source_size)
{
	unsigned char charset[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t new_source_size,endfix,target_size;
	if(source_size%3==0)
	{
		new_source_size=source_size;
	}
	else
	{
		new_source_size=(source_size/3+1)*3;
	}
	endfix=new_source_size-source_size;
	target_size=new_source_size/3*4;
	unsigned char * new_source=(unsigned char *)malloc(new_source_size+1);
	if(new_source==NULL)
	{
		return NULL;
	}
	memset(new_source,0,new_source_size+1);
	memcpy(new_source,source,source_size);
	unsigned char * target=(unsigned char *)malloc(target_size+1);
	if(target==NULL)
	{
		free(new_source);
		new_source=NULL;
		return NULL;
	}
	memset(target,0,target_size+1);
	char chargroup_raw[3],chargroup_new[4];
	int offset_new_source=0;
	int offset_target=0;
	for(;offset_new_source<new_source_size;offset_new_source=offset_new_source+3)
	{
		target[offset_target]=charset[((new_source[offset_new_source]&0xFC)>>2)];
		target[offset_target+1]=charset[((new_source[offset_new_source]&0x03)<<4)+((new_source[offset_new_source+1]&0xF0)>>4)];
		target[offset_target+2]=charset[((new_source[offset_new_source+1]&0x0F)<<2)+((new_source[offset_new_source+2]&0xC0)>>6)];
		target[offset_target+3]=charset[(new_source[offset_new_source+2]&0x3F)];
		offset_target=offset_target+4;
	}
	free(new_source);
	new_source=NULL;
	if(endfix!=0)
	{
		memset(&(target[target_size-endfix]),'=',endfix);
	}
	return target;
}
void gettime(unsigned char * target)
{
	time_t timestamp=time(NULL);
	struct tm tm_local;
	localtime_r(&timestamp,&tm_local);
	int tzdiff=-timezone+tm_local.tm_isdst*3600;
	short tzdiff_hour=tzdiff/3600;
	short tzdiff_min=tzdiff/60-tzdiff_hour*60;
	sprintf(target,"%04d-%02d-%02d %02d:%02d:%02d UTC%+03d:%02d",tm_local.tm_year+1900,tm_local.tm_mon+1,tm_local.tm_mday,tm_local.tm_hour,tm_local.tm_min,tm_local.tm_sec,tzdiff_hour,tzdiff_min);
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
				case 0x1F:
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
void * int2varint(unsigned long src, void * dst)
{
	if(dst==NULL)
	{
		return NULL;
	}
	unsigned char * base=dst;
	int i=0;
	do
	{
		base[i]=(src&0x7F)|0x80;
		src=src>>7;
		i++;
	} while(src>0);
	base[i-1]=base[i-1]&0x7F;
	return dst+i;
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
size_t memcat(void * dst, size_t dst_size, void * src, size_t src_size)
{
	memcpy(dst+dst_size,src,src_size);
	return dst_size+src_size;
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
		if(logfd!=NULL)
		{
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
size_t freadall(unsigned char * filename, unsigned char ** dest)
{
	size_t once_size=8192;
	size_t max_size=5242880;
	unsigned char * result=NULL;
	if(filename==NULL)
	{
		errno=FREADALL_ENONAME;
		return 0;
	}
	FILE * srcfd=NULL;
	if(strcmp(filename,"-")==0)
	{
		srcfd=stdin;
	}
	else
	{
		srcfd=fopen(filename,"rb");
	}
	if(srcfd==NULL)
	{
		errno=FREADALL_ENOREAD;
		return 0;
	}
	size_t total_size=0;
	unsigned char * buffer=(unsigned char *)calloc(1,once_size);
	while(1)
	{
		size_t read_size=fread(buffer,1,once_size,srcfd);
		if(total_size==0)
		{
			result=(unsigned char *)calloc(1,read_size+1);
			if(result==NULL)
			{
				free(buffer);
				buffer=NULL;
				errno=FREADALL_ECALLOC;
				return 0;
			}
			result[read_size]=0;
		}
		if((total_size+read_size)>max_size)
		{
			free(buffer);
			buffer=NULL;
			free(result);
			result=NULL;
			errno=FREADALL_ELARGE;
			return 0;
		}
		unsigned char * result_pre=realloc(result,total_size+read_size+1);
		if(result_pre==NULL)
		{
			free(buffer);
			buffer=NULL;
			free(result);
			result=NULL;
			errno=FREADALL_EREALLOC;
			return 0;
		}
		result=result_pre;
		result[total_size+read_size]=0;
		memcat(result,total_size,buffer,read_size);
		total_size=total_size+read_size;
		if(read_size<once_size)
		{
			break;
		}
	}
	free(buffer);
	buffer=NULL;
	*dest=result;
	return total_size;
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
size_t strlen_notail(const char * src, char tailchar)
{
	if(src==NULL)
	{
		return 0;
	}
	size_t result=strlen(src);
	for(int i=result-1;i>=0;i--)
	{
		if(src[i]!=tailchar)
		{
			break;
		}
		result--;
	}
	return result;
}
size_t strcmp_notail(const char * str1, const char * str2, char tailchar)
{
	size_t str1_length=strlen_notail(str1,tailchar);
	size_t str2_length=strlen_notail(str2,tailchar);
	if(str1_length<str2_length)
	{
		return -1;
	}
	else if(str1_length>str2_length)
	{
		return 1;
	}
	else
	{
		return strncmp(str1,str2,str1_length);
	}
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
void * varint2int(void * src, unsigned long * dst)
{
	if((src==NULL)||(dst==NULL))
	{
		return src;
	}
	unsigned char * base=src;
	unsigned long dst_single=0;
	size_t index_lastunit=sizeof(*dst)*8/7;
	if(base[index_lastunit]&0x80)
	{
		return src;
	}
	*dst=0;
	for(int i=0;i<=index_lastunit;i++)
	{
		dst_single=base[i]&0x7F;
		*dst=*dst|(dst_single<<(i*7));
		if(!(base[i]&0x80))
		{
			return src+i+1;
			break;
		}
	}
}
