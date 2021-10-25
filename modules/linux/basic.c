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
size_t freadall(const char * filename, char ** dst)
{
	if((filename==NULL)||(dst==NULL))
	{
		errno=FREADALL_EINVAL;
		return 0;
	}
	FILE * srcfd=fopen(filename,"rb");
	if(srcfd==NULL)
	{
		errno=FREADALL_ERFAIL;
		return 0;
	}
	fseek(srcfd,0,SEEK_END);
	size_t filesize=ftell(srcfd);
	fseek(srcfd,0,SEEK_SET);
	if(filesize>FREADALL_SLIMIT)
	{
		fclose(srcfd);
		errno=FREADALL_ELARGE;
		return 0;
	}
	char * result=(char *)calloc(1,filesize+1);
	if(result==NULL)
	{
		fclose(srcfd);
		errno=FREADALL_ENOMEM;
		return 0;
	}
	fread(result,filesize,1,srcfd);
	fclose(srcfd);
	*dst=result;
	return filesize;
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
size_t strlen_notail(const char * src, char exemptchr)
{
	if(src==NULL)
	{
		return 0;
	}
	size_t result=strlen(src);
	while(result>0)
	{
		if(src[result-1]!=exemptchr)
		{
			break;
		}
		result--;
	}
	return result;
}
size_t strcmp_notail(const char * str1, const char * str2, char exemptchr)
{
	size_t str1_length=strlen(str1);
	size_t str2_length=strlen_notail(str2,exemptchr);
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
		return strncmp(str1,str2,str2_length);
	}
}
char * strtok_head(char * dst, char * src, char delim)
{
	if(src==NULL)
	{
		return NULL;
	}
	if(*src=='\0')
	{
		if(dst!=NULL)
		{
			*dst='\0';
		}
		return NULL;
	}
	char * ptr_delim=strchr(src,delim);
	if(ptr_delim==NULL)
	{
		if(dst!=NULL)
		{
			strcpy(dst,src);
		}
		return NULL;
	}
	size_t length=ptr_delim-src;
	if(dst!=NULL)
	{
		strncpy(dst,src,length);
		dst[length]='\0';
	}
	return ptr_delim+1;
}
size_t strtok_tail(char * dst, char * src, char delim, size_t length)
{
	if(src==NULL)
	{
		return 0;
	}
	if(length==0)
	{
		if(dst!=NULL)
		{
			*dst='\0';
		}
		return 0;
	}
	char * buffer=(char *)calloc(1,length+1);
	if(buffer==NULL)
	{
		return length;
	}
	strncpy(buffer,src,length);
	char * ptr_delim=strrchr(buffer,delim);
	if(ptr_delim==NULL)
	{
		if(dst!=NULL)
		{
			strcpy(dst,buffer);
		}
		free(buffer);
		return 0;
	}
	if(dst!=NULL)
	{
		strcpy(dst,ptr_delim+1);
	}
	free(buffer);
	return ptr_delim-buffer;
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
