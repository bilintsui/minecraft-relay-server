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
size_t strlen_head(const char * src, char tailchar)
{
	if(src==NULL)
	{
		return 0;
	}
	size_t result=0;
	for(;result<strlen(src);result++)
	{
		if(src[result]==tailchar)
		{
			break;
		}
	}
	return result;
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
		result--;
		if(src[i]==tailchar)
		{
			break;
		}
	}
	if(result==0)
	{
		return strlen(src);
	}
	return result;
}
size_t strcmp_notail(const char * str1, const char * str2, char tailchar)
{
	size_t str1_length=strlen(str1);
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
		return strncmp(str1,str2,str2_length);
	}
}
char * strtok_head(char * src, char delim, char * dst)
{
	size_t length_head=strlen_head(src,delim);
	if(length_head)
	{
		strncpy(dst,src,length_head);
	}
	dst[length_head]='\0';
	if(src[length_head]=='\0')
	{
		return NULL;
	}
	return src+length_head+1;
}
char * strtok_tail(char * src, char delim)
{
	return src+strlen_notail(src,delim)+1;
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
