/*
	basic.h: Basic Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.
	
	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Freedom Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
void gettime(unsigned char * target)
{
	time_t timestamp;
	time(&timestamp);
	struct tm * times_gmt=gmtime(&timestamp);
	int mingmt=(times_gmt->tm_hour)*60+(times_gmt->tm_min);
	struct tm * times_local=localtime(&timestamp);
	int minlocal=(times_local->tm_hour)*60+(times_local->tm_min);
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
		sprintf(target,"%04d-%02d-%02d %02d:%02d:%02d UTC-%02d:%02d",times_local->tm_year+1900,times_local->tm_mon,times_local->tm_mday,times_local->tm_hour,times_local->tm_min,times_local->tm_sec,-hourdiff,mindiff);
	}
	else
	{
		sprintf(target,"%04d-%02d-%02d %02d:%02d:%02d UTC+%02d:%02d",times_local->tm_year+1900,times_local->tm_mon,times_local->tm_mday,times_local->tm_hour,times_local->tm_min,times_local->tm_sec,hourdiff,mindiff);
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
char ** getaddresses(char * hostname)
{
	struct hostent * resolve_result;
	resolve_result = gethostbyname2(hostname,AF_INET);
	if(resolve_result == NULL)
	{
		return NULL;
	}
	return (resolve_result->h_addr_list);
}
struct sockaddr_in genSockConf(unsigned short family, unsigned long addr, unsigned short port)
{
	struct sockaddr_in result;
	result.sin_family=family;
	result.sin_addr.s_addr=htonl(addr);
	result.sin_port=htons(port);
	return result;
}
