/*
	log.c: Log Functions for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta3
	Copyright (c) 2020-2022 Bilin Tsui. All right reserved.
	This is a Free Software, absolutely no warranty.

	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "log.h"

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
int mksysmsg(unsigned short noprefix, char * logfile, unsigned short runmode, unsigned short maxlevel, unsigned short msglevel, char * format, ...)
{
	char level_str[8];
	int status;
	va_list varlist;
	if(msglevel>maxlevel)
	{
		return 0;
	}
	memset(level_str,0,8);
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
		memset(time_str,0,32);
		gettime(time_str);
		FILE * logfd=fopen(logfile,"a");
		if(logfd!=NULL)
		{
			if(noprefix==0)
			{
				fprintf(logfd,"[%s] [%s] ",time_str,level_str);
			}
			char format_output[BUFSIZ];
			memset(format_output,0,BUFSIZ);
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
