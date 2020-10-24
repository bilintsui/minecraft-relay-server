/*
	proto_modern.h: Functions for Legacy Protocol (12w04a-13w39b) on Minecraft Relay Server
	A component of Minecraft Relay Server.
	
	Minecraft Relay Server, version 1.2-beta2
	Copyright (c) 2020 Bilin Tsui. All right reserved.
	This is a Freedom Software, absolutely no warranty.
	Licensed with GNU General Public License Version 3 (GNU GPL v3).
	It basically means you have free rights for uncommerical use and modify, also restricted you to comply the license, whether part of original release or modified part by you.
	For detailed license text, watch: https://www.gnu.org/licenses/gpl-3.0.html
*/
int make_kickreason_legacy(unsigned char * source, unsigned char * target)
{
	int size,recidx,string_length;
	unsigned char tmp[256];
	unsigned char * ptr_tmp=tmp;
	unsigned char * ptr_source=source;
	unsigned char * ptr_target=target;
	while(*ptr_source!='\0')
	{
		*ptr_tmp=0;
		ptr_tmp++;
		*ptr_tmp=*ptr_source;
		ptr_tmp++;
		ptr_source++;
	}
	string_length=ptr_tmp-tmp;
	ptr_tmp=tmp;
	ptr_target[0]=255;
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
