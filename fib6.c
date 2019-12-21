/***************************************************************************
 *            fib6.c
 *
 *  2018/11/21 16:14:21 星期三
 *  Copyright  2018  XuDongLai
 *  <XuDongLai0923@163.com>
 ****************************************************************************/
/*
 * fib6.c
 *
 * Copyright (C) 2018 - XuDongLai
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include "l3router.h"

extern struct fib6 f6[FAST_ROUTE_FIB_CNT+1];

#define PATH6 "/proc/net/ipv6_route"

void show_kernel_fib6(void)
{
	int i = 0;
	printf("%-127s\n", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\tPort");
	for(;i<FAST_ROUTE_FIB_CNT + 1;i++)
	{
		if(f6[i].portidx > -1)
		{
			
		}
	}
}

void load_kernel_fib6(void)
{
	FILE *fp = NULL;
	char buf[256] = {0};
	u32 dest = 0;
	int i = 0;


	for(;i<FAST_ROUTE_FIB_CNT + 1;i++)
	{
		f6[i].portidx = -1;/*标记未使用*/	
	}
	i = 0;
	
	fp = fopen (PATH6, "r"); 
	if (NULL == fp) 
	{ 
		perror ("can't open file!\n");
		exit (0); 
	} 	
	/*无标题行*/
	while (!feof (fp))
	{ 
		fgets (buf, BUFSIZ, fp);
		
		if(!strncmp(f6[i].if_name,"obx",3))
		{
			if(0)/*说明读到了默认网关，保存在FIB表的最后一条，i的计数不加，重新获取新的表项*/
			{
				memcpy(&f6[FAST_ROUTE_FIB_CNT],&f6[i],sizeof(struct fib6));
				f6[FAST_ROUTE_FIB_CNT].portidx = (int)(f6[i].if_name[3] - 48);
				continue;
			}
			else
			{
				f6[i].portidx = (int)(f6[i].if_name[3] - 48);
				i++;
			}
		}	
		else
		{
			memset(&f6[i],0x00,sizeof(struct fib6));/*不属于FAST接口的数据不要，可能是最后一条，导致数据不对，故要清零*/
			f6[i].portidx = -1;/*将其使用端口置为无效*/
		}
	} 
	fclose (fp); 
}

void load_kernel_fib6_info(void)
{
	load_kernel_fib6();
	show_kernel_fib6();	
}


int fib6_lookup(u32 dst)
{
	int i = 0;
	for(;i<FAST_ROUTE_FIB_CNT;i++)
	{
		
	}
	return FAST_ROUTE_FIB_CNT;/*返回默认网关位置*/
}