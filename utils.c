/***************************************************************************
 *            utils.c
 *
 *  2018/11/15 15:24:10 星期四
 *  Copyright  2018  XuDongLai
 *  <XuDongLai0923@163.com>
 ****************************************************************************/
/*
 * utils.c
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

extern struct port_info ports[FAST_ROUTE_PORT_CNT];

/*--------------------------MAC地址操作-------------------------*/
int is_multicast_ether_addr(u8 addr[]) {
	return 0x01 & addr[0];
}

int is_host_ether_addr(u8 addr[], int port) {
	return !memcmp(addr, ports[port].mac, 6);
}

int ether_addr_equal(u8 addr1[],u8 addr2[]) {
	u16 *a = (u16*)addr1;
	u16 *b = (u16*)addr2;
	
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0; 
}

/*-----------------------------IP地址判断---------------------------*/
int is_host_IPv4_addr(u32 dstip) {
	int i = 0;
	for(; i<FAST_ROUTE_PORT_CNT; i++)
		if(ports[i].ip4 == dstip)
			return 1;
	return 0;
}

int is_host_IPv4_BCast_addr(u32 dstip) {
	int i = 0;
	for(;i<FAST_ROUTE_PORT_CNT;i++)
		if(ports[i].bcast == dstip)
			return 1;
	return 0;
}

int is_IPv4_Multicast_addr(u32 dstip) { 
	return (ntohl(dstip) > 0xE0000000) && (ntohl(dstip) < 0xEFFFFFFF);
}


/*--------------------------数据交换-----------------------------------*/
void exchange_value(u8 *src, u8 *dst, int len) {
	u8 t[len];
	memcpy(t, dst, len);
	memcpy(dst, src, len);
	memcpy(src, t, len);
}

/*-----------------------------------端口操作------------------------------*/

void get_dev_mac(char *if_name, int port) {
	int sock,i=0;
	struct ifreq ifr;

	if((sock = socket(AF_INET,SOCK_STREAM,0))<0) {
		xprintf("Read %s MAC ERROR!\n",if_name);
		exit(0);
	}

	strcpy(ifr.ifr_name,if_name);
	if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0) {
		xprintf("Read %s MAC ioctl ERROE!\n",if_name);
		exit(0);
	}
	memcpy(ports[port].mac,ifr.ifr_hwaddr.sa_data,6);	
	close(sock);
}

void get_dev_ip(char *if_name,int port) {
	struct ifaddrs *ifa, *p;	
	char ip4[16] = {0}, ip4_bcast[16] = {0};
	char ip6[128] = {0};
	int s = 0,i4 = 0,i6 = 0;
	
	if (getifaddrs(&ifa)) {
		xprintf("getifaddrs");
		exit(0);
	}

	for (p = ifa; p!=NULL; p=p->ifa_next) {
		if (p->ifa_addr == NULL)
    		continue;
		if(!i6 && p->ifa_addr->sa_family == AF_INET6 && !strncmp(if_name,p->ifa_name,strlen(if_name))) {
			s = getnameinfo(p->ifa_addr,sizeof(struct sockaddr_in6),
                           ip6, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
        		printf("getnameinfo6() failed: %s\n", gai_strerror(s));
        		exit(0);
            }	
			else {
				ports[port].ip6 = ((struct sockaddr_in6 *)(p->ifa_addr))->sin6_addr;
				//printf("IPv6:%s\n",ip6);
				i6 = 1;
			}
		}
		else if(!i4 && p->ifa_addr->sa_family == AF_INET && !strncmp(if_name,p->ifa_name,strlen(if_name))) {
			s = getnameinfo(p->ifa_addr,sizeof(struct sockaddr_in),
                          ip4, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
        		printf("getnameinfo4() failed: %s\n", gai_strerror(s));
        		exit(0);
            }
			else {
				ports[port].ip4 = (u32)inet_addr(ip4);
				//printf("IPv4:%s\n",ip4);
				i4 = 1;
			}

			s = getnameinfo(p->ifa_ifu.ifu_broadaddr,sizeof(struct sockaddr_in),
                          ip4_bcast, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
        		printf("getnameinfo4() failed: %s\n", gai_strerror(s));
        		exit(0);
            }
			else {
				ports[port].bcast = (u32)inet_addr(ip4_bcast);
				//printf("IPv4:%s\n",ip4);
				i4 = 1;
			}
		}
	}
}


void init_port(void) {
	int i = 0, j = 0;
	char if_name[16];

	memset(ports, 0x00, sizeof (struct port_info)*FAST_ROUTE_PORT_CNT);
	for(;i<FAST_ROUTE_PORT_CNT;i++) {
		sprintf(if_name, "obx%d", i);
		get_dev_mac(if_name, i);
		get_dev_ip(if_name, i);
		printf("Port[%d]->%s,MAC->" NMACFMT ",IPv4->" NIPV4FMT ",IPv6->" NIPV6FMT "\n",
		       i, if_name,
		       NMACADDR(ports[i].mac),
		       NIPV4ADDR(ports[i].ip4),
		       NIPV6ADDR(ports[i].ip6));
		for(j=0; j<FAST_NEIGH_MAX; j++)
			rt_queue_head_init(&ports[i].list[j]);
		pthread_mutex_init(&ports[i].neigh_lock, NULL);
		pthread_mutex_init(&ports[i].poll_lock, NULL);
	}	
}



/*------------------------------队列操作-----------------------------------------*/
static inline struct rt_buff *rt_peek(const struct rt_buff_head *list_)
{
	struct rt_buff *buf = list_->next;

	if (buf == (struct rt_buff *)list_)
		buf = NULL;
	return buf;
}

static inline void __rt_unlink(struct rt_buff *buf, struct rt_buff_head *list)
{
	struct rt_buff *next, *prev;

	list->qlen--;
	next	   = buf->next;
	prev	   = buf->prev;
	buf->next  = buf->prev = NULL;
	next->prev = prev;
	prev->next = next;
}

static inline struct rt_buff *__rt_dequeue(struct rt_buff_head *list)
{
	struct rt_buff *buf = rt_peek(list);
	if (buf)
		__rt_unlink(buf, list);
	return buf;
}

/*从队列头取出元素*/
struct rt_buff *rt_dequeue(struct rt_buff_head *list)
{
	unsigned long flags;
	struct rt_buff *result;
	
	pthread_mutex_lock(&list->lock);
	result = __rt_dequeue(list);	
	pthread_mutex_unlock(&list->lock);
	return result;
}

static inline void __rt_insert(struct rt_buff *newbf,
				struct rt_buff *prev, struct rt_buff *next,
				struct rt_buff_head *list)
{
	newbf->next = next;
	newbf->prev = prev;
	next->prev  = prev->next = newbf;
	list->qlen++;
}

static inline void __rt_queue_before(struct rt_buff_head *list,
				      struct rt_buff *next,
				      struct rt_buff *newbf)
{
	__rt_insert(newbf, next->prev, next, list);
}

static inline void __rt_queue_tail(struct rt_buff_head *list,
				   struct rt_buff *newbf)
{
	__rt_queue_before(list, (struct rt_buff *)list, newbf);
}

/*向队列尾添加元素*/
void rt_queue_tail(struct rt_buff_head *list, struct rt_buff *newbf)
{
	unsigned long flags;

	pthread_mutex_lock(&list->lock);
	__rt_queue_tail(list, newbf);
	pthread_mutex_unlock(&list->lock);
}

static inline void __rt_queue_head_init(struct rt_buff_head *list)
{
	list->prev = list->next = (struct rt_buff *)list;
	list->qlen = 0;
}
/*初始化列表对象*/
void rt_queue_head_init(struct rt_buff_head *list)
{	
	pthread_mutex_init(&list->lock,NULL);
	__rt_queue_head_init(list);
}
