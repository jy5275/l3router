/***************************************************************************
 *            l3router.h
 *
 *  2018/11/15 14:01:23 星期四
 *  Copyright  2018  XuDongLai
 *  <XuDongLai0923@163.com>
 ****************************************************************************/
/*
 * l3router.h
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

#ifndef __L3ROUTER_H__
#define __L3ROUTER_H__
#include "../../include/fast.h"
#include <linux/if.h>
#include <netdb.h>
#include <ifaddrs.h>

#define FAST_ROUTE_PORT_CNT 4
#define FAST_NEIGH_MAX 8
#define FAST_ROUTE_FIB_CNT 16

#define NIPV6FMT "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X"
#define NIPV6ADDR(ip) ntohs(*((u16 *)&ip +0)),ntohs(*((u16 *)&ip +1)),ntohs(*((u16 *)&ip +2)),ntohs(*((u16 *)&ip +3)),ntohs(*((u16 *)&ip +4)),ntohs(*((u16 *)&ip +5)),ntohs(*((u16 *)&ip +6)),ntohs(*((u16 *)&ip +7))
#define NIPV4FMT "%u.%u.%u.%u"
#define NIPV4ADDR(ip) ((u8 *)&ip)[0],((u8 *)&ip)[1],((u8 *)&ip)[2],((u8 *)&ip)[3]
#define NMACFMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define NMACADDR(mac) ((u8 *)&mac)[0],((u8 *)&mac)[1],((u8 *)&mac)[2],((u8 *)&mac)[3],((u8 *)&mac)[4],((u8 *)&mac)[5]

#define xprintf(argc...) if(debug)printf(argc);

struct eth_header {
	u8 dmac[6];
	u8 smac[6];
	u16 frame;
	u8 data[0];
}__attribute__((packed));

struct arp {
	u16 ar_hrd;				/* format of hardware address	*/
	u16 ar_pro;				/* format of protocol address	*/
	u8	ar_hln;				/* length of hardware address	*/
	u8	ar_pln;				/* length of protocol address	*/
	u16 ar_op;				/* ARP opcode (command)		*/
	u8  ar_sha[ETH_ALEN];	/* sender hardware address	*/
	u32  ar_sip;			/* sender IP address		*/
	u8  ar_tha[ETH_ALEN];	/* target hardware address	*/
	u32  ar_tip;			/* target IP address		*/
}__attribute__((packed));

struct ip4_header {
	u8	ihl:4,
		version:4;
	u8	tos;
	u16	tot_len;
	u16	id;
	u16	frag_off;
	u8	ttl;
	u8	protocol;
	u16	check;
	u32	src;
	u32	dst;
	/*The options start here. */
}__attribute__((packed));


/*-----------------------------------------*/
struct neigh_table {	
	u8 mac[6];
	u8 pad[2];
	u32 ip4;
	u32 time;
	struct in6_addr ip6;
}__attribute__((packed));

struct port_stats {
	u64 recv_pkts;
	u64 recv_bytes;
	u64 send_pkts;
	u64 send_bytes;
}__attribute__((packed));/*32B*/

struct rt_buff  {
	/* These two members must be first. */
	struct rt_buff		*next;
	struct rt_buff		*prev;
	u32 gw;
	u32 arp_request_cnt;
	struct fast_packet pkt;
};

struct rt_buff_head {
	/* These two members must be first. */
	struct rt_buff	*next;
	struct rt_buff	*prev;
	u32		qlen;
	pthread_mutex_t	lock;
};

struct port_info {
	struct in6_addr ip6;	// IPv6地址, 目前支持一个地址
	struct neigh_table neigh[FAST_NEIGH_MAX + 1];	// 端口的邻接表
	/* 为每个邻接对象建一个队列, 存储需要发送给此邻居节点的所有报文
	 * (当该邻居节点不存在时, 可能有多个包要发给它, 则只请求几次ARP, 成功后,
	 * 可将此队的报文全部发送), 在构造ARP请求时, 在邻居表中占据一个位置
	 * 当这个位置的MAC回来后，可以通知此队列发送报文
	 */
	struct rt_buff_head list[FAST_NEIGH_MAX];
	struct port_stats stats;/*端口计数信息*/
	u8 mac[6];
	u16 portidx;	/*端口物理端口号*/
	u32 ip4;		/*接口IPv4地址，目前支持一个地址*/
	u32 bcast;		/*IP BroadCast*/
	u8 updown;		/*端口UP或DOWN状态*/
	u8 flag;		/*标志位，XXXX*/
	u8 state;		/*接口状态*/	
	u8 poll;		/*端口输出队列轮询标志*/
	pthread_mutex_t	neigh_lock;
	pthread_mutex_t	poll_lock;
};

struct fib4 {
	u8 if_name[16];
	u32 dest;			/*网络地址*/
	u32 gw;				/*网关, 下一跳*/
	u32 flags;
	u32 refcnt;
	u32 use;
	u32 metric;
	u32 mask;
	u32 mtu;
	u32 window;
	u32 irtt;
	s16 portidx;	/*输出端口号*/
	u16 mask_len;
};	/*根据内核路由表结构定义*/

struct fib6 {
	u8 if_name[16];
	struct in6_addr dest;		/*网络地址*/
	struct in6_addr mask;   /*掩码*/
	struct in6_addr nexthop;		/*网关*/
	s16 portidx;			/*输出端口号*/
	u16 mask_len;
	u32 pad;
};

struct fib_info {
	struct fib4 *f4;
	struct fib4 *f4_bak;
	struct fib6 *f6;
	struct fib6 *f6_bak;
	int use_flag;
};

void init_port(void);
void load_kernel_fib_info(void);
int fib_lookup(u32 dst);

struct rt_buff *rt_dequeue(struct rt_buff_head *list);
void rt_queue_tail(struct rt_buff_head *list, struct rt_buff *newbf);
void rt_queue_head_init(struct rt_buff_head *list);
extern int debug;
#endif //__L3ROUTER_H__