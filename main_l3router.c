/***************************************************************************
 *            main_l3route.c
 *
 *  2018/11/12 17:03:05 星期一
 *  Copyright  2018  XuDongLai
 *  <XuDongLai0923@163.com>
 ****************************************************************************/
/*
 * main_l3route.c
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

int debug = 1;
int poll = 1;
struct port_info ports[FAST_ROUTE_PORT_CNT];
struct fib6 f6[FAST_ROUTE_FIB_CNT+1];
struct fib_info fi;/*FIB表对象*/


void create_send_arp_request(u32 dip,int outport) {
	/*连续发送3个ARP请求*/
	struct fast_packet *pkt = (struct fast_packet*)malloc(sizeof(struct fast_packet));
	struct eth_header *eth = (struct eth_header*)pkt->data;
	struct arp *ar = (struct arp*)(eth+1);

	xprintf("send_arp_request " NIPV4FMT " on Port[%d]\n", NIPV4ADDR(dip), outport);
	memset(pkt, 0x00, sizeof(struct fast_packet));
	
	memset(eth->dmac, 0xFF, 6);
	memcpy(eth->smac, ports[outport].mac, 6);
	eth->frame = htons(0x0806);
	
	ar->ar_hrd = htons(0x0001);
	ar->ar_pro = htons(0x0800);
	ar->ar_hln = 6;
	ar->ar_pln = 4;
	ar->ar_op = htons(1);/*ARP请求*/
	memcpy(ar->ar_sha, eth->smac, 6);
	ar->ar_sip = ports[outport].ip4;
	//ar->ar_tha;/*整个报文已置0*/
	ar->ar_tip = dip;
	pkt->um.outport = outport;
	pkt->um.len = sizeof(struct eth_header) + sizeof(struct arp) + sizeof(struct um_metadata);
	pkt_send_normal(pkt, pkt->um.len);
	pkt_send_normal(pkt, pkt->um.len);
	pkt_send_normal(pkt, pkt->um.len);	/*连接发送3个，发送间隔其实有是要求的～*/
	free(pkt);
}



int pkt_send_normal(struct fast_packet *pkt, int pkt_len) {
	xprintf("pkt_send_normal->%p,outport:%d,len:%d\n", pkt, pkt->um.outport, pkt_len);
	pkt->um.pktsrc = 1;		/* 报文来源为CPU输入 */
	pkt->um.pktdst = 0;		/* 报文目的为硬件输出 */
	pkt->um.dstmid = 5;		/* 直接从硬件GOE模块输出, 不走解析、查表等模块 */
	pkt->cm.pkttype = 0;	/* 数据报文 */
	pkt->um.discard = 0;	/* 不丢弃 */
	return fast_ua_send(pkt, pkt_len);
}

void pkt_send_flood(struct fast_packet *pkt, int pkt_len) {
	int i = 0, inport = pkt->um.inport; /*保存输入端口*/
	xprintf("------pkt_send_flood------\n");
	for(; i < FAST_ROUTE_PORT_CNT; i++) {
	/*除输入端口外，其他都发送一份*/
		//TODO User add code
		if (i == pkt->um.inport) continue;
		pkt->um.outport = i;
		pkt_send_normal(pkt, pkt_len);
	}
}


void arp_do_response(struct fast_packet *pkt) {
	struct eth_header *eth = (struct eth_header*)pkt->data;
	struct arp *ar = (struct arp*)(eth + 1);

	xprintf("arp_do_response on Port[%d]\n", pkt->um.inport);
	/* 构造ARP应答, 源目IP交换, 源目MAC交换, 然后置上发送端MAC地址 */
	ar->ar_op = htons(2);	// ARP报文::operation
	exchange_value(eth->dmac, eth->smac, 6);
	exchange_value(ar->ar_tha, ar->ar_sha, 6);
	exchange_value((u8*)&ar->ar_tip, (u8*)&ar->ar_sip, 4);

	memcpy(ar->ar_sha, ports[pkt->um.inport].mac, 6);	// ARP报文::smac
	memcpy(eth->smac, ports[pkt->um.inport].mac, 6);	// 以太网帧::smac

	pkt->um.outport = pkt->um.inport;	// ARP回应报文从原端口返回
	pkt_send_normal(pkt, pkt->um.len);
}


void learn_smac(struct fast_packet *pkt) {
	struct eth_header *eth = (struct eth_header*)pkt->data;
	struct arp *ar = (struct arp*)(eth+1);
	int i = 0, j = -1;

	xprintf("Learn SMAC Port[%d]," NMACFMT "\n", pkt->um.inport, NMACADDR(eth->smac));

	//TODO User add code
	int idx = -1, macidx;
	// Find the neigh_table entry with ip4 equal to ar->sip (or a new entry)
	if ((macidx = find_mac_by_ip4(ar->ar_sip, pkt->um.inport, &idx)) == -1) {
		macidx = idx;
	}
	// Insert <ip, mac> entry into neighbor table of this inport
	ports[pkt->um.inport].neigh[macidx].time = 1;
	ports[pkt->um.inport].neigh[macidx].ip4 = ar->ar_sip;
	memcpy(ports[pkt->um.inport].neigh[macidx].mac, ar->ar_sha, 6);

	xprintf("Learn SMAC Port[%d],NEIGH[%d],Save["NMACFMT"]!\n",
		pkt->um.inport, j, NMACADDR(eth->smac));
}


int find_mac_by_ip4(u32 ip, int port, int *idx) {
	int i = 0;
	for (; i < FAST_NEIGH_MAX; i++) {
		if (ports[port].neigh[i].ip4 == ip) {
			// 在邻接表中找到了对应IP地址
			// TODO User add code
			return i;
		}
		if (ports[port].neigh[i].ip4 == 0 && *idx == -1)
			*idx = i;
	}
	return -1;
}


int pack_l2_send(struct fast_packet *pkt, int outport, int macidx) {
	struct eth_header *eth = (struct eth_header*)pkt->data;
	memcpy(eth->dmac, ports[outport].neigh[macidx].mac, 6);
	memcpy(eth->smac, ports[outport].mac, 6);
	pkt->um.outport = outport;
	xprintf("Pack L2 on Port[%d]\n", outport);
	return pkt_send_normal(pkt, pkt->um.len);
}


/* 处理队列报文线程, One thread for each outport 
 * 该部分不能直接替换二层数据转发是因为: nexthop的MAC地址在neigh表中不存在
 * 故需根据 IP_addr 去重新学习对应的 MAC 地址后才能封装新的二层数据转发
 */
void *handle_queue_packet(void *argv) {
	struct rt_buff *buf = NULL, *send_buf = NULL;	
	u32 gw = 0;
	int i=0, j=0, portidx=*((int*)argv), arpflag=0, sendflag=0;

	xprintf("handle_queue_packet on port[%d]\n", portidx);
	while (poll) {
		if (ports[portidx].poll == 1) {
			pthread_mutex_lock(&ports[portidx].poll_lock);
			ports[portidx].poll = 0;
			pthread_mutex_unlock(&ports[portidx].poll_lock);
		}
		arpflag = sendflag = 0;		// 重置标记为0，用于判断是否有报文需要发送
		for (i=0; i < FAST_NEIGH_MAX; i++) {
			if (ports[portidx].list[i].qlen == 0)	continue;
			buf = ports[portidx].list[i].next;
			if (buf) {
				if(buf->arp_request_cnt++ < 3) {
					arpflag = 1;
					gw = buf->gw;
					// 从 portidx 发出询问: gw 端口的 mac 地址是啥?
					create_send_arp_request(gw, portidx);
					usleep(100000);
				}
				else {
					while ((send_buf = rt_dequeue(&ports[portidx].list[i]))) {
						/*只当前IP有MAC，就取其队列中报文出来发送*/
						/*构造ICMP不可达信息返回主机端*/
						xprintf("ICMP Report and Drop!\n");
						free(send_buf);/*释放该报文*/
					}
				}
			}
			for (j=0; j<FAST_NEIGH_MAX; j++) {
				if(ports[portidx].neigh[j].time != 0 && ports[portidx].list[j].qlen > 0) {
					/* 说明该表项上的IP地址学习到了MAC地址 */
					/* 如果队列过大，此处是否可以做个限额发送？？？？ */
					while ((send_buf = rt_dequeue(&ports[portidx].list[j]))) {
						/* 只当前IP有MAC，就取其队列中报文出来发送 */
						sendflag = 1;
						/* 第J项邻接表学到MAC了，可以将挂在此队列的报文全部输出了 */
						pack_l2_send(&send_buf->pkt, portidx, j);
						/* 由于该报文是重新申请内容，拷贝报文内容后存入队列的，在发送完成后应该释放其内存 */
						free(send_buf);
					}
				}
			}
		}

		/* 如果此轮没有报文处理，说明所有转发报文均能正常查询得到MAC进行转发 */
		if (arpflag + sendflag == 0) {	
			xprintf("handle_queue_packet[%d]->Wait pkt INQUEUE...\n",portidx);
			while (ports[portidx].poll == 0)
				usleep(50000);	/* 静待该端口有入队操作，开启新的处理工作 */
			xprintf("handle_queue_packet[%d]->Start Process...\n",portidx);
		}
		else {
			sleep(3);
		}
	}
}



int handle_arp(struct fast_packet *pkt) {
	struct eth_header *eth = (struct eth_header*)pkt->data;
	struct arp *ar = (struct arp*)(eth + 1);
	if (ar->ar_tip == ports[pkt->um.inport].ip4) {	// ARP请求当前接口的IPv4地址
		xprintf("ARP->Host IPv4\n");
		if (is_multicast_ether_addr(eth->dmac)) {	// ARP Request
			xprintf("ARP->Request," NIPV4FMT "[" NMACFMT "]--> " NIPV4FMT "[???]\n",
				NIPV4ADDR(ar->ar_sip), NMACADDR(ar->ar_sha), 
				NIPV4ADDR(ar->ar_tip));
			arp_do_response(pkt);
			return 0;
		}
		else {	/* ARP Response */
			xprintf("ARP->Response," NIPV4FMT "[" NMACFMT "]--> " NIPV4FMT "[" NMACFMT "]\n",
				NIPV4ADDR(ar->ar_sip), NMACADDR(ar->ar_sha),
				NIPV4ADDR(ar->ar_tip), NMACADDR(ar->ar_tha));
			learn_smac(pkt);
			pkt->um.dstmid = 128;	/*送协议栈*/
			// 让协议栈学习邻接信息 (ICMP、控制协议等等依赖协议栈工作)
			return fast_ua_send(pkt, pkt->um.len);
		}
	}	// 请求其他IP不处理，路由的广播阻断功能
	xprintf("ARP->Other Host,Drop!\n");
	return 0;
}



int handle_control_plane_pkt(struct fast_packet *pkt) {
	pkt->um.dstmid = FAST_DMID_PROTO_STACK;		// 将报文目的送往协议栈
	xprintf("Control Plane->Send to Protocol Stack[%d]!\n",pkt->um.dstmid);	
	return fast_ua_send(pkt, pkt->um.len);
}



int output_dataplane_pkt(struct fast_packet *pkt, int tlbidx) {
	struct eth_header *eth = (struct eth_header*)pkt->data;
	struct ip4_header *ip4 = (struct ip4_header*)(eth+1);
	int outport = -1, macidx = -1, ipidx = -1, queue_tail = 0;

	u32 gw = 0;		// 根据命中FIB表信息提取网关(下一跳)IP地址
	get_out_gw(&outport, &gw, tlbidx);
	
	if (gw == 0)	// 网关 (下一跳) 为零，说明直接转发，网关即目的IP地址
		gw = ip4->dst;

	if (outport == -1) {
		// 查表不命中会返回默认路由, 若route文件本无默认路由, 可能导致输出端口为-1
		xprintf("ICMP Report and Drop!\n");
		return;
	}

	xprintf("Data Plane->Next Hop:" NIPV4FMT ",outport:%d\n",NIPV4ADDR(gw),outport);
	pthread_mutex_lock(&ports[outport].neigh_lock);		// 锁定输出端口表上的邻接表

	if ((macidx = find_mac_by_ip4(gw, outport, &ipidx)) > -1) {
		// 查到了目的MAC地址, 可以直接封装二层数据后进行转发
		pthread_mutex_unlock(&ports[outport].neigh_lock);	// 释放锁
		xprintf("Data Plane->port[%d],NEIGH[%d],DMAC->" NMACFMT "\n",outport,macidx,NMACADDR(ports[outport].neigh[macidx]));
		return pack_l2_send(pkt, outport, macidx);	// 封装二层数据发送
	}
	else if(ipidx != -1) {
		// Nexthop mac not found ==> ARP packet required, 现将其提交到请求处理队列
		// ipidx != -1 说明为此gw找到了邻接表中的一个空项, 用来学习该IP的MAC地址
		// 挂到队列后处理，不影响整个数据处理的后续流程
		struct rt_buff *buf = (struct rt_buff *)malloc(sizeof(struct rt_buff));

		xprintf("Data Plane->port[%d],NEIGH[%d],IN QUEUE[%d]\n",outport,ipidx,ipidx);
		ports[outport].neigh[ipidx].ip4 = gw;	// 在输出端口找到的位置里，把IP地址记录下来
		ports[outport].neigh[ipidx].time = 0;

		// 将此报文复制后进队列, 当前pkt是UA的回调函数中的内存, 此次回调结束后会重新用来接收新报文
		memcpy(&buf->pkt, pkt, pkt->um.len);
		
		buf->gw = gw;	// 保存该报文的网关地址, 在APR请求MAC时要用
		// 将报文挂到该输出端口, 并且是该端口邻接表中存储该网关地址对应的报文队列上
		rt_queue_tail(&ports[outport].list[ipidx],buf);
		queue_tail = 1;
	}	
	pthread_mutex_unlock(&ports[outport].neigh_lock);	// 释放锁

	if (ports[outport].poll == 0 && queue_tail == 1) {
		// 只要有入队就标记该端口poll (当然还有此标志已经为0, 说明线程停止处理数据了), 启动队列处理线程
		pthread_mutex_lock(&ports[outport].poll_lock);
		ports[outport].poll = 1;
		xprintf("Data Plane->Active Thread on Port[%d],QUEUE[%d] len:%d\n",outport,ipidx,ports[outport].list[ipidx].qlen);
		pthread_mutex_unlock(&ports[outport].poll_lock);
	}
	return 0;
}


int handle_dataplane_pkt(struct fast_packet *pkt) {
	struct eth_header *eth = (struct eth_header*)pkt->data;
	struct ip4_header *ip4 = (struct ip4_header*)(eth+1);
	u32 ip_dst = ip4->dst;				/* 取报文中的目的IP地址 */
	int tlbidx = fib_lookup(ip_dst);	/* 根据目的IP地址查FIB表，找到命中的表项索引 */

	xprintf("Data Plane->FIB(dst:" NIPV4FMT ") tblidx:%d\n", NIPV4ADDR(ip_dst), tlbidx);
	return output_dataplane_pkt(pkt, tlbidx);	/* 根据查表结果输出此报文 (数据平面报文) */
}


int dispatch_pkt(struct fast_packet *pkt) {
	struct eth_header *eth = (struct eth_header*)pkt->data;
	struct ip4_header *ip4 = (struct ip4_header*)(eth + 1);
	if(is_host_IPv4_addr(ip4->dst))
		return handle_control_plane_pkt(pkt);
	else
		return handle_dataplane_pkt(pkt);
}


int dispatch_multicast_pkt(struct fast_packet *pkt) {
	struct eth_header *eth = (struct eth_header *)pkt->data;
	struct ip4_header *ip4 = (struct ip4_header *)(eth+1);
	
	xprintf("Recv (" NIPV4FMT ") Multicast Packet!\n",NIPV4ADDR(ip4->dst));
	if(is_host_IPv4_addr(ip4->dst)||is_host_IPv4_BCast_addr(ip4->dst)||is_IPv4_Multicast_addr(ip4->dst)) {
		xprintf("Recv HOST Multicast Packet!\n");
		return handle_control_plane_pkt(pkt);
	}
	else
		return handle_dataplane_pkt(pkt);
}


int handle_ipv4(struct fast_packet *pkt) {
	if(is_host_ether_addr(pkt->data, pkt->um.inport)) {
		/* 目的MAC为本接口的MAC地址, 说明是主机报文 */
		// xprintf("Recv Unicast Host Packet,Dispatch Packet!\n");
		return dispatch_pkt(pkt);
	}
	else if(is_multicast_ether_addr(pkt->data)) {
		/* 路由器是否支持组播功能？ */
		//xprintf("Recv Multicast Packet!\n");
		return dispatch_multicast_pkt(pkt);
	}
	else { /* 其他主机MAC，说明是数据平面报文 */
		//xprintf("Recv Other host Packet,Drop!\n");		
	}
	return 0;
}


int callback(struct fast_packet *pkt, int pkt_len) {
	struct eth_header *eth = (struct eth_header *)pkt->data;

	xprintf("UA Recv ptk %p, len:%d, inport:%d\n", pkt, pkt->um.len, 
		pkt->um.inport);
	switch(ntohs(eth->frame)) {
		case 0x0806:	// ARP
			xprintf("Recv ARP Packet!\n");
			return handle_arp(pkt);	
		case 0x0800:	// IPv4
			//xprintf("Recv IPv4 Packet!\n");
			return handle_ipv4(pkt);
			break;
		case 0x86DD:	// IPv6
			//xprintf("Recv IPv6 Packet!\n");
			break;
		default:
			return 0;
			break;
	}
	return 0;
}


/**
* @brief 
*/
void ua_init(u8 mid) {
	int ret = 0;
	// 向系统注册, 自己进程处理报文模块ID为mid的所有报文
	if((ret = fast_ua_init(mid, callback))) {	
		// UA模块实例化 (输入参数1:接收模块ID号, 输入参数2:接收报文的回调处理函数)
		perror("fast_ua_init!\n");
		exit (ret);		//如果初始化失败
	}
}


void start_handle_queue_packet(int port) {
	pthread_t tid;
	int *idx = malloc(sizeof(int*));		
	
	*idx = port;
	if (pthread_create(&tid, NULL, handle_queue_packet, (void*)idx)) {
		xprintf("Create handle_queue_packet on Port[%d] thread error!\n",port);
	}
	else {
		xprintf("Create handle_queue_packet on Port[%d] thread OK!\n",port);
	}
}


void start_queue_thread(void) {
	int i = 0;	
	for(; i < FAST_ROUTE_PORT_CNT; i++)
		start_handle_queue_packet(i);
}


int main(int argc,char* argv[]) {
	init_port();	
	load_kernel_fib_info();	
	start_queue_thread();
	sleep(1);
	ua_init(FAST_UA_DFT_L3ROUTE);
	// 配置硬件规则, 将硬件所有报文送到模块ID为mid的进程处理
	fast_reg_wr(FAST_ACTION_REG_ADDR|FAST_DEFAULT_RULE_ADDR, 
		ACTION_SET_MID<<28|FAST_UA_DFT_L3ROUTE);	
	// 启动线程接收分派给UA进程的报文
	fast_ua_recv();
	while(1) { sleep(9999); }
	return 0;
}
