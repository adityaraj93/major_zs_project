/*
 * nt_3_1.c
 * This file is part of Major Project
 *
 * Copyright (C) 2016 - Aditya Raj
 *
 * Major Project is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Major Project is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Major Project. If not, see <http://www.gnu.org/licenses/>.
 */
/*
*	Program to print the five tuples of flow - 
*	src IP, src port, dst IP, dst port, protocol(TCP or UDP)
*	and store them in a hash table
*	and display the hash table
*/

#include<pcap/pcap.h>
#include<sys/types.h>
#include<stdio.h>
#include<sys/types.h>
#include<string.h>
#include<netinet/if_ether.h>
#include<stdlib.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<signal.h>
#include"project_includes/project.h"
#include"project_includes/regex_project.c"
#include"project_includes/hash_project2.c"

#define MAX_PACKETS 1000
#define IP_S_TO_N(addd) (((addd->a)<<24)|\
			((addd->b)<<16)|\
			((addd->c)<<8)|\
			(addd->d))


flow_tuple_t list[MAX_PACKETS];
struct ipaddr *ip,*msk;
u_int32_t pcount=0;
u_int8_t myadd[ETH_ALEN] = {0xe0,0x69,0x95,0xd1,0xc7,0x17};
u_int8_t etha[ETH_ALEN];

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
	if (isprint(*ch))
            printf("%c", *ch);
	else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

/*
 *  print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{
    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;
		
	
    if (len <= 0)
        return;

	
    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

// function to copy the payload of the packet to the flow_tuple structure
void tcp_payload_copy(	const struct tcphdr *tcp_and_payload,// pointer to TCP 
															 // header
					  	flow_tuple_t *node, 		// pointer to the index in
					  								// the list where node is 
					  								// to be inserted
					  	u_int payload_length,		// length of the payload
					  	session_t *session)			// session_t structure in 
					  								// which payload is to be 
					  								// copied
{
	int i;
	const u_char *payload = (u_char*)(((u_char*)tcp_and_payload)+ 
										tcp_and_payload->th_off*4);
	session->payload_length = payload_length;
	session->ack_no=tcp_and_payload->th_ack;
	session->seq_no=tcp_and_payload->th_seq;
	if (payload_length<0)
	{
		return;
	}
	bzero(session->payload,PAYLOAD_MAX_LENGTH);
	for(i=0;i<payload_length;i++){
		session->payload[i]=*(payload+i);
	}
}


// function to print all the five tuples
void printIpAdd(struct ip *addr,int lenp)			
{
	struct ipaddr *src,*dst;
	unsigned int hdrlen, protocol;	
	struct tcphdr *tcph;
	struct udphdr *udph;
	src = (struct ipaddr*)&(addr->ip_src.s_addr);	// take the source address
	dst = (struct ipaddr*)&(addr->ip_dst.s_addr);	// take the destination address
	hdrlen = addr->ip_hl;
	protocol = addr->ip_p;
	printf("%3u.%3u.%3u.%3u > %3u.%3u.%3u.%3u |",
		src->a,src->b,src->c,src->d,dst->a,dst->b,dst->c,dst->d);
	// for TCP protocols
	if(protocol == TCPPROTO){ 			
		printf("   TCP    |");
		tcph = (struct tcphdr*)(((char*)addr) + 4*hdrlen) ;
		lenp-=4*hdrlen;
		printf(" %5u : %5u |",
			ntohs(tcph->source),ntohs(tcph->dest));
		if(tcph->syn){
			printf(" SYN ");
		}
		else{
			printf("  .  ");
		}
		if(tcph->fin){
			printf(" FIN ");
		}
		else{
			printf("  .  ");
		}
		if(tcph->ack){
			printf(" ACK |");
		}
		else{
			printf("  .  |");
		}
		list[pcount].proto = protocol;
		list[pcount].flags = tcph->th_flags;
		list[pcount].ack_no = tcph->th_ack;
		list[pcount].seq_no = tcph->th_seq;
		list[pcount].count = 1;
		list[pcount].next = NULL;
		list[pcount].prev = NULL;
		list[pcount].sport = ntohs(tcph->source);
		list[pcount].dport = ntohs(tcph->dest);
		list[pcount].srcip = IP_S_TO_N(src);
		list[pcount].dstip = IP_S_TO_N(dst);		
		
		session_t *session = (session_t*)malloc(sizeof(session_t));
		session->next=NULL;
		session->srcip = IP_S_TO_N(src);
		session->dstip = IP_S_TO_N(dst);		
		tcp_payload_copy( tcph,list+pcount, 
						  ntohs(addr->ip_len)-(addr->ip_hl*4 + tcph->th_off*4),
						  session  ); 
		list[pcount++].session_list = session;

		insertNode(&list[pcount-1],flow_tuple_hash_table);
	}
	else if(protocol == UDPPROTO){				// for UDP protocols
		printf("   UDP    |");
		udph = (struct udphdr*)(((char*)addr) + 4*hdrlen);
		printf(" %5u | %5u |",
			ntohs(udph->source),ntohs(udph->dest));
		printf("%15s|"," ");
		list[pcount].proto = protocol;
		list[pcount].next = NULL;
		list[pcount].prev = NULL;
		list[pcount].count = 1;
		list[pcount].sport = ntohs(udph->source);
		list[pcount].dport = ntohs(udph->dest);
		list[pcount].srcip = IP_S_TO_N(src);
		list[pcount++].dstip = IP_S_TO_N(dst);
		insertNode(&list[pcount-1],flow_tuple_hash_table);
	}
	else 	printf("   %3d    |",protocol);
	printf("\n");
}

// the callback function
void fp(u_char *arg1, const struct pcap_pkthdr* pkhdr, const u_char* packet) {
	int i=0,f1=1,f2=1,f3=1;
	struct ether_header *eth;
	static int count,ipc,arpc,ip6c,uc;
	struct ip *addr;
	++count;
	printf("%6d | %6d ",count,pkhdr->len);
	eth = (struct ether_header *) packet;
	switch(ntohs(eth->ether_type))
	{
		case ETHERTYPE_IP :  printf("| %04x IPv4 | %4d |",
						ntohs(eth->ether_type),++ipc);
					addr = (struct ip*) (packet+sizeof(struct ether_header));
					printIpAdd(addr,pkhdr->caplen-sizeof(struct ether_header));
					return;
					break;
		case ETHERTYPE_ARP : printf("| %04x  ARP | %4d |\n",
						ntohs(eth->ether_type),++arpc);
					return;
					break;
		case ETHERTYPE_IPV6: printf("| %04x IPv6 | %4d |",
						ntohs(eth->ether_type),++ip6c);
					break;
		default : 	     printf("| %04x UNKN | %4d |",
						ntohs(eth->ether_type),++uc);
					break;
	}
	printf("\n");	
}

pcap_if_t *alldevs,*d;
pcap_t *descr=NULL;

void breakl(int s){
	pcap_breakloop(descr);
}

void main(){
	char message[10],dev[20]={0};
	int i=0,j,interface_count=0;
	bpf_u_int32 pMask,pNet;
	struct bpf_program fpr;
	pcap_findalldevs(&alldevs,message);
	printf("-----------------------------------------------------------------------------------------------------------\n");
	printf("No. | Interface       |    Mask          | Net             |  Description  \n");
	printf("-----------------------------------------------------------------------------------------------------------\n");
	for(d=alldevs;d;d=d->next)
	{
		printf("%3d | %-15s | ",++i,d->name);
		pcap_lookupnet(d->name,&pNet,&pMask,message);
		ip = (struct ipaddr*)&pNet;
		msk = (struct ipaddr*)&pMask;
		printf(" %3u.%3u.%3u.%3u | %3u.%3u.%3u.%3u | ",
			msk->a,msk->b,msk->c,msk->d,ip->a,ip->b,ip->c,ip->d);
		if(d->description)
			printf(" %s \n",d->description);
		else
			printf(" No description\n");
		interface_count++;
	}
	printf("-----------------------------------------------------------------------------------------------------------\n");
	do{
		printf("Enter the interface number: ");
		scanf("%d",&i);
		if( i<1 || i>interface_count)
			printf("ERROR : Not a valid interface number.\n");
	}while(i<1 || i>interface_count);
	--i;
	j=0;
	d=alldevs;
	while(j<i)
		d=d->next,j++;
	printf("Selected interface: %s\n",d->name);	
	printf("-----------------------------------------------------------------------------------------------------------\n");
	strcpy(dev,d->name);
	printf("Promiscuous: 0-No 1-yes? ");
	scanf("%d",&i);
	printf("Output:- %s : Type ",dev);
	descr = pcap_open_live(dev,2048,i,512,message);
	if(pcap_datalink(descr)==DLT_EN10MB)// its a etherner (10MBps) packet
		printf("Ethernet \n");
	
	printf("-----------------------------------------------------------------------------------------------------------\n");

	printf("Starting Capture......\n\n");
		
	signal(SIGINT,breakl);
	signal(SIGTSTP,breakl);
	printf("------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	printf("|Packet| Header |   Type    | Cnt  |    Source IP   |  Destination    | Protocol | Source| Dest  | TCP Flags     | Is Flow \n");
	printf("|Number| Length |           |      |     address    |  IP  address    |          | Port  | Port  |               | Present? \n");
	printf("------------------------------------------------------------------------------------------------------------------------------------------------------\n");

	// not ssh, arp, and not broadcast
	pcap_compile(descr,&fpr,"not port 22 and not arp and not dst host 255.255.255.255",0,0); 
	pcap_setfilter(descr,&fpr);	// setting the filter
	pcap_loop(descr,MAX_PACKETS,fp,NULL);	// start capturing MAX_PACKETS packets and callback null
	pcap_freealldevs(alldevs);	// free all after cpaturing is done
	
/*	printf("\n\n***************************************************************************************************************************\n\n");
	for(i=0;i<pcount; i++)
	{	
		printf("%5d IPS %8x PS %5d IPD %8x PD %5d PROTO %2d",
			i,list[i].srcip,list[i].sport,list[i].dstip,
					list[i].dport,list[i].proto);
		if(list[i].proto!=UDPPROTO) 
			printf(" Seq : %10u, Ack : %10u",list[i].seq_no,list[i].ack_no);
		if(list[i].proto==TCPPROTO){
			if(list[i].flags&TH_SYN)
				printf(" SYN");
			if(list[i].flags&TH_FIN)
				printf(" FIN");
			if(list[i].flags&TH_ACK)
				printf(" ACK");
		}
		printf("\n");
	}

	printf("\n\n***************************************************************************************************************************\n\n");*/
	printTable(flow_tuple_hash_table);
}
