/*
*	Program to print the five tuples of flow - 
*	src IP, src port, dst IP, dst port, protocol(TCP or UDP)
*	and store them in a hash table
*	and display the hash table
*/
#include"project_includes/project.h"
#include"project_includes/hash_project2.c"
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
	printf("Source IP: %3u.%3u.%3u.%3u Dest IP: %3u.%3u.%3u.%3u HLen: %u P: ",
		src->a,src->b,src->c,src->d,dst->a,dst->b,dst->c,dst->d,hdrlen);
	// for TCP protocols
	if(protocol == TCPPROTO){ 			
		printf("TCP");
		tcph = (struct tcphdr*)(((char*)addr) + 4*hdrlen) ;
		lenp-=4*hdrlen;
		printf(" SPort: %u DPort: %u",
			ntohs(tcph->source),ntohs(tcph->dest));
		if(tcph->syn)
			printf(" SYN");
		if(tcph->fin)
			printf(" FIN ");
		if(tcph->ack)
			printf(" ACK ");
		list[pcount].proto = protocol;
		list[pcount].flags = tcph->th_flags;
		list[pcount].ack_no = tcph->th_ack;
		list[pcount].seq_no = tcph->th_seq;
		list[pcount].count=1;
		list[pcount].next = NULL;
		list[pcount].prev = NULL;
		list[pcount].sport = ntohs(tcph->source);
		list[pcount].dport = ntohs(tcph->dest);
		list[pcount].srcip = IP_S_TO_N(src);
		bzero(list[pcount].payload,2000);
		strncpy(list[pcount].payload,
			(char*)(((char*)tcph)+ 4*tcph->th_off),lenp);

		list[pcount++].dstip = IP_S_TO_N(dst);

		insertNode(&list[pcount-1],flow_tuple_hash_table);
	}
	else if(protocol == UDPPROTO){				// for UDP protocols
		printf("UDP");
		udph = (struct udphdr*)(((char*)addr) + 4*hdrlen);
		printf(" SPort: %u DPort: %u\n",
			ntohs(udph->source),ntohs(udph->dest));
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
	else 	printf("%d",protocol);
	printf("\n");
}

// the callback function
void fp(u_char *arg1, const struct pcap_pkthdr* pkhdr, const u_char* packet) {
	int i=0,f1=1,f2=1,f3=1;
	struct ether_header *eth;
	static int count,ipc,arpc,ip6c,uc;
	struct ip *addr;
	++count;
	printf("%3d: %6d ",count,pkhdr->len);
	eth = (struct ether_header *) packet;
	switch(ntohs(eth->ether_type))
	{
		case ETHERTYPE_IP :  printf(": Ethernet type: %04x IPv4 %2d :",
						ntohs(eth->ether_type),++ipc);
					addr = (struct ip*) (packet+sizeof(struct ether_header));
					printIpAdd(addr,pkhdr->caplen-sizeof(struct ether_header));
					return;
					break;
		case ETHERTYPE_ARP : printf(": Ethernet type: %04x  ARP %2d :\n",
						ntohs(eth->ether_type),++arpc);
					return;
					break;
		case ETHERTYPE_IPV6: printf(": Ethernet type: %04x IPv6 %2d :",
						ntohs(eth->ether_type),++ip6c);
					break;
		default : 	     printf("  Ethernet type: %04x UNKN %2d :",
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
	int i=0,j;
	bpf_u_int32 pMask,pNet;
	struct bpf_program fpr;
	pcap_findalldevs(&alldevs,message);
	for(d=alldevs;d;d=d->next)
	{
		printf("%d - %-15s : ",++i,d->name);
		pcap_lookupnet(d->name,&pNet,&pMask,message);
		ip = (struct ipaddr*)&pNet;
		msk = (struct ipaddr*)&pMask;
		printf(" Mask %3u.%3u.%3u.%3u : Net %3u.%3u.%3u.%3u : ",
			msk->a,msk->b,msk->c,msk->d,ip->a,ip->b,ip->c,ip->d);
		if(d->description)
			printf(" %s \n",d->description);
		else
			printf("No description\n");
	}
	printf("Enter the interface number: ");
	scanf("%d",&i);
	--i;
	j=0;
	d=alldevs;
	while(j<i)
		d=d->next,j++;
	printf("Selected interface: %s\n",d->name);	
	strcpy(dev,d->name);
	printf("Promiscuous: 0-No 1-yes? ");
	scanf("%d",&i);
	printf("output:- %s : type ",dev);
	descr = pcap_open_live(dev,2048,i,512,message);
	if(pcap_datalink(descr)==DLT_EN10MB)// its a etherner (10MBps) packet
		printf("Ethernet \n");
	
		
	signal(SIGINT,breakl);
	signal(SIGTSTP,breakl);
	

	// not ssh, arp, and not broadcast
	pcap_compile(descr,&fpr,"not port 22 and not arp and not dst host 255.255.255.255",0,0); 
	pcap_setfilter(descr,&fpr);	// setting the filter
	pcap_loop(descr,MAX_PACKETS,fp,NULL);	// start capturing MAX_PACKETS packets and callback null
	pcap_freealldevs(alldevs);	// free all after cpaturing is done
	
	printf("\n\n***************************************************************************************************************************\n\n");
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

	printf("\n\n***************************************************************************************************************************\n\n");
	printTable(flow_tuple_hash_table);
}
