#ifndef __PROJECT_INCLUDES_PROJECT
#define __PROJECT_INCLUDES_PROJECT 1

#include<sys/types.h>

#define ICMPPROTO 0x01
#define IGMPPROTO 0x02
#define TCPPROTO 0x06
#define EGPPROTO 0x08
#define IGPPROTO 0x09
#define UDPPROTO 0x11
#define OSPFPROTO 0x59
#define MTPPROTO 0x5C

// Structure to store the IPv4 addresses, and print them in octets
struct ipaddr{
	unsigned int a:8;
	unsigned int b:8;
	unsigned int c:8;
	unsigned int d:8;
};

struct flow_tuple{
	unsigned int proto:8;	/* the protocol number of transport layer protocol */
	u_int8_t flags;			/* the flags */
	u_int32_t dstip;		/* the destination IP address */
	u_int32_t srcip;		/* the source IP address */
	u_int32_t sport:16;		/* the source port number */
	u_int32_t dport:16;		/* the destination port number */
	u_int32_t ack_no;		/* the acknowledgement number */
	u_int32_t seq_no;		/* the sequence number */
	u_int32_t count;
	u_int32_t outC;			/* count of outgoing packets of the microflow */
	u_int32_t inC;			/* count of incoming packets of the microflow */
	unsigned char payload[2000];
	struct flow_tuple *next,*prev;
};
typedef struct flow_tuple flow_tuple_t;

#endif /* project_includes/project.h */
