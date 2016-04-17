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
	u_int8_t a;
	u_int8_t b;
	u_int8_t c;
	u_int8_t d;
};
typedef struct session{
#define PAYLOAD_MAX_LENGTH 2000
	u_char payload[PAYLOAD_MAX_LENGTH];
	u_int payload_length;
	u_int32_t ack_no;		/* the acknowledgement number */
	u_int32_t seq_no;		/* the sequence number */
	u_int32_t dstip;		/* the destination IP address */
	u_int32_t srcip;		/* the source IP address */
	struct session *next;
} session_t;
struct flow_tuple{
	u_int8_t proto;	/* the protocol number of transport layer protocol */
	u_int8_t flags;			/* the flags */
	u_int32_t dstip;		/* the destination IP address */
	u_int32_t srcip;		/* the source IP address */
	u_int16_t sport;		/* the source port number */
	u_int16_t dport;		/* the destination port number */
	u_int32_t ack_no;		/* the acknowledgement number */
	u_int32_t seq_no;		/* the sequence number */
	u_int32_t count;
	u_int32_t outC;			/* count of outgoing packets of the microflow */
	u_int32_t inC;			/* count of incoming packets of the microflow */
	session_t *session_list;
	struct flow_tuple *next,*prev;
};
typedef struct flow_tuple flow_tuple_t;

#endif /* project_includes/project.h */
