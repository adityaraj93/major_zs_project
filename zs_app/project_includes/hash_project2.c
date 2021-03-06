#ifndef __PROJECT_INCLUDES_HASH_PROJECT
#define __PROJECT_INCLUDES_HASH_PROJECT 1

/*
	Set of functions to 
	1. create hash table 		:	create_table()
	2. insert node into hash table	:	insertNode(flow_tuple_t * node,
							flow_tuple_t *table[])
	3. check if node is already	:	isPresent(flow_tuple_t *node,
	   present in the hash table 			flow_tuple *table[])
	4. calculate the hash for the	:	hash(flow_tuple_t *node)
	   node
	5. print the complete hash table:	printTable(flow_tuple_t *table[])
	6. delete a node from the table :	deleteNode(flow_tuple_t *node,
								flow_tuple_t *table[])
*/

//#include "project.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "regex_project.c"

#define TABLESIZE 10007 
#define PRINTIP(ip) printf("%3u.%3u.%3u.%3u",\
			((ip&0xff000000)>>24),((ip&0x00ff0000)>>16),\
			((ip&0x0000ff00)>>8),(ip&0x000000ff))
			
/* 
* Definition in the main file
*/ 
void
print_hex_ascii_line(const u_char *payload, int len, int offset);
void
print_payload(const u_char *payload, int len);
/*
*	the hash function for the hash table
*/
u_int32_t hash(flow_tuple_t *node) 
{	
	return (((node->srcip^node->dstip)*59)^
			((node->sport^node->dport)<<16)^
			node->proto);
}
/*
*	create a table and intitialie its entries to NULL
*/

flow_tuple_t *flow_tuple_hash_table[TABLESIZE]={NULL};
/* 
*	search for the node in the particular index of the table
*/
flow_tuple_t* searchNode(flow_tuple_t *node, u_int32_t index,
		flow_tuple_t *table[])
{
	flow_tuple_t *ptr = table[index];
	while(ptr!=NULL){
		if(ptr->proto==node->proto &&
		   ptr->dstip==node->dstip &&
		   ptr->srcip==node->srcip &&
		   ptr->sport==node->sport &&
		   ptr->dport==node->dport)
			break;
	}
	return ptr;
}
/*
*	Function to insert the session node into the singly linked list of 
*	flow to the hash table. This function is used only when the flow is 
*	already present in the hash table.
*/
void insert_session_node(flow_tuple_t *node, session_t *session)
{
	session->next=node->session_list;
	node->session_list=session;
}
/* 	
*	Checks if a node is present in the table or not
*	If present returns -1, else returns the hash index for the table
*/
u_int32_t isPresent(flow_tuple_t *node,flow_tuple_t *table[])
{
	u_int32_t index=hash(node)%TABLESIZE;
	flow_tuple_t *ptr=NULL;
	if(table[index]==NULL)
		return index;
	else{
		ptr = table[index];
		while(ptr!=NULL){
			if(ptr->proto == node->proto &&
				ptr->sport==node->sport &&
				ptr->dport==node->dport &&
				ptr->srcip==node->srcip &&
				ptr->dstip==node->dstip){
				ptr->count++;
				ptr->outC++;
				if (node->proto==TCPPROTO)
				{
					insert_session_node(ptr,node->session_list);
				}
				
				return -1;
			}
			else if(ptr->proto == node->proto &&
				ptr->sport == node->dport &&
				ptr->dport == node->sport &&
				ptr->srcip == node->dstip &&
				ptr->dstip == node->srcip){
				ptr->inC++;
				ptr->count++;
				if (node->proto==TCPPROTO)
				{
					insert_session_node(ptr,node->session_list);
				}
				return -1;
			}
			else{
				ptr=ptr->next;
			}
		}
	}
	return index;
}


/*
*	Function to insert a new node into the hash table
*/
void insertNode(flow_tuple_t *node, flow_tuple_t *table[])
{
	u_int32_t index;
	flow_tuple_t *ptr=NULL;
	// return if node already present
	if((index=isPresent(node,table))==-1){
		printf(" Present ");
		return;
	}
	// if its the first node in the bucket
	if(table[index]==NULL)
		table[index]=node;
	else{	// if its a collision then a doubly linked list is created
		ptr=table[index];
		// add the tuple at the start of the list 
		node->next=table[index];
		table[index]->prev=node;
		table[index]=node;
		node->prev=NULL;
	}
}
/* 
*	Function to delete an existing node from the table
*/
/*void deleteNode(flow_tuple_t *node,flow_tuple_t *table[])
{
	u_int32_t index = hash(node)%TABLESIZE;
	struct flow_tuple *ptr=NULL;
	if(table[index]==NULL)
		return;
	ptr = searchNode(node,index,table);
	if(ptr==NULL)
		return;
	if(ptr->prev!=NULL){
		ptr->prev->next = ptr->next;
		if(ptr->next!=NULL)
			ptr->next->prev = ptr->prev;
	}
	else{
		table[index] = ptr->next;
		if(ptr->next!=NULL)
			ptr->next->prev==NULL;
	}
}*/
void print_sessions(session_t *list);
/* 
*	Function to match the payload to the list of applications
*	and return the application name.
*/
void lookup_application(flow_tuple_t *node)
{
	session_t *ptr = node->session_list;
	node->matched=0;
	bzero(node->application,sizeof(node->application));
	while(ptr->next!=NULL)
	{	
		int ret = control_regex(ptr->payload);
		if(ret!=-1)
		{
			strcpy(node->application, signature_names[ret]);
			node->matched=1;
			break;
		}
		ptr=ptr->next;
	}
	if(!node->matched){
		strcpy(node->application,"Unknown");
	}
	printf("Application: %s\n",node->application);
/*	if(node->sport==21 && node->dport == 57823)
		print_sessions(node->session_list);
	else if (node->sport==57823 && node->dport==21)
		print_sessions(node->session_list); */

}
/*	
*	Funtion to print the session nodes of the flow 
*/
void print_sessions(session_t *list)
{
	while (list->next!=NULL)
	{
		printf("\n-------------------------------");
		printf("\nPayload length = %u\n",list->payload_length);
		printf("Ack No. %10u\n",list->ack_no);
		printf("Seq No. %10u\n",list->seq_no);
		PRINTIP(list->srcip);printf(">");PRINTIP(list->dstip);
		printf("\nApplication: \n");
		if (control_regex(list->payload))
		{
			print_payload(list->payload, list->payload_length);
		}
		printf("\n--------------------------------");
		list=list->next;
	}
}
/*
*	Function to print all the flows recorded in the table
*	along with the number of flows and the number of 
*	indices used.
*/	
void printTable(flow_tuple_t *table[])
{
	flow_tuple_t *node;
	u_int32_t index,count=0,ic=0;
	for(index=0;index<TABLESIZE;++index){
		if(table[index]==NULL)
			continue;
		++ic;
//		printf("\nIndex : %d\n",index);
		node = table[index];
		while(node!=NULL){
			printf("%3d: ",index);
			PRINTIP(node->srcip);
			printf(":%05d > ",node->sport);
			PRINTIP(node->dstip);
			printf(":%05d L4: %s Count %u ",node->dport,
			       (node->proto==TCPPROTO)?"TCP":"UDP",node->count);
			++count;
			if (node->proto==TCPPROTO)
			{
//				print_sessions(node->session_list);
				lookup_application(node);
			}
			else
				printf("\n");
			
			node=node->next;
		}
	}
	printf("\nNumber of indices used: %d\nNumber of microflows: %d\n",
						ic,count);
}
#endif /* project_includes/hash_project.h */
