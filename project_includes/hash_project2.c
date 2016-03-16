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
#define TABLESIZE 10007 
#define PRINTIP(ip) printf("%u.%u.%u.%u",\
			((ip&0xff000000)>>24),((ip&0x00ff0000)>>16),\
			((ip&0x0000ff00)>>8),(ip&0x000000ff))
/*
*	the hash function for the hash table
*/
u_int32_t hash(flow_tuple_t *node) 
{	
	return (((node->srcip^node->dstip)*59)^((node->sport^node->dport)<<16)^node->proto);
}
/*
*	create a table and intitialie its entries to NULL
*/

flow_tuple_t *flow_tuple_hash_table[TABLESIZE]={NULL};

/*flow_tuple_t*[TABLESIZE] create_table()
{
	return flow_tuple_hash_table;
}*/
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
				return -1;
			}
			else if(ptr->proto == node->proto &&
				ptr->sport == node->dport &&
				ptr->dport == node->sport &&
				ptr->srcip == node->dstip &&
				ptr->dstip == node->srcip){
				ptr->inC++;
				ptr->count++;
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
*	Function to insert a new node into the table
*/
void insertNode(flow_tuple_t *node, flow_tuple_t *table[])
{
	u_int32_t index;
	flow_tuple_t *ptr=NULL;
	// return if node already present
	if((index=isPresent(node,table))==-1){
		printf("Present\n");
		return;
	}
	// if its the first node in the bucket
	if(table[index]==NULL)
		table[index]=node;
	else{	// if its a collision then a doubly linked list is created
		ptr=table[index];
		while(ptr->next!=NULL)
			ptr=ptr->next;
		ptr->next=node;
		node->prev=ptr;
		node->next=NULL;
	}
}
/* 
*	Function to delete an existing node from the table
*/
void deleteNode(flow_tuple_t *node,flow_tuple_t *table[])
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
		printf("Index : %d\n",index);
		node = table[index];
		while(node!=NULL){
			printf("%3d IPS ",index);
			PRINTIP(node->srcip);
			printf(" PS %d IPD ",node->sport);
			PRINTIP(node->dstip);
			printf(" PD %d PR %s Count %u Out: %u In %u\n",node->dport,
			       (node->proto==TCPPROTO)?"TCP":"UDP",node->count,
			       node->outC,node->inC);
			++count;
			node=node->next;
		}
	}
	printf("\nNumber of indices used: %d\nNumber of microflows: %d\n",
						ic,count);
}
#endif /* project_includes/hash_project.h */
