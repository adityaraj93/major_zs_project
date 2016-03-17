#ifndef __PROJECT_INCLUDES_HASH_PROJECT
#define __PROJECT_INCLUDES_HASH_PROJECT 1

/*
	Set of functions to 
	1. create hash table 		:	create_table()
	2. insert node into hash table	:	insertNode(struct flow_tuple* node,
							struct flow_tuple **table)
	3. check if node is already	:	isPresent(struct flow_tuple *node,
	   present in the hash table 			struct flow_tuple **table)
	4. calculate the hash for the	:	hash(struct flow_tuple *node)
	   node
	5. print the complete hash table:	printTable(struct flow_tuple** table)
	6. delete a node from the table :	deleteNode(struct flow_tuple *node,
							struct flow_tuple **table)
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
u_int32_t hash(struct flow_tuple *node) 
{	


	return 	(node->srcip*59)
		^(node->dstip)
		^(node->sport<<16)
		^(node->dport)
		^(node->proto);
}
/*
*	create a table and intitialie its entries to NULL
*/
struct flow_tuple** create_table()
{
	int i;
	struct flow_tuple **table;
	// create a table of size TABLESIZE
	table=(struct flow_tuple**)malloc(sizeof(struct flow_tuple*)*TABLESIZE);
	for(i=0;i<TABLESIZE;i++)
		table[i]=NULL;	// initialize each pointer as NULL
	return table;
}
/* 
*	search for the node in the particular index of the table
*/
struct flow_tuple* searchNode(struct flow_tuple *node, u_int32_t index,
		struct flow_tuple **table)
{
	struct flow_tuple *ptr = table[index];
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
u_int32_t isPresent(struct flow_tuple *node,struct flow_tuple **table)
{
	u_int32_t hh=hash(node);
	u_int32_t index=hh%TABLESIZE;
FILE *fp1 = fopen("hash_test.txt","a");
	fprintf(fp1,"%u\n",hh);
	fclose(fp1);
	struct flow_tuple *ptr=NULL;
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
				return -1;
			}
			else
				ptr=ptr->next;
		}
	}
	return index;
}
/*
*	Function to insert a new node into the table
*/
void insertNode(struct flow_tuple *node, struct flow_tuple **table)
{
	u_int32_t index;
	struct flow_tuple *ptr=NULL;
	// return if node already present
	if((index=isPresent(node,table))==-1){
		printf("Present\n");
		return;
	}
	node->count=0;
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
void deleteNode(struct flow_tuple *node,struct flow_tuple **table)
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
void printTable(struct flow_tuple **table)
{
	struct flow_tuple *node;
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
			printf(" PD %d PR %s Count %u\n",node->dport,
			       (node->proto==TCPPROTO)?"TCP":"UDP",node->count);
			++count;
			node=node->next;
		}
	}
	printf("\nNumber of indices used: %d\nNumber of microflows: %d\n",
						ic,count);
}
#endif /* project_includes/hash_project.h */
