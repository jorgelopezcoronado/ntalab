#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>	
#include <unistd.h>
#include "helpers.h"
#include "runmon.h"

#define DEBUG 1
/*
 * process_dns_name: auxiliary function to 
 */
u_char *process_dns_name(u_char *payload, u_char **pointer)
{
        u_char *data_ptr = *pointer;
        int i = 0, chars = (int)*data_ptr, jump = 0, length = 0;
	u_char *result = NULL;

	if(((chars & 0xC0) >> 6) == 3)//fist two bits are on, we have a jump
	{
		jump = ((*data_ptr & 0x3F) << 8) + *(data_ptr + 1);
		data_ptr = payload + jump;
		chars = (int)*data_ptr;
		*pointer = *pointer + 2;
	}
	
	//if we are at this point it means we need to process the string
		
        while(chars)
        {    
		length += chars + 1;
		result = (u_char*)realloc(result, length * sizeof(u_char));
                for(i = 0; i <= chars; i++) 
                      *(result + length - (chars + 1) + i) = *(data_ptr++); 
		if(!jump)
			*pointer = *pointer + chars + 1;
                chars = (int)*data_ptr;
		if(((chars & 0xC0) >> 6) == 3)//fist two bits are on, we have a jump
        	{
			jump = ((*data_ptr & 0x3F) << 8) + *(data_ptr + 1);
			data_ptr = payload + jump;
               		chars = (int)*data_ptr;
		}
		else if(!jump && !chars)
			*pointer = *pointer + 1;
        }	
	length++;
	result = (u_char*)realloc(result, length * sizeof(u_char));
	*(result + length -1) = 0;

	return result;
}

/*
 * process_vsnp: function to map a network packet to a vsnp_packet data structure
 */
vsnp_packet *process_vsnp(u_char *payload, int payload_size)//should be size_t payload_size, but... whatever...
{
	vsnp_packet *vsnp = (vsnp_packet*)malloc(sizeof(vsnp_packet));
	if(payload_size < sizeof(u_short))
	{
		free(vsnp);
		return NULL;
	}
	vsnp->ID=ntohs(*((u_short*)payload));
	vsnp->number = NULL;
	if(payload_size >= 2*sizeof(u_short)) //if there's something more... well... let it be lost
	{	
		vsnp->number = (u_short*)malloc(sizeof(u_short));
		*(vsnp->number) = ntohs(*((u_short*)(payload + sizeof(u_short)))); 
	}
	return vsnp;
}

/*
 * release a vsnp packet
 */
void release_vsnp(vsnp_packet *vsnp)
{
	if(!vsnp)
		return;
	if(vsnp->number)
		free(vsnp->number);
	free(vsnp);
}

/*
 * process_dns: function to map a packet to a dns_packet structure
 */
dns_packet *process_dns(u_char *payload, int payload_size)
{
	dns_packet *dns = (dns_packet*)malloc(1 * sizeof(dns_packet));
	dns->header = (dns_header_t*)payload;
	linked_list *queries = NULL, *answers = NULL, *auth_servers = NULL, *additional_records = NULL;
	dns_query_t *dns_query = NULL;
	dns_resource_record_t *dns_resource_record = NULL;
	u_char *ptr = payload + sizeof(dns_header_t);
	int i = 0;
	
	queries = create_linked_list();
	answers = create_linked_list();
	auth_servers = create_linked_list();
	additional_records = create_linked_list();

	for (i = 0; i < ntohs(dns->header->query_count); i++)
	{
		dns_query = (dns_query_t*)malloc(1 * sizeof(dns_query_t));
		dns_query->name = process_dns_name(payload, &ptr);		
		dns_query->type = *(u_short*)ptr;
		ptr = ptr + sizeof(u_short);
		dns_query->class = *(u_short*)ptr;
		ptr = ptr + sizeof(u_short);
		linked_list_add(queries, dns_query);
	}

	for (i = 0; i < ntohs(dns->header->answer_count); i++)
        {
		dns_resource_record = (dns_resource_record_t*)malloc(1 * sizeof(dns_resource_record_t));
		dns_resource_record->name = process_dns_name(payload, &ptr);		
		dns_resource_record->type = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
		dns_resource_record->class = *(u_short*)ptr;
		ptr = ptr + sizeof(u_short);
		dns_resource_record->TTL = *(u_int*)ptr;
		ptr = ptr + sizeof(u_int);
		dns_resource_record->data_length = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->data = (u_char*)ptr;
                ptr = ptr + htons(dns_resource_record->data_length);
		linked_list_add(answers, dns_resource_record);
	}	
		
	for (i = 0; i < ntohs(dns->header->auth_servers_count); i++)
        {
                dns_resource_record = (dns_resource_record_t*)malloc(1 * sizeof(dns_resource_record_t));
                dns_resource_record->name = process_dns_name(payload, &ptr);
                dns_resource_record->type = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->class = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->TTL = *(u_int*)ptr;
                ptr = ptr + sizeof(u_int);
                dns_resource_record->data_length = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->data = (u_char*)ptr;
                ptr = ptr + htons(dns_resource_record->data_length);
               	linked_list_add(auth_servers, dns_resource_record);
        }

	for (i = 0; i < ntohs(dns->header->additional_records_count); i++)
        {
                dns_resource_record = (dns_resource_record_t*)malloc(1 * sizeof(dns_resource_record_t));
                dns_resource_record->name = process_dns_name(payload, &ptr);
                dns_resource_record->type = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->class = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->TTL = *(u_int*)ptr;
                ptr = ptr + sizeof(u_int);
                dns_resource_record->data_length = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->data = (u_char*)ptr;
		ptr = ptr + htons(dns_resource_record->data_length);
                linked_list_add(additional_records, dns_resource_record);
        }
	dns->queries = queries;	
	dns->answers = answers;
	dns->auth_servers = auth_servers;
	dns->additional_records = additional_records;

	return dns;
}

/*
 * release_dns: frees all memory resources of a DNS packet
 */

void release_dns(dns_packet *dns)
{
	//free(dns->header); //why this matching way won't get released? pointer already gone? 
	int i = 0;
	dns_query_t *query = NULL;
	dns_resource_record_t *resource_record = NULL;
	while(dns->queries->head != NULL)
        {
		query = (dns_query_t*)linked_list_delete(dns->queries);
		free(query->name);
		free(query);
	}
	delete_linked_list(dns->queries);

	while(dns->answers->head != NULL)
        {
                resource_record = (dns_resource_record_t*)linked_list_delete(dns->answers);
                free(resource_record->name);
		//free(resource_record->data);
                free(resource_record);
        }
        delete_linked_list(dns->answers);

	while(dns->auth_servers->head != NULL)
        {
                resource_record = linked_list_delete(dns->auth_servers);
                free(resource_record->name);
		//free(resource_record->data);
                free(resource_record);
        }
        delete_linked_list(dns->auth_servers);

	while(dns->additional_records->head != NULL)
        {
                resource_record = (dns_resource_record_t*)linked_list_delete(dns->additional_records);
                free(resource_record->name);
		//free(resource_record->data);
                free(resource_record);
        }
        delete_linked_list(dns->additional_records);
	
	free(dns);
}

/*
 * print_std_dns_notation: auxiliary function to display data in standard DNS notation
 */
void print_std_dns_notation(u_char* data)
{
	u_char *data_ptr = data;
	int i = 0, chars = (int)*data_ptr;
	data_ptr++;
	while(chars)
	{
		for(i = 0; i < chars; i++)
			printf("%c",*(data_ptr + i));
		printf(".");
		data_ptr += chars;
		chars = (int)*data_ptr;
		data_ptr++;
	}
}

/*
 * print_dns: function to print a DNS record
 */
void print_dns(dns_packet *dns)
{
	linked_list_node *node = NULL;
        dns_query_t *dns_query = NULL;
        dns_resource_record_t *dns_resource_record = NULL;
	int i = 0;

	printf("ID: %i\n", ntohs(dns->header->id));	
	printf("Flags: %i, is response: %i\n", ntohs(dns->header->flags), DNS_QR(dns->header));
	printf("Query count: %i Answer count: %i Authoritative servers count: %i Additional records count: %i\n", ntohs(dns->header->query_count), ntohs(dns->header->answer_count), ntohs(dns->header->auth_servers_count), ntohs(dns->header->additional_records_count));
	node = dns->queries->head;
	printf("Queries:\n");
	while(node)
	{
		dns_query = (dns_query_t*)node->element;
		printf("\tName: ");
		print_std_dns_notation(dns_query->name);
		printf("\tType: %i Class: %i\n", ntohs(dns_query->type), ntohs(dns_query->class));
		node = node->next;
	}

	node = dns->answers->head;
	if(node)
		printf("Answers:\n");
	while(node)
        {    
                dns_resource_record = (dns_resource_record_t*)node->element;
                printf("\tName: ");
                print_std_dns_notation(dns_resource_record->name);
                printf("\tType: %i Class: %i TTL: %i Data Length: %i\n\tData:", ntohs(dns_resource_record->type), ntohs(dns_resource_record->class), ntohl(dns_resource_record->TTL), ntohs(dns_resource_record->data_length));
		for (i = 0; i < ntohs(dns_resource_record->data_length); i++)
			printf("%x",*(dns_resource_record->data + i));
		printf("\n");
                node = node->next;
        }

	node = dns->auth_servers->head;
	if(node)
		printf("Authoritative Servers:\n");
	while(node)
        {    
                dns_resource_record = (dns_resource_record_t*)node->element;
                printf("\tName: ");
                print_std_dns_notation(dns_resource_record->name);
                printf("\tType: %i Class: %i TTL: %i Data Length: %i\n\tData:", ntohs(dns_resource_record->type), ntohs(dns_resource_record->class), ntohl(dns_resource_record->TTL), ntohs(dns_resource_record->data_length));
		for (i = 0; i < ntohs(dns_resource_record->data_length); i++)
			printf("%x",*(dns_resource_record->data + i));
		printf("\n");
                node = node->next;
        }

	node = dns->additional_records->head;
	if(node)
		printf("Additional Records:\n");
	while(node)
        {    
                dns_resource_record = (dns_resource_record_t*)node->element;
                printf("\tName: ");
                print_std_dns_notation(dns_resource_record->name);
                printf("\tType: %i Class: %i TTL: %i Data Length: %i\n\tData:", ntohs(dns_resource_record->type), ntohs(dns_resource_record->class), ntohl(dns_resource_record->TTL), ntohs(dns_resource_record->data_length));
		for (i = 0; i < ntohs(dns_resource_record->data_length); i++)
			printf("%x",*(dns_resource_record->data + i));
		printf("\n");
                node = node->next;
        }
	printf("\n");

}



/*
 * release_packet: frees packet resources if no longer needed.
 */
void release_packet(runmon_packet* packet)
{
	free(packet->time);

        switch(packet->protocol_type)
        {   
                case DNS:
			if(packet->protocol_type)
                        	release_dns((dns_packet*)packet->protocol);
                        break;
                default:
                        //LOG THIS!
                break;
        }	
	
	free(packet);
}


/*
 * size_of_char_rep: function to calculate number size on string representation
 */
int size_of_char_rep(unsigned long long number)
{
	int size = 1;
	while ((number /= 10) > 0)
		size++;
	return size;
}

struct timeval *last_observed_time; //last observed time
pthread_mutex_t *last_observed_time_lock; //to guarantee thread safe of time reading and writing.
pthread_mutex_t *plist_lock;
linked_list *plist = NULL; 
int max_delay;
/*implement me*/

void check_properties(runmon_packet *pkt)
{
	//we will check the property that the transport should be not UDP (not a very smart check, not a good property, 2 delete)
	unsigned short sport, dport;

	dns_packet *dns = NULL, *strd_dns;
	linked_list_node *node = NULL;
	runmon_packet *strd_pkt = NULL;
	struct timeval result;
	char ip_dest[INET_ADDRSTRLEN];
	int i = 0;
	
	if(pkt->transport_type == UDP)//property no UDP packets allowed
	{
		udph *udp = (udph*)pkt->transport;
		sport = ntohs(udp->uh_sport);
        	dport = ntohs(udp->uh_dport);

		printf("Property violation! Packet %i is UDP!, source port:%i, destination port:%i \n", pkt->location_in_trace, sport, dport);
	}
	if(pkt->protocol_type == VSNP)
	{
		/*IMPLEMENT MEEEEEEEEEEEEEEEE*/	
	}
	//another property
	if(pkt->protocol_type == DNS)
	{
		dns = ((dns_packet*)pkt->protocol);
		if(DNS_QR(dns->header) == 0) //it is a query -> store
		{
			pthread_mutex_lock(plist_lock);
			pkt->reference_count++;
			linked_list_add(plist, pkt);
			pthread_mutex_unlock(plist_lock);
		}
		else //this is a DNS response
		{
			i = 0;
			pthread_mutex_lock(plist_lock);
			node = plist->head;
			while(node)
			{
				strd_pkt = (runmon_packet*)node->element;
				strd_dns = (dns_packet*)strd_pkt->protocol;
				if(dns->header->id == strd_dns->header->id)//response to a stored query
				{

					timeval_substract(&result, pkt->time, strd_pkt->time);
					
					if((result.tv_sec* 1000000+ result.tv_usec) > max_delay)//way too slow response for DNS query
					{
						inet_ntop(AF_INET, &pkt->ip->ip_src, ip_dest, INET_ADDRSTRLEN);
						printf("Property Violation! Slow DNS server IP=%s, query id=%i, response time bigger than Max=%i\n", ip_dest, dns->header->id, max_delay);
					}				
					if(--strd_pkt->reference_count == 0)
							release_packet(linked_list_delete_nth(plist,i));
					else
						linked_list_delete_nth(plist,i);
					break;

				}
				i++;
				node = node->next;
			}
			pthread_mutex_unlock(plist_lock);
		}
	}
}
 

/*
 * process_packet: function that processes each packet
 */

void process_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	static int count = 0;
	static struct timeval *offset;
	struct timeval *result, *time; 
	ethernet_h *ether = NULL;
	ip4 *ip = NULL;
	char ip_source[INET_ADDRSTRLEN], ip_dest[INET_ADDRSTRLEN];
	runmon_packet *message = (runmon_packet*)malloc(sizeof(runmon_packet));
	u_char *payload;
	tcph *tcp = NULL;
	udph *udp = NULL;
	dns_packet *dns = NULL;
	transport_e packet_transport;
	protocol_e packet_protocol;
	unsigned short sport, dport;

	if(count == 0)
	{
		offset = (struct timeval*)malloc(sizeof(struct timeval));
		offset->tv_sec = pkthdr->ts.tv_sec;
		offset->tv_usec = pkthdr->ts.tv_usec;
	}
	
	result = (struct timeval*)malloc(sizeof(struct timeval));
	time = (struct timeval*)&pkthdr->ts;
		
	timeval_substract(result,time,offset);

	pthread_mutex_lock(last_observed_time_lock);
	last_observed_time->tv_sec = result->tv_sec;
	last_observed_time->tv_usec = result->tv_usec;
	pthread_mutex_unlock(last_observed_time_lock);

	if (pkthdr->len < ETHERNET_HEADER_SIZE)
	{
		//LOG this!
		return;
	}

	ether = (ethernet_h*)pkt;
	if (ether->ether_type != ETHERNET_IPv4_TYPE)
	{
		//LOG this!
		return;
	}
	
	ip = (ip4*)(pkt + ETHERNET_HEADER_SIZE);
		
	//Leaving this here for future PO cathegorization... 
	inet_ntop(AF_INET, &ip->ip_src, ip_source, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, ip_dest, INET_ADDRSTRLEN);

	if (ip->ip_p == IP_PROTO_UDP)
	{
		udp = (udph*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + UDP_HEADER_SIZE); //* 4 because size expressed in 32bit  
		packet_transport = UDP;
	}	 
	else if (ip->ip_p == IP_PROTO_TCP)
	{
		tcp = (tcph*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + (TH_OFF(tcp) * 4)); //* 4 because size expressed in 32bit 
		packet_transport = TCP;
	}
	else
	{
		//LOG this!
		return;
	}

	//printf("%d) length=%d time=%d.%d. from:%s:%d to:%s:%d transport:%s \n", ++count, pkthdr->len, result->tv_sec, result->tv_usec, ip_source, ntohs((udp)?udp->uh_sport:tcp->th_sport), ip_dest, ntohs((udp)?udp->uh_dport:tcp->th_dport), (udp)?"UDP":"TCP"); //interested in all packets?
	//The previous line can be used for debug... it is priceless
	
	//WHERE TO SEND THIS? I mean choose depending on ports and so on.. let's do it based on ports for now
	sport = ntohs((udp)?udp->uh_sport:tcp->th_sport);
	dport = ntohs((udp)?udp->uh_dport:tcp->th_dport);
	if(sport == 53 || dport == 53)
	{
		packet_protocol = DNS;
		dns = process_dns(payload, pkthdr->len - (payload - pkt));	
	}
	else if(sport == 1010 || dport == 1010)
	{
		message->protocol = process_vsnp(payload, pkthdr->len - (payload - pkt));
		packet_protocol = (message->protocol)?VSNP:GENTCP;
	}	
	else if(packet_transport == TCP)
	{
		packet_protocol = GENTCP; //generic TCP
		//process not payload
	}
	else if(packet_transport == UDP)
	{
		packet_protocol = GENUDP;
		//process not payload
	}

	message->ethernet = ether;	
	message->ip = ip;
	message->time = result;
	message->transport_type = packet_transport;
	message->protocol_type = packet_protocol;
	message->location_in_trace = ++count;
	message->reference_count = 0;
		
	switch(packet_transport)
	{
		case UDP:	
			message->transport = udp;
			break;
		default:
			message->transport = tcp;
	}

	switch(packet_protocol)
	{
		case DNS:
			message->protocol = dns;
			break;
		default:
			//LOG THIS!
			break;
	}

	check_properties(message);
	
	if(message->reference_count == 0)
		release_packet(message);//we are done with this packet
}

/*
 * empty_old_messages: function that purges the message lists, the timeout variable is used to purge messages that are older than that time in usecs
 */
void empty_old_messages(unsigned long timeout_usec)
{
	linked_list_node *packet_node = NULL; 
	runmon_packet *packet = NULL;
	int i = 0, j = 0;
	unsigned long last_packet_time = 0;

        pthread_mutex_lock(last_observed_time_lock);
        last_packet_time = last_observed_time->tv_sec * 1000000 + last_observed_time->tv_usec;
        pthread_mutex_unlock(last_observed_time_lock);

	pthread_mutex_lock(plist_lock);

	packet_node = plist->head;	
	j = 0;
	while(packet_node)
	{
		packet = (runmon_packet*)packet_node->element;
		packet_node = packet_node->next;

		if(packet->time->tv_sec * 1000000 + packet->time->tv_usec + timeout_usec <= last_packet_time) // if timeout is 0 means delete all anyway
		{

	/*	if(!packet->completed_properties[get_property_of_variable(i)] && timeout_usec > 0) 
		{
			if(DEBUG)
				printf("--FAIL verdict--\n\tMessage(in trace): %i, incomplete in property %i.\n\n", packet->location_in_trace, i + 1);
                        	fail_verdicts[get_property_of_variable(i)]++;
			current_status[get_property_of_variable(i)] = CURRENT_STATUS_FAIL;
		}*/
			//report inconclusive??
			release_packet(packet);
			linked_list_delete_nth(plist, j);
			j--; //still transversing the ll, so, we need to set the new pointer location back since last packet was deleted
		}

		j++;
	}
	pthread_mutex_unlock(plist_lock);

}

/*
 * fail_timeout_func function for the fail timeout thread, takes as the parameter the time 
 */

char still_running; // if capture did not finish

void *fail_timeout_func(void *param)
{
	unsigned long timeout = *((unsigned long*)param);
	while(TRUE)
	{
		usleep(timeout);
		if(still_running)
			empty_old_messages(timeout);	
		else
			break;
	}
	return NULL;
}



#define FAIL_TIMEOUT_TIME 8*1000000

int main(int argc, char *argv[])
{
	char *devname = argv[1];
	char *errbuff = (char *) malloc(PCAP_ERRBUF_SIZE); 
	struct pcap_pkthdr *header;
	struct bpf_program fp;
	const u_char *payload;
	pthread_mutex_t *lock;
	pthread_t timeout_checker_thread;
	unsigned long fail_timeout_time = FAIL_TIMEOUT_TIME;

	if(argc != 4)
	{
		printf("Error in program call, should be %s <device> <filter> <timeout>\nE.g. %s eth0 \"\" 10 captures all traffic on eth0, sets a default timeout of 10us\n", argv[0], argv[0]);
		exit(1);
	}

	pcap_t *handler;
	
	if (!(handler = pcap_open_offline(devname,errbuff)))
		 handler = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuff);

	if (handler == NULL)
	{
		printf("Error while opening %s is not a valid filename or device, error: \n\t%s\n", devname, errbuff);
		exit(2);
	}

	if (pcap_compile(handler, &fp, argv[2], 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		printf("Couldn't parse filter \"%s\": %s\n", argv[2], pcap_geterr(handler));
		exit(2);
	}
 	if (pcap_setfilter(handler, &fp) == -1) 
	{
		printf("Couldn't install filter %s: %s\n", argv[2], pcap_geterr(handler));
		exit(2);
	}

	plist = create_linked_list();
	plist_lock = (pthread_mutex_t*)malloc(1 * sizeof(pthread_mutex_t));
	pthread_mutex_init(plist_lock, NULL);
	max_delay = atoi(argv[3]);

	last_observed_time = (struct timeval*)malloc(1 * sizeof(struct timeval));
	last_observed_time->tv_sec = 0;
	last_observed_time->tv_usec = 0;
	last_observed_time_lock = (pthread_mutex_t*)malloc(1 * sizeof(pthread_mutex_t));
	pthread_mutex_init(last_observed_time_lock, NULL);

	still_running = 1;

	pthread_create(&timeout_checker_thread, NULL, &fail_timeout_func, &fail_timeout_time);
	pthread_detach(timeout_checker_thread);

	if (pcap_loop(handler, -1, &process_packet, NULL) == -1)
		printf("Error occurred in capture!\n%s", pcap_geterr(handler));
	still_running = 0;

	empty_old_messages(0);

	return 0;
}
