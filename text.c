
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pcap.h>

//#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_STR_LEN 4096         /* maximum string length */
#define MAX_NUM_CONNECTION 1000

struct connection {

    char ip_src[MAX_STR_LEN];  /*source ip*/
    char ip_dst[MAX_STR_LEN];  /*destination ip*/
    uint16_t port_src;      /*source port number*/
    uint16_t port_dst;      /*destination port number*/
    int syn_count;          /*flag count*/
    int fin_count;
    int rst_count;
    double starting_time;
    double ending_time;
    double duration;
    int num_packet_src;     /*number of packets sent out by source*/
    int num_packet_dst;     /*number of packets sent out by destination*/
    int num_total_packets;
    int cur_data_len_src;   /*num data bytes*/
    int cur_data_len_dst;   /*num data bytes*/
    int cur_total_data_len;
    uint16_t max_win_size;  /*max window size*/
    uint16_t min_win_size;  /*min window size*/
    int windowsize;
    double sum_win_size;
    //struct round_trip rtt_ary_src[MAX_NUM_CONNECTION/4]; /*assume 1000*/
    int rtt_ary_src_len;    /*the size of the rtt_ary_src array*/
    //struct round_trip rtt_ary_dst[MAX_NUM_CONNECTION/4]; /*assume 1000*/
    int rtt_ary_dst_len;    /*the size of the rtt_ary_dst array*/
    int initialized;

};

struct packet {
    char src_ip[MAX_STR_LEN];  /*source ip*/
    char dst_ip[MAX_STR_LEN];  /*destination ip*/
    u_short src_port;
    u_short dst_port;
    unsigned int seq;
    unsigned int ack;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short th_urp;
    int data_bytes;
    double time;
    int used;
};

struct TCP_hdr {

    u_short th_sport;
    u_short th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    u_char th_offx2;
    #define TH_OFF(th)    (((th)->th_offx2 &0xf0) >> 4)
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;

};



struct packet items[10000];
struct connection connectedinformation[10000];
int packet_counter = 0;
int connection_num = 0;
double standard_time;
int resetcount;

//gcc -o text text.c -lpcap
//./text sample-capture-file

void check_connection(int total_packets){
int i;
int j;

for(i=0;i<total_packets;i++){
if(items[i].used==0){

for(j=0;j<total_packets;j++){
	if((items[i].src_port==items[j].src_port &&items[i].dst_port==items[j].dst_port
	&&!strcmp(items[i].dst_ip, items[j].dst_ip)&&!strcmp(items[i].src_ip, items[j].src_ip)
	&&items[j].used==0)||(items[i].dst_port==items[j].src_port
	&&items[i].src_port==items[j].dst_port &&!strcmp(items[i].src_ip,items[j].dst_ip)
	&& !strcmp(items[i].dst_ip,items[j].src_ip)&&items[j].used==0)){
	
		//add_info(r,j,k);
		//connection[k].inc++;
		items[j].used=1+connection_num;
}
}
connection_num++;
}
}
struct connection connectedinformation[connection_num+1];
int k;
int n;
int syn,fin;
int pactfromdst,pactfromsrc;
int countcomplete=0;
double mintime=0;
double maxtime=0;
double totaltimeduration=0;
int minpacket=0;
int totalpacket=0;
int maxpacket=0;
int minbyte=0;
int totalbyte=0;
int maxbyte=0;
for(k=0;k<=connection_num;k++){
	for(n=0;n<packet_counter;n++){
		if(items[n].used==k+1){
			if(items[n].flags==2){
				strcpy(connectedinformation[k].ip_dst, items[n].dst_ip);
				strcpy(connectedinformation[k].ip_src, items[n].src_ip);
				connectedinformation[k].port_src=items[n].src_port;
				connectedinformation[k].port_dst=items[n].dst_port;
				connectedinformation[k].starting_time=items[n].time-standard_time;
				}
			if(items[n].flags==2||items[n].flags==18){
				connectedinformation[k].syn_count++;
			}
			if(items[n].flags==17){
				//connectedinformation[k].ending_time=items[n].time-standard_time;
				connectedinformation[k].fin_count++;
			}
			
		
			if(!strcmp(connectedinformation[k].ip_dst, items[n].dst_ip)){
				if(!connectedinformation[k].min_win_size){
					connectedinformation[k].min_win_size=items[n].window;
				}if(connectedinformation[k].min_win_size>items[n].window){
					connectedinformation[k].min_win_size=items[n].window;
				}	
				if(items[n].window>connectedinformation[k].max_win_size){
					connectedinformation[k].max_win_size=items[n].window;
				}	
				connectedinformation[k].sum_win_size=connectedinformation[k].sum_win_size+items[n].window;
				connectedinformation[k]. num_packet_src++;
				connectedinformation[k]. cur_data_len_src+=items[n].data_bytes;
			}else{
				if(!connectedinformation[k].min_win_size){
					connectedinformation[k].min_win_size=items[n].window;
				}if(connectedinformation[k].min_win_size>items[n].window){
					connectedinformation[k].min_win_size=items[n].window;
				}	
				if(items[n].window>connectedinformation[k].max_win_size){
					connectedinformation[k].max_win_size=items[n].window;
				}	

				connectedinformation[k].sum_win_size=connectedinformation[k].sum_win_size+items[n].window;
				connectedinformation[k]. num_packet_dst++;
				connectedinformation[k]. cur_data_len_dst+=items[n].data_bytes;
			}	
			if(items[n].flags==20){
			connectedinformation[k].rst_count++;
			
			resetcount++;
			}
			connectedinformation[k].ending_time=items[n].time-standard_time;
		}
	}	
}	
	//printf("Start time111: %f\n", connectedinformation[0].ending_time-connectedinformation[0].starting_time);

//printf("Start time: %f\n", connectedinformation[45].starting_time);
//printf("Start time: %f\n", connectedinformation[2].starting_time);
	//printf("Standard time %f:\n",standard_time);
	printf("A) Total number of connections: %d\n", connection_num);
	printf("--------------------------------------------------------\n");
	printf("B) Connections' details:\n\n");
//printf("Source Address11: %s\n",connectedinformation[1].ip_src);
int g;

for(g=1;g<=connection_num;g++){
	printf("Connection%d:\n",g);
	printf("Source Address: %s\n",connectedinformation[g-1].ip_src);
	printf("Destination Port:  %s\n",connectedinformation[g-1].ip_dst);
	printf("Source Port:  %d\n",connectedinformation[g-1].port_src);
	printf("Destination Port: %d\n",connectedinformation[g-1].port_dst);
	//printf("Start Time: %d\n",connectedinformation[g-1].starting_time);
	printf("Status: S%dF%d\n",connectedinformation[g-1].syn_count,connectedinformation[g-1]. fin_count);
if((connectedinformation[g-1].syn_count==1&&connectedinformation[g-1]. fin_count==1)||(connectedinformation[g-1].syn_count==2&&connectedinformation[g-1]. fin_count==1)||(connectedinformation[g-1].syn_count==2&&connectedinformation[g-1]. fin_count==2)){
	countcomplete++;
	printf("Start time: %f\n", connectedinformation[g-1].starting_time);
	printf("Ending time: %f\n", connectedinformation[g-1].ending_time);
	connectedinformation[g-1].duration=connectedinformation[g-1].ending_time-connectedinformation[g-1].starting_time;
	printf("Duration: %f\n ",connectedinformation[g-1].duration);
	if(mintime==0){
	mintime=connectedinformation[g-1].duration;
	}
	if(connectedinformation[g-1].duration<mintime&&connectedinformation[g-1].duration!=0){
		mintime=connectedinformation[g-1].duration;
	}	
	if(connectedinformation[g-1].duration>maxtime){
	maxtime=connectedinformation[g-1].duration;
}
	totaltimeduration=totaltimeduration+connectedinformation[g-1].duration;
	printf("Number of Packet from Source: %d\n",connectedinformation[g-1]. num_packet_src);
	printf("Number of Packet from Destination:  %d\n",connectedinformation[g-1]. num_packet_dst);
	connectedinformation[g-1].num_total_packets=connectedinformation[g-1]. num_packet_src+connectedinformation[g-1]. num_packet_dst;
	printf("Total NUmber of Packets:  %d\n",connectedinformation[g-1].num_total_packets);
	if(minpacket==0){
	minpacket=connectedinformation[g-1].num_total_packets;
	}
	if(connectedinformation[g-1].num_total_packets<minpacket&&connectedinformation[g-1].num_total_packets!=0){
		minpacket=connectedinformation[g-1].num_total_packets;
	}	
	if(connectedinformation[g-1].num_total_packets>maxpacket){
	maxpacket=connectedinformation[g-1].num_total_packets;
	}
	
	totalpacket=totalpacket+connectedinformation[g-1].num_total_packets;
	
	printf("Number of data bytes sent from Source to Destination:  %d\n", connectedinformation[g-1]. cur_data_len_src);
	printf("Number of data bytes sent from Destination to Source:  %d\n", connectedinformation[g-1]. cur_data_len_dst);
	connectedinformation[g-1].cur_total_data_len=connectedinformation[g-1]. cur_data_len_src+connectedinformation[g-1]. cur_data_len_dst;
	printf("Total number of data bytes: %d\n", connectedinformation[g-1].cur_total_data_len);
	if(connectedinformation[g-1].min_win_size<minbyte){
		minbyte=connectedinformation[g-1].min_win_size;
	}	
	if(connectedinformation[g-1].max_win_size>maxbyte){
	maxbyte=connectedinformation[g-1].max_win_size;
}
	totalbyte=totalbyte+connectedinformation[g-1].sum_win_size;
	
}	

	printf("END\n+++++++++++++++++++++++++++++\n");

}	
	printf("C) General\n\n");
	//for(g=1;g<=connection_num;g++){
	//	printf("windowsize%d : %d\n ",g,connectedinformation[g-1].min_win_size);
	//}
	printf("Total number of complete TCP connections: %d\n", countcomplete);
	printf("Number of reset TCP connections:  %d\n", resetcount);
	printf("Number of TCP connections that were still open when the trace capture ended: %d\n", connection_num- countcomplete );
	printf("+++++++++++++++++++++++++++++\n\n");
	printf("D) Complete TCP connections: \n\n");
	printf("Minimum time durations: %f\n", mintime);
	printf("Mean time durations: %f\n",totaltimeduration/countcomplete);
	printf("Maximum time durations: %f\n\n", maxtime);
	printf("Minimum RTT values including both send/received: \n");
	printf("Mean RTT values including both send/received:     \n");
	printf("Maximum RTT values including both send/received:  \n\n");
	printf("Minimum number of packets including both send/received: %d\n", minpacket);
	printf("Mean number of packets including both send/received: %d\n",totalpacket/countcomplete);
	printf("Maximum number of packets including both send/received: %d\n\n",maxpacket);
	printf("Minimum receive window sizes including both send/received: %d\n", minbyte);
	printf("Mean receive window sizes including both send/received: %d\n",totalbyte/totalpacket);
	printf("Maximum receive window sizes including both send/received: %d\n",maxbyte);
	
}
int parse_packet(const unsigned char *packet, struct timeval ts, unsigned int caplen){
	struct ip *ip;
	struct TCP_hdr *tcp;
	unsigned int IP_header_length;
	int length = caplen;
	if (caplen < sizeof(struct ether_header))
		{
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		printf("Error:Ethernet header");
		return 0;
		}
	packet += sizeof(struct ether_header);
	caplen -= sizeof(struct ether_header);
	ip=(struct ip*) packet;/*hao NB*/
	IP_header_length=ip->ip_hl*4;
	if (caplen < IP_header_length)
		{ /* didn't capture the full IP header including options */
		printf( "IP header invalid");
		return;
		}
	if(ip->ip_p!=IPPROTO_TCP){
		printf("Error: Not tcp packet\n");
		return 0;
}
	packet += IP_header_length;
	caplen -= IP_header_length;
	//printf("testcaplen :%d\n",caplen);
	//printf("structure length :%d\n",sizeof(struct TCP_hdr));

	if (caplen < sizeof(struct TCP_hdr))
		{
		printf( "Invalid tcp header length\n");
		return 0;
		}
//printf("i am tcp!!\n");
tcp = (struct TCP_hdr*) packet;
int size_tcp = TH_OFF(tcp)+1;
size_tcp=size_tcp-1;
size_tcp=size_tcp*4;
int data = length-sizeof(struct ether_header)-IP_header_length - size_tcp;

//printf("%d\n,",data);
static char timestamp_string_buf[256];
sprintf(timestamp_string_buf,"%d.%06d", (int) ts.tv_sec,(int)ts.tv_usec);
double t=atof(timestamp_string_buf);
if(standard_time==0){
	standard_time=t;
}

char *addr = inet_ntoa(ip->ip_src);
//printf("ip address is: %s\n", addr);

 strcpy(items[packet_counter].src_ip, addr);
//printf("i am tcp!!4\n");
    int size = strlen(items[packet_counter].src_ip);
//printf("i am tcp!!3\n");
    items[packet_counter].src_ip[size] = '\0';
//printf("ip address is: %s\n", addr);
addr=inet_ntoa(ip->ip_dst);
 strcpy(items[packet_counter].dst_ip, addr);
	size=strlen(items[packet_counter].dst_ip);
	items[packet_counter].dst_ip[size] = '\0';
    items[packet_counter].src_port = ntohs(tcp->th_sport);
    items[packet_counter].dst_port = ntohs(tcp->th_dport);
//printf("i am tcp!!\n");
    items[packet_counter].seq = ntohl(tcp->th_seq);
    items[packet_counter].ack = ntohl(tcp->th_ack);
    items[packet_counter].flags = (unsigned int)tcp->th_flags;
    items[packet_counter].window = ntohs(tcp->th_win);
    items[packet_counter].used = 0;
    items[packet_counter].data_bytes = data;
	items[packet_counter].time = t;
	packet_counter++;
}
int main(int argc, char *argv[]){
	int count=0;
	pcap_t *pcap;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	pcap = pcap_open_offline(argv[1], errbuf);
	if (pcap == NULL)
		{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
		}
	//printf("%d\n",argc);
	if ( argc != 2 )
		{
		fprintf(stderr, "program requires one argument, the trace file\n");
		exit(1);
		}
	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
	while ((packet = pcap_next(pcap, &header)) != NULL){
		parse_packet(packet, header.ts, header.caplen);
}
	//printf("total: %d\n", packet_counter);
	check_connection(packet_counter);


	return 0;
	}

