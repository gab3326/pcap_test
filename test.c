#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		/* Ethernet header */
		struct sniff_ethernet {
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_short ether_type; /* IP? ARP? RARP? etc */		
		};

		/* IP header */
		struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst;/* source and dest address */
		};
		
		/* TCP header */
		typedef u_int tcp_seq;
		struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
		u_char th_flags;
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
		};

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */		
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip; /* The IP header */
	uint16_t size_ip;
	uint16_t size_tcp;
	const struct sniff_tcp *tcp;
	const char *data;
	uint16_t size_data;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

		int i=0;

		while(1){
		i = pcap_next_ex(handle, &header, &packet);

		ethernet = (struct sniff_ethernet*)(packet);
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		data = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

		size_ip = IP_HL(ip)*4;
		size_tcp = TH_OFF(tcp)*4;

		size_data = (ip->ip_len)*4 - ((IP_HL(ip)*4) + (TH_OFF(tcp)*4));
		
		char src_ip[1024];
		char dst_ip[1024];

		inet_ntop(2,&(ip->ip_src),src_ip,16);//INET_ADDRSTRLEN
		inet_ntop(2,&(ip->ip_dst),dst_ip,16);//16. Length of the string form for IP.

		
		
		//printf("*test1\n"); <-error test area
		
		//packet += 14;
		//printf("*test2\n");
		
		//printf("*test3\n");
		
		//printf("*test4\n");

		/* Hard coding area
		void tcp_port(const u_char *packet)
		{
		printf("\tTcp Source Port = %d \n", ((packet[34]*256) + packet[35]));
		printf("\tTcp Destination Port = %d \n", ((packet[36]*256) + packet[37]));
		}*/
		
		printf("\tEth.dmac : ");
		for(int d = 0; d<6; d++){
			printf("%02x",ethernet->ether_dhost[d]);
			printf(" : ");
			}
		printf("\n");
		
		printf("\tEth.smac : ");
		for(int s = 0; s<6; s++){
			printf("%02x",ethernet->ether_shost[s]);
			printf(" : ");
			}
		printf("\n");
		
		printf("\tSource ip : %s",src_ip);
		printf("\n");
		printf("\tDestination ip : %s",dst_ip);
		printf("\n");
		
		//tcp_port(packet); 		
		
		if((ip->ip_p)==0x6){
			printf("Tcp Source port : %d",ntohs(tcp->th_sport));
			printf("Tcp Destination port : %d",ntohs(tcp->th_dport));
		}

		printf("\tData_size : %d\n", size_data);
		printf("\tData : \n %s", data);
		printf("\n");
		printf("\n");
		}
		
		pcap_close(handle);
		return(0);
	 }
