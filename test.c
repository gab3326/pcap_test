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
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)
		/* Ethernet header */
		struct sniff_ethernet {
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		
		u_short ether_type; /* IP? ARP? RARP? etc */
		};

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
		
		typedef u_int tcp_seq;
		struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
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
		u_int size_ip;
		u_int size_tcp;
		const struct sniff_tcp *tcp;
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
		/* Grab a packet */
		while(1){
		i = pcap_next_ex(handle, &header, &packet);
		printf("*1\n");
		ethernet = (struct sniff_ethernet*)(packet);
		//packet += 14;
		printf("*2\n");
		size_ip = IP_HL(ip)*4;
		ip = (struct sniff_addr*)(packet + SIZE_ETHERNET);
		
		size_tcp = TH_OFF(tcp)*4;
		printf("*3\n");
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			
		//if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		//return;
		//}
		printf("*4\n");

		//printf("%d",ntohs(tcp->th_sport));

		char src_ip[1024];
		char dst_ip[1024];
		strcpy(src_ip,inet_ntoa(ip->ip_src));
		strcpy(dst_ip,inet_ntoa(ip->ip_dst));

		printf("Source ip : %s",src_ip);
		printf("\n");
		printf("Destination ip : %s",dst_ip);
		printf("\n");

		/*
		printf("eth.dmac : ");
		for(int d = 0; d<6; d++){
			printf("%02x",ethernet->ether_dhost[d]);
			printf(" : ");
			}
		printf("\n");
		
		printf("eth.smac : ");
		for(int s = 0; s<6; s++){
			printf("%02x",ethernet->ether_shost[s]);
			printf(" : ");
			}
		printf("\n");
		
		*/
		}

		/* And close the session */
		pcap_close(handle);
		return(0);
	 }
