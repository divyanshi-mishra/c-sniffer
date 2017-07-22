#include <pcap.h>       
#include <stdio.h>      
#include <unistd.h> 
#include <string.h>

#include <arpa/inet.h> 

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

void got_packet( u_char *, const struct pcap_pkthdr *, const u_char * );
void write_ethernet( const struct ether_header * );
void write_ip( const struct ip * );
void write_tcp( const struct tcphdr * );

int main( int argc, char *argv[] )
{

	pcap_t *handle;


	char *dev = NULL;
	

	char *filter_exp = NULL;
	

	char errbuf[ PCAP_ERRBUF_SIZE ];


	struct bpf_program fp;
	
	bpf_u_int32 mask;
	
	bpf_u_int32 net;
	
	const u_char *packet;
	
	struct pcap_pkthdr header;
	
	int num_packets = 0;
    
	int i;
	
	opterr = 0;
	while( ( i = getopt( argc, argv, "hi:f:" ) ) != -1 )
	{
		switch( i )
		{
			case 'i':
			{
				dev = optarg;
				break;
			}
			case 'f':
			{
				filter_exp = optarg;
				break;
			}
			case '?':
			{
				printf("Opzione non riconosciuta: -%c\n", optopt );
				return 0;
			}
		}
	}

	if( !dev )
	{
		dev = pcap_lookupdev( errbuf );
		
		if( !dev )
		{
			printf("Non posso ottenere il device di default: %s\n", errbuf );
			return 2;
		}
	}
	if( pcap_lookupnet( dev, &net, &mask, errbuf ) == -1 )
	{
		fprintf( stderr, "Non posso ottenere la netmask di %s\n", dev);
		net = mask = 0;
	}
	
	handle = pcap_open_live( dev, BUFSIZ, 1, 1000, errbuf );
    
	if( !handle )
	{
		fprintf( stderr, "Non posso aprire l'interfaccia %s: %s\n", dev, errbuf );
		return 2;
	}
    
	if( filter_exp )
	{	
		if( pcap_compile( handle, &fp, filter_exp, 0, net ) == -1 ) 
		{
			fprintf(stderr, "Non posso compilare il filtro %s: %s\n", filter_exp, pcap_geterr( handle ) );
			return 2;
		}
        
		if( pcap_setfilter( handle, &fp ) == -1 ) 
		{
			fprintf(stderr, "Non posso impostare il filtro %s: %s\n", filter_exp, pcap_geterr( handle ) );
			return 2;
		}
	}
    
	u_char x = 'A';
	
	pcap_loop( handle, num_packets, got_packet, &x );
    
	pcap_freecode( &fp );
	
	pcap_close( handle );
	
	return 0;
}

void got_packet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet )
{
	/* Ethernet header */
	const struct ether_header *ethernet_header;
    
	/* IP header */
	const struct ip *ip_header;
    
	
    /* TCP header */
	const struct tcphdr *tcp_header;
	
	/* Payload */
	const char *payload;
	
	int size_payload, ip_hl_size;
	
	ethernet_header = ( struct ether_header * ) packet;
	
    write_ethernet( ethernet_header );

	ip_header = ( struct ip * )( packet + ETHER_HDR_LEN );
    
    write_ip( ip_header );
    
    
    
	switch( ip_header -> ip_p ) 
	{
		case IPPROTO_TCP:		/* protocollo TCP */
			break;
			
		case IPPROTO_UDP:
        {  
            printf("[UDP][/UDP]\n");
			return;
		}	
		case IPPROTO_ICMP:
        {
            printf("[ICMP][/ICMP]\n");   
			return;
		}	
		default:
        {
            printf("[PROTOCOLLO SCONOSCIUTO]\n");
            return;

        }
    }
    
	
    tcp_header = ( struct tcphdr * )( packet + ETHER_HDR_LEN + ( ( ip_header -> ip_hl * 32 ) / 8 ) );

    write_tcp( tcp_header );

	payload = ( u_char * )( packet + ETHER_HDR_LEN + ( ip_header -> ip_hl * 4 ) + ( tcp_header -> th_off * 4 ) );
    
	printf("\n[DATA]");
	printf("%s", payload );
    
	printf("[/DATA]\n\n");
    
	
}

void write_ethernet( const struct ether_header *ethernet_header )
{

	printf("[ETHERNET]");
	

	printf("[ether_dhost: %02x:%02x:%02x:%02x:%02x:%02x]",
           ( unsigned ) ethernet_header -> ether_dhost[0],
           ( unsigned ) ethernet_header -> ether_dhost[1],
           ( unsigned ) ethernet_header -> ether_dhost[2],
           ( unsigned ) ethernet_header -> ether_dhost[3],
           ( unsigned ) ethernet_header -> ether_dhost[4],
           ( unsigned ) ethernet_header -> ether_dhost[5]);
	

	printf("[ether_shost: %02x:%02x:%02x:%02x:%02x:%02x]",
           ( unsigned ) ethernet_header -> ether_shost[0],
           ( unsigned ) ethernet_header -> ether_shost[1],
           ( unsigned ) ethernet_header -> ether_shost[2],
           ( unsigned ) ethernet_header -> ether_shost[3],
           ( unsigned ) ethernet_header -> ether_shost[4],
           ( unsigned ) ethernet_header -> ether_shost[5]);

    printf("[ether_type: ");
    printf("%s", ( ethernet_header -> ether_type & ETHERTYPE_PUP      ) ? "PUP " : "" );
    printf("%s", ( ethernet_header -> ether_type & ETHERTYPE_IP       ) ? "IP  " : "" );
    printf("%s", ( ethernet_header -> ether_type & ETHERTYPE_ARP      ) ? "Addr. resolution protocol " : "" );
    printf("%s", ( ethernet_header -> ether_type & ETHERTYPE_REVARP   ) ? "reserve Addr. resolution protocol " : "" );
    printf("%s", ( ethernet_header -> ether_type & ETHERTYPE_VLAN     ) ? "IEE 802.1Q VLAN tagging " : "" );
    printf("%s", ( ethernet_header -> ether_type & ETHERTYPE_IPV6     ) ? "IPV6 " : "" );
    printf("%s", ( ethernet_header -> ether_type & ETHERTYPE_LOOPBACK ) ? "Test interface " : "" );
    printf("]");
    
	printf("[/ETHERNET]\n");
}

void write_ip( const struct ip *ip_header )
{
   
    if( ip_header -> ip_v == 6 )
    {
        printf("[PACCHETTO IPV6]\n");
        return;
    }
    
    printf("[IP]");
    
	if( BYTE_ORDER == LITTLE_ENDIAN )
	{
		printf("[Type: little endian]");
		printf("[ip_hl: %u]", ip_header -> ip_hl );
		printf("[ip_v: %u]", ip_header -> ip_v );
	}	
    
	else if( BYTE_ORDER == BIG_ENDIAN )
	{                
		printf("[Type: big endian]");	
		printf("[ip_v: %u]", ip_header -> ip_v );
		printf("[ip_hl: %u]", ip_header -> ip_hl );
	}
    
	printf("[ip_len: %u]", ip_header -> ip_len );
	printf("[ip_id: %u]", ip_header -> ip_id );
	printf("[ip_off: %u]", ip_header -> ip_off );
	
	/***********************************************************
     #define	IP_RF 0x8000			// reserved fragment flag 
     #define	IP_DF 0x4000			// dont fragment flag 
     #define	IP_MF 0x2000			// more fragments flag 
     #define	IP_OFFMASK 0x1fff		// mask for fragmenting bits 
     ************************************************************/
	
	printf("[ip_ttl: %u]", ip_header -> ip_ttl );
	printf("[ip_p: %u]", ip_header -> ip_p );
	
	printf("[ip_sum: %u]", ip_header -> ip_sum );
	
	printf("[ip_src: %s]", inet_ntoa( ip_header -> ip_src ) );
	printf("[ip_dst: %s]", inet_ntoa( ip_header -> ip_dst ) );
    
	printf("[/IP]\n");
}


void write_tcp( const struct tcphdr *tcp_header )
{
    printf("[TCP]");
    
	printf("[th_sport: %u]", ntohs( tcp_header -> th_sport ) );
	printf("[th_dport: %u]", ntohs( tcp_header -> th_dport ) );
    
    printf("[th_seq: %u]", tcp_header -> th_seq ); // sequence number
      printf("[th_ack: %u]", tcp_header -> th_ack ); 
	
    printf("[th_x2: %u]", tcp_header -> th_x2 ); // variabile deprecata sempre 0;
    
    printf("[th_off: %u]", tcp_header -> th_off ); // The segment offset specifies the length of the TCP header in 32bit/4byte blocks. Without tcp header options, the value is 5.
    
    // FLAGS
    /*
     This field consists of six binary flags. Using bsd headers, they can be combined like this: flags = FLAG1 | FLAG2 | FLAG3...
     
     TH_URG: Urgent. Segment will be routed faster, used for termination of a connection or to stop processes (using telnet protocol).
     TH_ACK: Acknowledgement. Used to acknowledge data and in the second and third stage of a TCP connection initiation (see IV.).
     TH_PUSH: Push. The systems IP stack will not buffer the segment and forward it to the application immediately (mostly used with telnet).
     TH_RST: Reset. Tells the peer that the connection has been terminated.
     TH_SYN: Synchronization. A segment with the SYN flag set indicates that client wants to initiate a new connection to the destination port.
     TH_FIN: Final. The connection should be closed, the peer is supposed to answer with one last segment with the FIN flag set as well. 
     */
    
    printf("[th_flags: ");
    printf("%s",  ( tcp_header -> th_flags & TH_URG  )  ? "URG " : "    " );
    printf("%s",  ( tcp_header -> th_flags & TH_ACK  )  ? "ACK " : "    " );
    printf("%s",  ( tcp_header -> th_flags & TH_PUSH )  ? "PUSH" : "    " );
    printf("%s",  ( tcp_header -> th_flags & TH_RST  )  ? "RST " : "    " );
    printf("%s",  ( tcp_header -> th_flags & TH_SYN  )  ? "SYN " : "    " );
    printf("%s]", ( tcp_header -> th_flags & TH_FIN  )  ? "FIN " : "    " );
    
    printf("[th_win: %u]", tcp_header -> th_win );
    printf("[th_sum: %u]", tcp_header -> th_sum );
    printf("[th_urp: %u]", tcp_header -> th_urp );

}
