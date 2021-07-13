
#include <pcap.h>
#include <errno.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h> //contain the ethernet header
#include <netinet/ip.h>	//contain the ip header
#include <netinet/tcp.h> // contain the tcp header


void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
  // get the ip part in the packet
  struct iphdr* ip_h = (struct iphdr*)(packet +sizeof(struct ethhdr));
  struct sockaddr_in src,dst;
  // to represent the ip header len with int 
  int ip_header_len = ip_h->ihl * 4;
  
  // get the icmp part in the packet
  struct tcphdr * tcp_h = (struct tcphdr *)(packet + ip_header_len + sizeof(struct ethhdr));
	src.sin_addr.s_addr = ip_h->saddr;//for the src ip
	dst.sin_addr.s_addr = ip_h->daddr;//for the dest ip
	
  // print the information of the packet.
  if(ip_h->protocol == IPPROTO_TCP)
   {printf("tcp packet information: \nthe source port is %d\n the the destanation port is: %d\n",ntohs(tcp_h->th_sport),ntohs(tcp_h->th_dport));
     printf("the source ip is: %s \n", inet_ntoa(src.sin_addr));
  printf("the destanation ip is: %s \n",inet_ntoa(dst.sin_addr));
  
    switch(ip_h->protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n\n");
            return;
        default:
            printf("   Protocol: others\n\n");

}
   }
}

int main()
{
    pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  // filter, the sniffer will get only icmp 
  char filter_exp[] = "tcp and dst portrange 10-100";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with enp0s3 interface
    // "enp0s3" is a string that specifies the network device to open. BUFSIZ specifies the maximum number of bytes to capture from one packet. promisc specifies if the interface is to be put into promiscuous mode.  1000 specifies the read timeout in milliseconds. errbuf is used to return error text and is only set when pcap_open_live() fails and returns NULL.
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  //it used to compile a string into a filter program
  pcap_compile(handle, &fp, filter_exp, 0, net);     
  if (pcap_setfilter(handle, &fp) != 0 )
  {
    printf("can't set filter");
  }
                         

  // Step 3: Capture packets
  // go to a loop of sniff icmp packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
 

 
