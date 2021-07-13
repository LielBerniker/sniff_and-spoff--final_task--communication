
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


void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
  // get the ip part in the packet
  struct iphdr* ip_h = (struct iphdr*)(packet +sizeof(struct ethhdr));
  struct sockaddr_in src,dst;
  
	src.sin_addr.s_addr = ip_h->saddr;//for the src ip
	dst.sin_addr.s_addr = ip_h->daddr;//for the dest ip
  // print the information of the packet.
     printf("the source ip is: %s \n", inet_ntoa(src.sin_addr));
  printf("the destanation ip is: %s \n",inet_ntoa(dst.sin_addr));
      /* determine protocol */
    switch(ip_h->protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");

}
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with any interface
    // "any" is a string that specifies the network device to open. BUFSIZ specifies the maximum number of bytes to capture from one packet. promisc specifies if the interface is to be put into promiscuous mode.  1000 specifies the read timeout in milliseconds. errbuf is used to return error text and is only set when pcap_open_live() fails and returns NULL.
  handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);                     

  // Step 2: Capture packets
  // go to a loop of sniff any packet
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
 
