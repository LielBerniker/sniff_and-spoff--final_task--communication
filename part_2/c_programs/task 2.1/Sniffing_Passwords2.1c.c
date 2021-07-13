
#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h> //contain the ethernet header
#include <netinet/ip.h>	//contain the ip header
#include <netinet/tcp.h> // contain the tcp header
#include <linux/if_ether.h>






void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
  int data_size= 0;
  // get the ip part in the packet
  struct iphdr* ip_h = (struct iphdr*)(packet +sizeof(struct ethhdr));
  struct sockaddr_in src,dst;
  int ip_header_len = ip_h->ihl * 4;
  
  // get the tcp part in the packet
  struct tcphdr * tcp_h = (struct tcphdr *)(packet + ip_header_len + sizeof(struct ethhdr));
  
  //ip src and dst
	src.sin_addr.s_addr = ip_h->saddr;//for the src ip
	dst.sin_addr.s_addr = ip_h->daddr;//for the dest ip
	
  
  //get the data part/payload in the packet 
 char *packet_data = (char *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
 
 //data size=tot_len - ip heder size + tcp heder size
  data_size = ntohs(ip_h->tot_len) - (sizeof(struct iphdr)) + sizeof(struct tcphdr) ;
 
    // print the information of the packet.
  if(ip_h->protocol == IPPROTO_TCP && ntohs(tcp_h->th_dport) == 23)
   {
     printf("tcp packet information: \nthe source port is %d\n the the destanation port is: %d\n",ntohs(tcp_h->th_sport),ntohs(tcp_h->th_dport));
     printf("the source ip is: %s \n", inet_ntoa(src.sin_addr));
  printf("the destanation ip is: %s \n",inet_ntoa(dst.sin_addr));
  
// print the data part in the packet
  printf("%d",data_size);
  if(data_size > 0)
  {
      printf("the packet data is:\n");
      for(int i = 0 ; i < data_size; i++)
       {
        if(isprint(*packet_data))
          {printf("%c",*packet_data);}
        else
          {printf("_");}
        packet_data++;
      }
    printf("\n\n");
   }
}
}
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  
  // filter, the sniffer will get only icmp 
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with br-b371452b513c interface
  //u "br-b371452b513c" is a string that specifies the network device to open. BUFSIZ specifies the maximum number of bytes to capture from one packet. promisc specifies if the interface is to be put into promiscuous mode.  1000 specifies the read timeout in milliseconds. errbuf is used to return error text and is only set when pcap_open_live() fails and returns NULL.
  handle = pcap_open_live("br-b371452b513c", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  //it used to compile a string into a filter program
  pcap_compile(handle, &fp, filter_exp, 0, net);     
  pcap_setfilter(handle, &fp);
  

  // Step 3: Capture packets
  // go to a loop of sniff tcp packets
  pcap_loop(handle,-1,got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
 

 
