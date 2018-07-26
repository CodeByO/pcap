#define _BSD_SOURCE
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>




void* EtherHeader( void* data);
 FILE * fd;
 int i;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
    struct pcap_pkthdr* header;
    const u_char* packet;

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while(i < 10000)
  {
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
   
   EtherHeader((void*)packet);
  i++;
  }
    pcap_close(handle);
    return 0;
}

void* EtherHeader(void* data)  
{  
    struct ether_header* ehP = (struct ether_header *)data;  
      
    printf("============================================================="  
            "==========\n");  
    printf("==     SOURCE        ->     Destination\n");  
    printf("== %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n",  
            ehP->ether_shost[0],  
            ehP->ether_shost[1],  
            ehP->ether_shost[2],  
            ehP->ether_shost[3],  
            ehP->ether_shost[4],  
            ehP->ether_shost[5],  
            ehP->ether_dhost[0],  
            ehP->ether_dhost[1],  
            ehP->ether_dhost[2],  
            ehP->ether_dhost[3],  
            ehP->ether_dhost[4],  
            ehP->ether_dhost[5]  
              
            );  
  
    if(ntohs(ehP->ether_type)==ETHERTYPE_IP)  
    {    
      printf("======= Protocol       : ");
      printf("[IP]\n");  

      struct iphdr *iph = (struct iphdr *)(sizeof(struct ether_header)+data);
  
      printf("=============================================================\n");
  
      printf("== Source Address      : %s\n", inet_ntoa(*(in_addr*)&iph->saddr));  
      printf("== Destination Address : %s\n", inet_ntoa(*(in_addr*)&iph->daddr));  
      printf("=============================================================\n");  
    
     if (iph->protocol == IPPROTO_TCP)
        {
  	  struct tcphdr *tcph = (struct tcphdr *)(data+sizeof(struct ether_header)+ sizeof(struct iphdr));
	  printf( "== SRC Port    :  %d\n", ntohs(tcph->source));
    	  printf( "== DST Port    :  %d\n", ntohs(tcph->dest));
    	  printf("==============================================================\n"); 
}
} 
}
