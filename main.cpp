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

  do
  {
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
     EtherHeader((void*)packet);

	
  }while(header->caplen < 100);

  pcap_close(handle);
  return 0;
}

void* EtherHeader(void* data)  
{  
    fd = fopen("./log.txt", "w");
    struct ether_header* ehP = (struct ether_header *)data;  
      
    fprintf(fd,"============================================================="  
            "==========\n");  
    fprintf(fd,"==     SOURCE        ->     Destination\n");  
    fprintf(fd,"== %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n",  
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
  
    fprintf(fd,"======= Protocol       : ");  
    if(ntohs(ehP->ether_type)==ETHERTYPE_IP)  
           fprintf(fd,"[IP]\n");  

    struct iphdr *iph = (struct iphdr *)(sizeof(struct ether_header)+data);
  
    fprintf(fd,"=============================================================\n");
  
    fprintf(fd,"== Source Address      : %s\n", inet_ntoa(*(in_addr*)&iph->saddr));  
    fprintf(fd,"== Destination Address : %s\n", inet_ntoa(*(in_addr*)&iph->daddr));  
    fprintf(fd,"=============================================================\n");  

    struct tcphdr *tcph = (struct tcphdr *)(data+sizeof(struct ether_header)+sizeof(struct iphdr));
    fprintf(fd, "== SRC Port    :  %d\n", ntohs(tcph->source));
    fprintf(fd, "== DST Port    :  %d\n", ntohs(tcph->dest));
    fprintf(fd,"==============================================================\n");
    return 0;  
}  
  

