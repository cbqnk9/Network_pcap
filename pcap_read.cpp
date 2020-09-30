#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>

using namespace std;

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);

void usage(){
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan8\n");
}

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000,errbuf);
    if(handle==nullptr){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n",dev,errbuf);
        return -1;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res,pcap_geterr(handle));
            break;
        }
        dump_pkt(packet,header);
    }
    pcap_close(handle);
}

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header){
    struct ether_header *ether_hdr = (struct ether_header *)pkt_data;

    u_int16_t eth_type = ntohs(ether_hdr-> ether_type);

    //if type is no IP, return function
    if(eth_type != ETHERTYPE_IP){    
        //IP
        struct ip *ip_hdr = (struct ip*)(pkt_data+sizeof(ether_header));

        u_int8_t ip_type = ip_hdr -> ip_p; //protocol
        u_int8_t ip_offset = ip_hdr->ip_hl; //Header Length

        //print ip addr
        char src_ip[16],dst_ip[16];
        char* tmp = inet_ntoa(ip_hdr->ip_src);
        strcpy(src_ip, tmp);
        tmp = inet_ntoa(ip_hdr->ip_dst);
        strcpy(dst_ip,tmp);

        printf("\n IP Packet Info =============================\n");

        printf("Src IP : %s\n", src_ip);
        printf("Dst IP : %s\n", dst_ip);
        
        if(ip_hdr->ip_p == IPPROTO_TCP ){
            //TCP
            struct tcphdr *tcp_hdr =(struct tcphdr*)(pkt_data + ip_offset * 4);   
            printf("\n TCP Packet Info =============================\n");
            printf("Src Port : %d\n",ntohs(tcp_hdr->source));
            printf("Dst Port : %d\n",ntohs(tcp_hdr -> dest));
        }
    
        //print pkt length      
        printf("%u bytes captured\n",header->caplen);

        //print mac addr
        u_int8_t *dst_mac = ether_hdr->ether_dhost;
        u_int8_t *src_mac = ether_hdr->ether_shost;

        printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
        printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);

        //print payload
        u_int32_t payload_len = header-> caplen * sizeof(ether_header) - ip_offset * 4;
        u_int32_t max = payload_len >= 16 ? 16 : payload_len;
        const u_char* pkt_payload = pkt_data+sizeof(ether_header)+ip_offset*4;
        printf("Payload : ");

        if(!payload_len){
            printf("No payload\n");
        }else{
            for(int i =0; i<max;i++) printf("%02x ",*(pkt_payload+i));
            printf("\n");
        }
    }
}