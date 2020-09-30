#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

struct arp
{
    u_char hdr[2]; //Hardware type
    u_char pro[2]; //Protocol type
    u_char hln; //Hardware address length
    u_char pln; //Protocol address length
    u_char op[2]; //OPcode
    u_char sha[6]; //Sender hardware address
    u_char spa[4]; //Sender protocol address
    u_char dha[6]; //Destination hardware address
    u_char dpa[4]; //Destination protocol address
};


int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
u_char packet[100];
int i;

    /* Check the validity of the command line */
    if (argc != 2)
    {
        printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
        return -1;
    }
    
    /* Open the output device */
    if ( (fp= pcap_open_live(argv[1],            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                        1000,               // read timeout
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
        return -1;
    }

    /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    packet[0]=1;
    packet[1]=1;
    packet[2]=1;
    packet[3]=1;
    packet[4]=1;
    packet[5]=1;
    
    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;
    
    //ethernet type -> ARP 0x0806 
    packet[12]=0x08;
    packet[13]=0x06;

    /* Fill the rest of the packet */
    for(i=14;i<100;i++)
    {
        packet[i]=i%256;
    }

    //arp packet
    struct arp arp;
    arp.hdr[0]=0x00;
    arp.hdr[1]=0x01; //0001 ethernet

    arp.pro[0]=0x08;
    arp.pro[1]=0x00;    //0800(2048)IPv4

    arp.hln=0x06; //MAC address

    arp.pln=0x04; //IPv4

    arp.op[0]=0x00;
    arp.op[1]=0x01; // 1.ARP request 2.ARP reply 3. RARP request 4. RARP reply

    arp.sha[0]=0x02;
    arp.sha[1]=0x02;
    arp.sha[2]=0x02;
    arp.sha[3]=0x02;
    arp.sha[4]=0x02;
    arp.sha[5]=0x02; //set mac source to 2:2:2:2:2:2


    arp.spa[0]=0x01;
    arp.spa[1]=0x02;
    arp.spa[2]=0x03;
    arp.spa[3]=0x04; //1.2.3.4
    
    arp.dha[0]=0x01;
    arp.dha[1]=0x01;
    arp.dha[2]=0x01;
    arp.dha[3]=0x01;
    arp.dha[4]=0x01;
    arp.dha[5]=0x01; //set mac destination to 1:1:1:1:1:1

    arp.dpa[0]=0x04;
    arp.dpa[1]=0x03;
    arp.dpa[2]=0x02;
    arp.dpa[3]=0x01; //4.3.2.1

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet,sizeof(struct arp)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}