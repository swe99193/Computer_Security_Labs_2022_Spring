/*
	Raw UDP sockets
    ref:
        https://www.binarytides.com/raw-udp-sockets-c-linux/
*/

#include <stdio.h>       //for printf
#include <string.h>      //memset
#include <sys/socket.h>  //for socket ofcourse
#include <stdlib.h>      //for exit(0);
#include <errno.h>       //For errno - the error number
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/ip.h>  //Provides declarations for ip header

/* 
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd : 1;     // recursion desired
    unsigned char tc : 1;     // truncated message
    unsigned char aa : 1;     // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1;     // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1;    // checking disabled
    unsigned char ad : 1;    // authenticated data
    unsigned char z : 1;     // its z! reserved
    unsigned char ra : 1;    // recursion available

    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
};

/*
	Generic checksum calculation function
*/
// unsigned short csum(unsigned short *ptr,int nbytes)
// {
// 	register long sum;
// 	unsigned short oddbyte;
// 	register short answer;

// 	sum=0;
// 	while(nbytes>1) {
// 		sum+=*ptr++;
// 		nbytes-=2;
// 	}
// 	if(nbytes==1) {
// 		oddbyte=0;
// 		*((u_char*)&oddbyte)=*(u_char*)ptr;
// 		sum+=oddbyte;
// 	}

// 	sum = (sum>>16)+(sum & 0xffff);
// 	sum = sum + (sum>>16);
// 	answer=(short)~sum;

// 	return(answer);
// }

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char const *argv[])
{
    u_int16_t src_port, dst_port;
    u_int32_t src_addr, dst_addr;
    src_addr = inet_addr(argv[1]);
    dst_addr = inet_addr(argv[3]);
    src_port = atoi(argv[2]);
    dst_port = 53;

    //Create a raw socket of type IPPROTO
    int skt = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (skt == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096], *data, *pseudogram;
    // UNKNOWN: pseudogram
    // GUESS: only used in checksum

    //zero out the packet buffer
    memset(datagram, 0, 4096);

    //IP header
    // NOTE: Typecasting a pointer
    struct iphdr *iph = (struct iphdr *)datagram;

    //UDP header
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));

    struct sockaddr_in sin;
    struct pseudo_header psh;
    struct DNS_HEADER *dns = NULL;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr); // pointer to data address
    // strcpy(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // write DNS query here...
    // dns = (struct DNS_HEADER *)(datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
    unsigned char DNS_query[] = {0xd8, 0xcb, 0x01, 0x00,
                                 0x00, 0x01, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00};
    memcpy(data, DNS_query, sizeof(DNS_query));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = dst_addr;

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DNS_query);
    iph->id = htonl(54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;        //Set to 0 before calculating checksum
    iph->saddr = src_addr; //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    iph->check = csum((unsigned short *)datagram, iph->tot_len);

    //UDP header
    udph->source = htons(src_port);
    udph->dest = htons(dst_port);
    udph->len = htons(8 + sizeof(DNS_query)); //tcp header size = [8 Bytes (header)] + [data size]
    udph->check = 0;                          //leave checksum 0 now, filled later by pseudo header

    //Now the UDP checksum using the pseudo header
    psh.source_address = src_addr;
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + sizeof(DNS_query));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(DNS_query);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + sizeof(DNS_query));

    udph->check = csum((unsigned short *)pseudogram, psize);

    //for(int i=0; i<3; i++)
    {
        //Send the packet
        if (sendto(skt, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
            printf("Packet Send. Length : %d \n", iph->tot_len);
        }
    }

    return 0;
}
