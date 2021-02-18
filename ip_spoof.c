#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>

#define SERVER_PORT 5000
#define ICMP_HDRLEN 8
#define IP4_HDRLEN 20
#define SOURCE_IP "10.9.0.5"
#define DESTINATION_IP "8.8.8.8"

unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }
    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits
    return answer;
}

int main()
{
    struct icmp icmphdr;
    char data[256] = "sendig myping";
    // fill ICMP header:
    size_t datalen = strlen(data) + 1;
    icmphdr.icmp_type = ICMP_ECHO;
    icmphdr.icmp_code = 0;
    icmphdr.icmp_id = 18;
    icmphdr.icmp_seq = 0;
    icmphdr.icmp_cksum = 0;

    // fill IP header
    struct ip iphdr;
    iphdr.ip_v = 4;
    iphdr.ip_hl = IP4_HDRLEN/4; // size of header
    iphdr.ip_tos = 0;
    iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + datalen);
    iphdr.ip_id = 0;
    int ip_flags[4];
    ip_flags[0] = 0;
    ip_flags[1] = 0;
    ip_flags[2] = 0;
    ip_flags[3] = 0;
    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);
    iphdr.ip_ttl = 64;
    iphdr.ip_p = IPPROTO_ICMP;
    if (inet_pton(AF_INET, SOURCE_IP, &(iphdr.ip_src)) <= 0)
    {
        perror("src didn't catch");
        exit(1);
    }
    if (inet_pton(AF_INET, DESTINATION_IP, &(iphdr.ip_dst)) <= 0)
    {
        perror("dest didn't catch");
        exit(1);
    }
    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *)&iphdr, IP4_HDRLEN);

    //close the whole packet
    char packet[256];
    memcpy(packet, &iphdr, IP4_HDRLEN);
    memcpy(packet + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);
    memcpy(packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
    memcpy((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    int sock;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1)
    {
        perror("socket didn't open");
        exit(1);
    }
    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    const int flagOne = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL,&flagOne,sizeof (flagOne)) == -1) 
    {
        perror("setsockopt() failed ");
        close(sock);
        exit(1);
    }
    // send packet
    socklen_t len = sizeof(dest_in);
    int byts = sendto(sock, packet, IP4_HDRLEN +ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&dest_in, len);
    if (byts == -1)
    {
        perror("couldn't send the massege");
        close(sock);
        exit(1);
    }
    close(sock);
    return 0;
}
