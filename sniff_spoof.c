#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <unistd.h>

#define ETHERNET_LENGTH 14
#define ICMP_HDRLEN 8
#define IP4_HDRLEN 20

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    //double check if the link header contains ip
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }
    // get the headers positions
    const u_char *ip_header;
    const u_char *icmp_header;
    int ip_len;
    ip_header = packet + ETHERNET_LENGTH;
    ip_len = ((*ip_header) & 0x0f) * 4;
    u_char protocol = *(ip_header + 9);
    // check if have icmp
    if (protocol != IPPROTO_ICMP)
    {
        printf("Not a ICMP packet. Skipping...\n\n");
        return;
    }
    icmp_header = packet + ETHERNET_LENGTH + ip_len;
    u_char icmp_type = (*icmp_header);
    // check if its request
    if (icmp_type != 8)
    {
        printf("Not a ICMP request(%d). Skipping...\n\n", icmp_type);
        return;
    }
    //print out the ip src and dest
    const u_char *ip_src_dst = ip_header + ip_len - 8;
    printf("ip src = ");
    for (int i = 0; i < 4; i++)
    {
        printf("%d", ip_src_dst[i]);
        if (i != 3)
            printf(".");
    }
    printf("\nip dest = ");
    for (int i = 4; i < 8; i++)
    {
        printf("%d", ip_src_dst[i]);
        if (i != 7)
            printf(".");
    }
    printf("\n");
    printf("\n");

    const u_char *payload = packet + (ETHERNET_LENGTH + ip_len + ICMP_HDRLEN);
    int payload_length = header->caplen - (ETHERNET_LENGTH + ip_len + ICMP_HDRLEN);

    //*************spoofing******
    // fill icmp header
    struct icmp icmphdr;

    icmphdr.icmp_type = 0;
    icmphdr.icmp_code = 0;
    icmphdr.icmp_id = *(uint16_t *)(icmp_header + 4);
    icmphdr.icmp_seq = *(uint16_t *)(icmp_header + 6);
    icmphdr.icmp_cksum = 0;

    // fill IP header
    struct ip iphdr;
    iphdr.ip_v = 4;
    iphdr.ip_hl = IP4_HDRLEN / 4; // size of header
    iphdr.ip_tos = 0;
    iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + payload_length);
    iphdr.ip_id = 0;
    int ip_flags[4];
    ip_flags[0] = 0;
    ip_flags[1] = 0;
    ip_flags[2] = 0;
    ip_flags[3] = 0;
    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);
    iphdr.ip_ttl = 110;
    iphdr.ip_p = IPPROTO_ICMP;

    iphdr.ip_dst.s_addr = *(in_addr_t *)(ip_src_dst);
    iphdr.ip_src.s_addr = *(in_addr_t *)(ip_src_dst + 4);

    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *)&iphdr, IP4_HDRLEN);

    //close the whole packet
    char packet_to_send[256];
    memcpy(packet_to_send, &iphdr, IP4_HDRLEN);
    memcpy(packet_to_send + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);
    memcpy(packet_to_send + IP4_HDRLEN + ICMP_HDRLEN, payload, payload_length);
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet_to_send + IP4_HDRLEN), ICMP_HDRLEN + payload_length);
    memcpy(packet_to_send + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);

    //open socket
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
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof(flagOne)) == -1)
    {
        perror("setsockopt() failed ");
        close(sock);
        exit(1);
    }
    // send packet
    socklen_t len = sizeof(dest_in);
    int byts = sendto(sock, packet_to_send, IP4_HDRLEN + ICMP_HDRLEN + payload_length, 0, (struct sockaddr *)&dest_in, len);
    if (byts == -1)
    {
        perror("couldn't send the massege");
        close(sock);
        exit(1);
    }
    close(sock);
    return;
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp"; //filter the none icmp
    bpf_u_int32 net;
    const char *device = "br-ab8676ef0483"; //need to change to your network card (use ifconfig)
    int packet_count_limit = 1;
    int timeout_limit = 1000;
    handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit, errbuf);
    pcap_set_promisc(handle, 1);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}