#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#define ETHERNET_LENGTH 14
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ip *iphdr;
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        //printf("not IP\n");
        return;
    }
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;
    int ip_len;
    //const u_char *ip_src_dst;
    ip_header = packet + ETHERNET_LENGTH;
    ip_len = ((*ip_header) & 0x0f) * 4;
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP)
    {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }
    tcp_header = packet + ETHERNET_LENGTH + ip_len;
    int tcp_len = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_len *= 4;
    printf("%d\n", tcp_len);
    int total_headers_size = ETHERNET_LENGTH + ip_len + tcp_len;
    payload = packet + total_headers_size;
    int payload_length = header->caplen - (ETHERNET_LENGTH + ip_len + tcp_len);
    printf("%d", payload_length);
    if (payload_length > 0)
    {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length)
        {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
    }
    /*ip_src_dst = ip_header + ip_len - 8;
    printf("ip src = ");
    for (int i = 0; i < 4; i++)
    {
        printf("%d", ip_src_dst[i]);
        if (i!=3) printf(".");
    }
    printf("\nip dest = ");
    for (int i = 4; i < 8; i++)
    {
        printf("%d", ip_src_dst[i]);
        if (i!=7) printf(".");
    }*/
    printf("\n");

    printf("\n");
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp and dst portrange 10-100";
    bpf_u_int32 net;
    const char *device = "br-ab8676ef0483";
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