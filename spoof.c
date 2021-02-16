#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#define ETHERNET_LENGTH 14
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        printf("not IP\n");
        return;
    }
    const u_char *ip_header;
    int ip_len;
    const u_char *ip_src_dst;
    ip_header = packet + ETHERNET_LENGTH;
    ip_len = (*ip_header) & 0x0f;
    ip_len *= 4;
    printf("size of ip: %d\n", ip_len);
    ip_src_dst = ip_header + ip_len - 8;
    for (int i = 0; i < 4; i++)
    {
        printf("%x", ip_src_dst[i]);
    }
    printf("\n");
    for (int i = 4; i < 8; i++)
    {
        printf("%x", ip_src_dst[i]);
    }
    printf("\n");
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;
    const char *device = "br-ab8676ef0483";
    int packet_count_limit = 1;
    int timeout_limit = 1000; /* In milliseconds */
    // Step 1: Open live pcap session on NIC with name eth3
    // Students needs to change "eth3" to the name
    // found on their own machines (using ifconfig).
    handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit, errbuf);
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap