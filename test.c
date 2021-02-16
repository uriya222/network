#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[])
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 1000; /* In milliseconds */

    /* Open device for live capture */
    handle = pcap_open_live(
        "br-ab8676ef0483",
        BUFSIZ,
        packet_count_limit,
        timeout_limit,
        error_buffer);

    /* Attempt to capture one packet. If there is no network traffic
      and the timeout is reached, it will return NULL */
    packet = pcap_next(handle, &packet_header);
    if (packet == NULL)
    {
        printf("No packet found.\n");
        return 2;
    }

    /* Our function to output some info */
    print_packet_info(packet, packet_header);

    return 0;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
    printf("packet time %ld\n", packet_header.ts.tv_usec);
}