#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

// Define the maximum payload bytes to print
#define MAX_PAYLOAD_PRINT 20

typedef struct {
        char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

void packet_parsing(const u_char *packet, struct pcap_pkthdr* packet_header){
    struct libnet_ethernet_hdr *eth_header = (struct libnet_ethernet_hdr *) packet;

    if(ntohs(eth_header -> ether_type) == ETHERTYPE_IP){
        struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        if(ip_header->ip_p == IPPROTO_TCP){
            struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_header->ip_hl * 4));

            printf("%u bytes captured\n", packet_header->caplen);

            printf("Src Mac: %02x:%02x:%02x:%02x:%02x:%02x  /  Dst Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
                eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
                eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
                eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

            printf("Src IP: %s  /  Dst IP: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
            printf("Src Port: %d  /  Dst Port: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

            const u_char *payload = packet + sizeof(struct libnet_ethernet_hdr) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
            int payload_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);

            printf("Payload: ");
            for (int i = 0; i < payload_len && i < MAX_PAYLOAD_PRINT; i++) {
                printf("%02x ", payload[i]);
            }
           printf("\n");
        }
        printf("\n");
    }
}

bool parse(Param* param, int argc, char* argv[]){
    if (argc != 2) {
        fprintf(stderr, "syntax: pcap-test <interface>\n");
        fprintf(stderr, "sample: pcap-test wlan0\n");
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char *argv[]) {

    if (!parse(&param, argc, argv))
            return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* packet_header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &packet_header, &packet);
        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        packet_parsing(packet, packet_header);
    }

    pcap_close(pcap);
    return 0;
}