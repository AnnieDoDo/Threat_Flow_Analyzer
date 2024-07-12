#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include "bpf_gen_struct.h"
#include "protocol_header.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

struct sock_fprog bpf = {
    .len = ARRAY_SIZE(code),
    .filter = code,
};

void print_mac_address(uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

void print_ip_address(uint32_t ip) {
    printf("%d.%d.%d.%d",
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
}

void print_ipv6_address(uint8_t *ip) {
    for (int i = 0; i < 16; ++i) {
        if (ip[i] != 00) {
            printf("%02x", ip[i]);
        }
        if (i < 15) printf(":");
    }
}

void print_packet_data(char *buffer, int len) {

    // Ethernet frame
    struct eth_header frame;

    memset(&frame, 0, sizeof(frame));
    memcpy(&frame, buffer, sizeof(frame));

    printf("Destination MAC: ");
    print_mac_address(frame.dest_mac);
    printf("\nSource MAC: ");
    print_mac_address(frame.src_mac);
    printf("\nEtherType: 0x%04x\n", ntohs(frame.ethertype));

    int ethertype = ntohs(frame.ethertype);
    if (ethertype == ETH_IPv4) {
        // IP header
        struct ip_header ip_hdr;

        memset(&ip_hdr, 0, sizeof(ip_hdr));
        memcpy(&ip_hdr, buffer + L3_OFFSET, sizeof(ip_hdr));

        printf("Version: %d\n", (ip_hdr.version_ihl >> 4) & 0xF);
        printf("IHL: %d\n", ip_hdr.version_ihl & 0xF);
        printf("Type of Service: 0x%02x\n", ip_hdr.type_of_service);
        printf("Total Length: %d\n", ntohs(ip_hdr.total_length));
        printf("Identification: 0x%04x\n", ntohs(ip_hdr.identification));
        printf("Flags + Fragment Offset: 0x%04x\n", ntohs(ip_hdr.flags_fragment_offset));
        printf("TTL: %d\n", ip_hdr.ttl);
        printf("Protocol: %d\n", ip_hdr.protocol);
        printf("Header Checksum: 0x%04x\n", ntohs(ip_hdr.header_checksum));
        printf("Source IP: ");
        print_ip_address(ntohl(ip_hdr.src_ip));
        printf("\nDestination IP: ");
        print_ip_address(ntohl(ip_hdr.dest_ip));
        printf("\n");
    } else if (ethertype == ETH_ARP) {
        // ARP header
        struct arp_header arphdr;

        memset(&arphdr, 0, sizeof(arphdr));
        memcpy(&arphdr, buffer + L3_OFFSET, sizeof(arphdr));

        printf("ARP Header:\n");
        printf("Hardware Type: %u\n", arphdr.hardware_type);
        printf("Protocol Type: 0x%04x\n", arphdr.protocol_type);
        printf("Hardware Size: %u\n", arphdr.hardware_size);
        printf("Protocol Size: %u\n", arphdr.protocol_size);
        printf("Opcode: %u\n", arphdr.opcode);
        printf("Sender MAC: ");
        print_mac_address(arphdr.target_mac);
        printf("\nTarget MAC: ");
        print_mac_address(arphdr.sender_mac);
        printf("\nSender IP: ");
        print_ip_address(ntohl(arphdr.sender_ip));
        printf("\nTarget IP: ");
        print_ip_address(ntohl(arphdr.target_ip));
        printf("\n");
    } else if (ethertype == ETH_IPv6) {
        // IPv6 header
        struct ipv6_header ipv6_hdr;

        memset(&ipv6_hdr, 0, sizeof(ipv6_hdr));
        memcpy(&ipv6_hdr, buffer + L3_OFFSET, sizeof(ipv6_hdr));

        printf("\nIPv6 Header:\n");
        printf("Version: %u\n", (ipv6_hdr.version_class_flow >> 28) & 0xF);
        printf("Traffic Class: %u\n", (ipv6_hdr.version_class_flow >> 20) & 0xFF);
        printf("Flow Label: %u\n", ipv6_hdr.version_class_flow & 0xFFFFF);
        printf("Payload Length: %u\n", ipv6_hdr.payload_length);
        printf("Next Header: %u\n", ipv6_hdr.next_header);
        printf("Hop Limit: %u\n", ipv6_hdr.hop_limit);
        printf("Source IP: ");
        print_ipv6_address(ipv6_hdr.source_ip);
        printf("\n");
        printf("Destination IP: ");
        print_ipv6_address(ipv6_hdr.dest_ip);
        printf("\n");
    }



}

int main () {

    // const char *command = "/home/annie/linux/tools/bpf/bpf_asm -c /home/annie/linux/tools/bpf/test";

    // // Open a pipe to the command
    // FILE *fp = popen(command, "r");
    // if (fp == NULL) {
    //     perror("popen");
    //     return 1;
    // }

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        printf("socket fd < 0\n");
        return -1;
    }

    int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (ret < 0){
        printf("set socket option < 0\n");
        close(sock);
        return -1;
    }

    printf("BPF program attached successfully\n");
    printf("socket fd = %d\n", sock);

    char buffer[2048];
    while (1) {
        int len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            perror("recvfrom failed");
            close(sock);
            return -1;
        }
        printf("Received packet of length %d\n", len);
        print_packet_data(buffer, len);
        printf("\n\n\n", len);
    }

    close(sock);
    return 0;
}

