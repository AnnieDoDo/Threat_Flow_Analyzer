#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <fcntl.h>

#include "protocol_header.h"

// Compute checksum (RFC 1071)
unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Create ICMP echo request
void create_icmp_echo_request(struct icmp_header *icmp, uint16_t identifier) {
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->identifier = identifier;  // Set unique identifier
    icmp->sequence = 0;
    icmp->checksum = 0x00;
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmp_header));
}

// Send ICMP echo request
int send_icmp_request(int sockfd, struct sockaddr_in *addr, uint16_t identifier) {
    struct icmp_header icmp;
    create_icmp_echo_request(&icmp, identifier);
    return sendto(sockfd, &icmp, sizeof(icmp), 0, (struct sockaddr *)addr, sizeof(*addr));
}

// Receive ICMP echo reply
int receive_icmp_reply(int sockfd, char *buffer, int size) {
    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds); // Initialize the read_fds
    FD_SET(sockfd, &read_fds);

    // Set timeout for select
    timeout.tv_sec = 0;  // Timeout in seconds
    timeout.tv_usec = 10000;           // Timeout in microseconds

    int result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

    if (result == -1) {
        perror("select");
        return -1; // Error occurred
    } else if (result == 0) {
        // printf("Receive timeout occurred\n");
        return 0; // Timeout occurred
    }

    // Data is available
    if (FD_ISSET(sockfd, &read_fds)) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        memset(&addr, 0, sizeof(addr));

        int bytes_received = recvfrom(sockfd, buffer, size, 0, (struct sockaddr *)&addr, &addr_len);

        if (bytes_received > 0) {
            struct iphdr *ip = (struct iphdr *)buffer;
            struct icmp_header *icmp = (struct icmp_header *)(buffer + (ip->ihl * 4));
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr.sin_addr), ip_str, INET_ADDRSTRLEN);

            if (icmp->type == ICMP_ECHOREPLY && icmp->identifier != 0) {
                printf("IP %s is up\n", ip_str);
                return 1; // Reply received
            }
        }
    }
    return 0; // No reply or error
}

int main() {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[1024];
    char ip_str[INET_ADDRSTRLEN];
    uint16_t identifier = 0;  // Arbitrary identifier for this request

    // Create a raw socket for ICMP
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    printf("Raw socket is scanning for ICMPv4.\n\n");

    // Send ICMP Echo Requests to each IP address in the range 192.168.120.1 to 192.168.120.255
    for (int i = 1; i < 255; i++) {
        // Set up the target address
        addr.sin_family = AF_INET;
        char target_ip[INET_ADDRSTRLEN];
        snprintf(target_ip, sizeof(target_ip), "192.168.120.%d", i);
        inet_pton(AF_INET, target_ip, &addr.sin_addr);
        identifier = i;

        if (send_icmp_request(sockfd, &addr, identifier) < 0) {
            perror("sendto");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

    }

    // Receive ICMP Echo Replies
    for (int i = 1; i < 255; i++) {
        // Set up the target address
        addr.sin_family = AF_INET;
        char target_ip[INET_ADDRSTRLEN];
        snprintf(target_ip, sizeof(target_ip), "192.168.120.%d", i);
        inet_pton(AF_INET, target_ip, &addr.sin_addr);
        receive_icmp_reply(sockfd, buffer, sizeof(buffer));
    }

    close(sockfd);
    return 0;
}
