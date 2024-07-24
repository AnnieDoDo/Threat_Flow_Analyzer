#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>

#define MAX_EVENTS 10
#define TIMEOUT 5000 // 5s

// ICMP header
struct icmp_header {
    uint8_t type;         // ICMP message type
    uint8_t code;         // Subtype code for ICMP message type
    uint16_t checksum;    // Checksum for ICMP message
    uint32_t rest_of_header;  // Additional data depending on type/code
};

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
void create_icmp_echo_request(struct icmp_header *icmp) {
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->rest_of_header = htons((getpid() & 0xFFFF) << 16); // Using PID as the identifier
    icmp->checksum = 0x00;
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmp_header));
}

// Send ICMP echo request
int send_icmp_request(int sockfd, struct sockaddr_in *addr) {
    struct icmp_header icmp;
    // char ip_str[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
    // printf("IP Address: %s\n", ip_str);
    create_icmp_echo_request(&icmp);
    return sendto(sockfd, &icmp, sizeof(icmp), 0, (struct sockaddr *)addr, sizeof(*addr));
}

// Receive ICMP echo reply
int receive_icmp_reply(int sockfd, char *buffer, int size) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int bytes_received = recvfrom(sockfd, buffer, size, 0, (struct sockaddr *)&addr, &addr_len);

    if (bytes_received > 0) {
        struct iphdr *ip = (struct iphdr *)buffer;
        struct icmp_header *icmp = (struct icmp_header *)(buffer + (ip->ihl * 4));
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), ip_str, INET_ADDRSTRLEN);

        if (icmp->type == ICMP_ECHOREPLY) {
            return 1;
        }
    }
    return 0;
}

// Scan a single IP address
int scan_ip(char *ip) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int epoll_fd, nfds;
    struct epoll_event event, events[MAX_EVENTS];

    // Create an epoll instance with EPOLL_CLOEXEC flag
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Add the raw socket to the epoll instance
    event.events = EPOLLIN;  // Interested in read events
    event.data.fd = sockfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &event) == -1) {
        perror("epoll_ctl");
        close(epoll_fd);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (send_icmp_request(sockfd, &addr) < 0) {
        perror("sendto");
        close(epoll_fd);
        close(sockfd);
        return -1;
    }

    char buffer[1024];
    while (1) {
        // Wait for events
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, TIMEOUT);
        if (nfds < 1) {
            close(epoll_fd);
            close(sockfd);
            return -1;
        }

        // Handle events
        for (int i = 0; i < nfds; ++i) {
            if (events[i].events & EPOLLIN) {
                if (receive_icmp_reply(sockfd, buffer, sizeof(buffer)) > 0) {
                    close(epoll_fd);
                    close(sockfd);
                    return 1;
                } else {
                    close(epoll_fd);
                    close(sockfd);
                    return 0;
                }
            }
        }
    }
}

// void *scan_range(void *args) {
//     int ip_num = *(int *)args;

//     char ip[16];
//     snprintf(ip, sizeof(ip), "192.168.120.%d", ip_num);
    
//     if (scan_ip(ip) == 1) {
//         printf("Host %s is up\n", ip);
//     }

//     free(args);
//     return NULL;
// }

int main() {
    char ip[16];

    for (int i = 87; i < 92; i++) {
        snprintf(ip, sizeof(ip), "192.168.120.%d", i);
        printf("Scanning %s: ", ip);
        if (scan_ip(ip) == 1) {
            printf("Host is up\n");
        } else {
            printf("No response\n");
        }
    }

    // int range_size = 253; // Adjust range size to match number of threads
    // pthread_t threads[range_size];

    // for (int i = 2; i <= range_size; i++) {
    //     int *ip_num = malloc(sizeof(int));
    //     *ip_num = i;
    //     if (pthread_create(&threads[i-2], NULL, scan_range, ip_num) != 0) {
    //         perror("pthread_create");
    //         free(ip_num);
    //         return 1;
    //     }
    // }

    // for (int i = 0; i < range_size; i++) {
    //     pthread_join(threads[i], NULL);
    // }
    return 0;
}
