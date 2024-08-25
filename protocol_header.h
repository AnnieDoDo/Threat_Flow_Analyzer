#include <stdint.h>

#define L3_OFFSET 14

enum Ethertype {
    ETH_IPv4 = 0x0800,  // Ethertype for IPv4
    ETH_ARP = 0x0806,
    ETH_IPv6 = 0x86dd,
    ETH_IPv6_o_IPv4 = 0xDD86, //6 in 4
};

struct eth_header {
    uint8_t dest_mac[6];    // Destination MAC address
    uint8_t src_mac[6];     // Source MAC address
    uint16_t ethertype;     // EtherType or length
};

struct ip_header {
    uint8_t version_ihl;          // Version (4 bits) + Internet header length (4 bits)
    uint8_t type_of_service;      // Type of service
    uint16_t total_length;        // Total length
    uint16_t identification;      // Identification
    uint16_t flags_fragment_offset; // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t ttl;                  // Time to live
    uint8_t protocol;             // Protocol
    uint16_t header_checksum;     // Header checksum
    uint32_t src_ip;              // Source address
    uint32_t dest_ip;             // Destination address
};

struct arp_header {
    uint16_t hardware_type;     // Hardware type (e.g., Ethernet is 1)
    uint16_t protocol_type;     // Protocol type (e.g., IPv4 is 0x0800)
    uint8_t  hardware_size;     // Size of hardware address (e.g., 6 for Ethernet)
    uint8_t  protocol_size;     // Size of protocol address (e.g., 4 for IPv4)
    uint16_t opcode;            // ARP operation code (e.g., request or reply)
    uint8_t  sender_mac[6];     // Sender hardware address (MAC)
    uint8_t  sender_ip[4];      // Sender protocol address (IPv4)
    uint8_t  target_mac[6];     // Target hardware address (MAC)
    uint8_t  target_ip[4];      // Target protocol address (IPv4)
};

struct ipv6_header {
    uint32_t     version_class_flow;   // Version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    uint16_t     payload_length;       // Length of the payload (excluding header)
    uint8_t      next_header;          // Next header protocol after IPv6 (e.g., TCP = 6, UDP = 17)
    uint8_t      hop_limit;            // Hop limit (similar to TTL in IPv4)
    uint8_t      source_ip[16];        // Source IPv6 address (128 bits)
    uint8_t      dest_ip[16];          // Destination IPv6 address (128 bits)
    // Optional: Extension headers and payload follow
};

// IPv6 over IPv4 Header Structure (Tunneling)
struct ipv6_over_ipv4_header {
    uint8_t  version;          // Version (always 4 for IPv4)
    uint8_t  header_length;    // Header length (in 32-bit words, minimum 5)
    uint16_t total_length;     // Total length of the packet (including header)
    uint8_t  protocol;         // Protocol type of the encapsulated packet (e.g., 41 for IPv6)
    uint8_t  ttl;              // Time-to-Live (TTL) or Hop Limit
    uint32_t source_ip;        // Source IPv4 address
    uint32_t dest_ip;          // Destination IPv4 address
    // IPv6 Header follows
    //uint32_t ipv6_header;    // IPv6 Header (can be directly embedded if known size)
};

// ICMP header
struct icmp_header {
    uint8_t type;         // ICMP message type
    uint8_t code;         // Subtype code for ICMP message type
    uint16_t checksum;    // Checksum for ICMP message
    uint16_t identifier;  // Unique identifier
    uint16_t sequence;
};