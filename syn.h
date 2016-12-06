#ifndef _SF_SYN_H
#define _SF_SYN_H
/*
 * File: syn.h
 * Description: structs and functions for syn packet
 * Author: Charles. 2016-12-5
 * Mailto: charlesliu.cn.bj@gmail.com
 */
#include <netinet/ip.h>
/* compatible things just sucks */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include "utility.h"
#include "globals.h"

#define TCP_HDRLEN 20
#define IP_HDRLEN 20

typedef struct syn_header_tag {
    struct iphdr    ip_header;
    struct tcphdr   tcp_header;
} syn_header_t;

int check_syn_config(global_config_t &config);
int init_syn_packet(syn_header_t &syn_header, global_config_t &config);
uint16_t checksum (uint16_t *addr, int len);
uint16_t tcp4_checksum (struct ip &iphdr, struct tcphdr &tcphdr);
int send_syn_packet(int syn_socket, syn_header_t &syn_header);
int syn_flood();

#endif
