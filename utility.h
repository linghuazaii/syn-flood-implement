#ifndef _UTILITY_H
#define _UTILITY_H
/*
 * File: utility.h
 * Description: common used functions
 * Author: Charles. 2016-11-30
 * Mailto: charlesliu.cn.bj@gmail.com
 */

#include "definition.h"

int check_root_privilege();
int stun_get_public_ip_imp(const char *server, unsigned short remote_port, unsigned short local_port, char *public_ip);
int dig_get_public_ip(char *public_ip, int len);
char *get_primary_ip(char *ip, size_t len);
char *get_ethernet_ip(const char *ethernet, char *ip, size_t len);
int resolve_fqdn_to_ip(const char *fqdn, vector<string> &ips);
bool is_valid_ip(const char *host);
int stun_get_public_ip(const char *server, unsigned short remote_port, unsigned short local_port, char *public_ip);
char *get_ethname_by_ip(const char *ip, char *ethname, size_t len);

#endif
