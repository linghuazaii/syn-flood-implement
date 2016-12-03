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

#endif
