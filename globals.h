#ifndef _GLOBALS_H
#define _GLOBALS_H
/*
 * FILE: globals.h
 * Description: global structs and definitions
 * Autor: Charles. 2016-12-02
 * Mailto: charlesliu.cn.bj@gmail.com
 */
#include "definition.h"

typedef struct global_config_tag {
    int silent;
    int verbose;
    char output_file[FILENAME_LEN];
    char host[HOST_LEN];
    int port;
    char stun_server[HOST_LEN];
    int stun_server_port;
    int stun_local_port;
    int ttl;
    int tos;
    char eth[ETH_LEN];
} global_config_t;

extern global_config_t g_config;

#define SF_SYSLOG(fmt, ...) \
	do {\
	 	if (g_config.verbose == 1)\
			SYSLOG(fmt, ##__VA_ARGS__);\
	} while (0)


#endif
