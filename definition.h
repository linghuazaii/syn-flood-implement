#ifndef _DEFINITION_H
#define _DEFINITION_H
/********************
 *
 * definition.h
 * Definitions
 * 2016-9-29 Charles.
 * mailto: charlesliu.cn.bj@gmail.com
 *
 ********************/
#include <stdio.h>
#include <time.h>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string>
#include <time.h>
#include <map>
#include <queue>
#include <vector>
#include <stdarg.h>
#include <stdint.h>
#include <iostream>
using namespace std;

#define FILENAME_LEN 256
#define HOST_LEN 256
#define ETH_LEN 64

#define SYSLOG(fmt, ...) \
    do { \
        char time_info[256];\
        time_t now = time(0);\
        struct tm time_tm;\
        localtime_r(&now, &time_tm);\
        strftime(time_info, 256, "%Y-%m-%d %H:%M:%S %Z", &time_tm);\
        fprintf(stderr, "[ %s ] [ %s:%d ] [ %s ] ", time_info, __FILE__, __LINE__, __FUNCTION__);\
        fprintf(stderr, fmt, ##__VA_ARGS__);\
        fprintf(stderr, "\n");\
    } while (0)

#define VSYSLOG(info, fmt, valist) \
    do { \
        char time_info[256];\
        time_t now = time(0);\
        struct tm time_tm;\
        localtime_r(&now, &time_tm);\
        strftime(time_info, 256, "%Y-%m-%d %H:%M:%S %Z", &time_tm);\
        fprintf(stderr, "[ %s ] [ %s:%d ] [ %s ] ", time_info, __FILE__, __LINE__, __FUNCTION__);\
        fprintf(stderr, "%s: ", info);\
        vfprintf(stderr, fmt, valist);\
        fprintf(stderr, "\n");\
    } while (0)

typedef struct CALC_TIME_TAG {
    int pri_time;
    int sec_time;
} CALC_TIME_T;

#define CALC_TIME_MS(calc_time, msg, function) do {\
    struct timeval calc_time_ms_start, calc_time_ms_stop;\
    gettimeofday(&calc_time_ms_start, NULL);\
    function;\
    gettimeofday(&calc_time_ms_stop, NULL);\
    int calc_time_ms_internal = ((calc_time_ms_stop.tv_sec - calc_time_ms_start.tv_sec) * 1000000 + calc_time_ms_stop.tv_usec - calc_time_ms_start.tv_usec) / 1000;\
    calc_time.pri_time = calc_time_ms_internal / 1000;\
    calc_time.sec_time = calc_time_ms_internal % 1000;\
} while (0)

#define CALC_TIME_US(calc_time, msg, function) do {\
    struct timeval calc_time_us_start, calc_time_us_stop;\
    gettimeofday(&calc_time_us_start, NULL);\
    function;\
    gettimeofday(&calc_time_us_stop, NULL);\
    int calc_time_us_internal = ((calc_time_us_stop.tv_sec - calc_time_us_start.tv_sec) * 1000000 + calc_time_us_stop.tv_usec - calc_time_us_start.tv_usec);\
    calc_time.pri_time = calc_time_us_internal / 1000000;\
    calc_time.sec_time = calc_time_us_internal % 1000000;\
} while (0)

#ifdef __GNUC__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#define NEW2(tag, n) (tag *)calloc(n, sizeof(tag))
#define NEW(tag) NEW2(tag, 1)

#define NTH_BYTE(integer, n) ((integer >> (8 * n)) & 0xFF) /* get the nth byte of integer */

typedef unsigned int uint;

#endif
