#include "utility.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <netdb.h>
#include "globals.h"

int check_root_privilege() {
    uid_t ruid, euid, suid;
    int rc = getresuid(&ruid, &euid, &suid);
    if (rc == -1) {
        SYSLOG("getresuid() failed (%s)", strerror(errno));
        return -1;
    }
    
    //SYSLOG("ruid: %d euid: %d, suid: %d", ruid, euid, suid);

    /* program may have suid bit set to get root privilege */
    if (euid != 0 )
        return -1;

    return 0;
}

/* 
 * simple stun client implement base on RFC3489 and RFC5389
 * http://www.ietf.org/rfc/rfc3489.txt (obsoleted)
 * https://tools.ietf.org/html/rfc5389
 * most servers are not usable or need permission
 */
int stun_get_public_ip_imp(const char *server, unsigned short remote_port, unsigned short local_port, char *public_ip) {
    int stun_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (stun_socket == -1) {
        SF_SYSLOG("failed to create stun socket (%s).", strerror(errno));
        return -1;
    }

    struct sockaddr_in stun_client;
    memset(&stun_client, 0, sizeof(stun_client));

    stun_client.sin_family = AF_INET;
    stun_client.sin_port = htons(local_port);

    int rc = bind(stun_socket, (struct sockaddr *)&stun_client, sizeof(stun_client));
    if (rc == -1) {
        SF_SYSLOG("failed to bind stun socket (%s).", strerror(errno));
        close(stun_socket);
        return -1;
    }

    struct sockaddr_in stun_server;
    memset(&stun_server, 0, sizeof(stun_server));

    stun_server.sin_family = AF_INET;
    stun_server.sin_port = htons(remote_port);
    inet_pton(AF_INET, server, &stun_server.sin_addr);

    typedef struct stun_header_tag {
        uint16_t message_type;
        uint16_t message_length;
        unsigned char transaction_id[16];
    } stun_header_t;

    stun_header_t header;
    header.message_type = htons(0x0001); /* Binding Request */
    header.message_length = htons(0);
    *(uint32_t *)(&header.transaction_id[0]) = htonl(0x2112A442);
    /* 96bit transaction id */
    *(uint32_t *)(&header.transaction_id[4]) = 0xAAAABBBB; 
    *(uint32_t *)(&header.transaction_id[8]) = 0xCCCCDDDD;
    *(uint32_t *)(&header.transaction_id[12]) = 0xEEEEFFFF;

    rc = sendto(stun_socket, (void *)&header, sizeof(header), 0, (struct sockaddr *)&stun_server, sizeof(stun_server));
    if (rc == -1) {
        SF_SYSLOG("failed to send request to stun server %s (%s)", server, strerror(errno));
        close(stun_socket);
        return -1;
    }

    unsigned char response[1024];
    rc = recvfrom(stun_socket, response, 1024, 0, NULL, 0);
    if (rc == -1) {
        SF_SYSLOG("failed to receive from stun server %s (%s)", server, strerror(errno));
        close(stun_socket);
        return -1;
    }

    /* determine if it is a Binding Response 0x0101 */
    if (*(uint16_t *)(&response[0]) == htons(0x0101)) {
         uint16_t resp_length = ntohs(*(uint16_t *)(&response[2]));
        /* check transaction id consistence */
        if (*(uint32_t *)(&response[8]) == 0xAAAABBBB && *(uint32_t *)(&response[12]) == 0xCCCCDDDD && *(uint32_t *)(&response[16]) == 0xEEEEFFFF) {
            uint16_t attr_length = 0, pos = 0;
            while (pos < resp_length) {
                if (*(uint16_t *)(&response[20]) == htons(0x0001)) { /* check if Binding Response Attribute type is `MAPPED-ADDRESS`*/
                    sprintf(public_ip, "%d.%d.%d.%d", response[28], response[29], response[30], response[31]);
                    break;
                }  else if (*(uint16_t *)(&response[20]) == htons(0x0020)) { /* check if Binding Resopnse Attribute type is `XOR-MAPPED-ADDRESS` */
                    sprintf(public_ip, "%d.%d.%d.%d", response[28]^0x21, response[29]^0x12, response[30]^0xA4, response[31]^0x42);
                    break;
                } 
                attr_length = ntohs(*(uint16_t *)(&response[20 + pos + 2]));
                pos += attr_length + 4;
            }

            if (pos == resp_length) {
                SF_SYSLOG("STUN server doesn't response `XOR-MAPPPED-ADDRESS` or `MAPPED-ADDRESS`");
                close(stun_socket);
                return -1;
            }
        } else {
            SF_SYSLOG("stun transaction id not consistent");
            close(stun_socket);
            return -1;
        }
    } else {
        SF_SYSLOG("stun server doesn't response a Binding Response");
        close(stun_socket);
        return -1;
    }

    close(stun_socket);
    return 0;
}

int stun_get_public_ip(const char *server, unsigned short remote_port, unsigned short local_port, char *public_ip) {
    vector<string> ips;
    if (is_valid_ip(server)) {
        return stun_get_public_ip_imp(server, remote_port, local_port, public_ip);
    } else {
        int rc = resolve_fqdn_to_ip(server, ips);
        if (rc != 0) {
            SF_SYSLOG("resolve dns for %s failed.", server);
            return -1;
        }

        return stun_get_public_ip_imp(ips[0].c_str(), remote_port, local_port, public_ip);
    }
}

int dig_get_public_ip(char *public_ip, int len) {
    const char *dig_cmd = "dig +short myip.opendns.com @resolver1.opendns.com";
    FILE *cmd_fp = popen(dig_cmd, "r");
    if (cmd_fp == NULL) {
        SF_SYSLOG("popen failed, command (%s) (%s)", dig_cmd, strerror(errno));
        return -1;
    }

    char *rc = fgets(public_ip, len, cmd_fp);
    if (rc == NULL) {
        SF_SYSLOG("fgets from pipe failed.");
        pclose(cmd_fp);
        return -1;
    }
    /* omit the last `\n` */
    public_ip[strlen(public_ip) - 1] = 0;

    pclose(cmd_fp);
    return 0;
}

/**
 * get ip address the router choosed
 */
char *get_primary_ip(char *ip, size_t len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (unlikely(sock == -1)) {
        SF_SYSLOG("create socket failed (%s)", strerror(errno));
        return NULL;
    }

    /**
     * use google dns for test, we don't need to send any packet, the router will determine
     * which interface to use.
     */
    const char *google_dns = "8.8.8.8";
    uint16_t dns_port = 53;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(google_dns);
    serv.sin_port = htons(dns_port);

    int rc = connect(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (unlikely(rc == -1)) {
        SF_SYSLOG("UDP connect failed (%s)", strerror(errno));
        return NULL;
    }

    sockaddr_in name;
    socklen_t name_len = sizeof(name);
    rc = getsockname(sock, (struct sockaddr *)&name, &name_len);
    if (unlikely(rc == -1)) {
        SF_SYSLOG("getsockname() failed (%s)", strerror(errno));
        return NULL;
    }

    const char *p = inet_ntop(AF_INET, &name.sin_addr, ip, len);
    if (unlikely(p == NULL)) {
        SF_SYSLOG("inet_ntop() failed (%s)", strerror(errno));
        return NULL;
    }

    return ip;
}

/**
 * get ip address of specified ethernet.
 */
char *get_ethernet_ip(const char *ethernet, char *ip, size_t len) {
    struct ifaddrs *ips, *iter;
    int rc = getifaddrs(&ips);
    if (unlikely(rc == -1)) {
        SF_SYSLOG("getifaddrs() failed (%s)", strerror(errno));
        freeifaddrs(ips);
        return NULL;
    }

    for (iter = ips; iter != NULL; iter = ips->ifa_next) {
        if (strcasecmp(ethernet, iter->ifa_name) == 0 && iter->ifa_addr->sa_family == AF_INET) {
            sockaddr_in *local_ip = (sockaddr_in *)iter->ifa_addr;
            const char *p = inet_ntop(AF_INET, &local_ip->sin_addr, ip, len);
            if (unlikely(p == NULL)) {
                SF_SYSLOG("inet_ntop() failed (%s)", strerror(errno));
                freeifaddrs(ips);
                return NULL;
            }

            freeifaddrs(ips);
            return ip;
        }
    }

    freeifaddrs(ips);
    return NULL;
}

/**
 * get ip address of specified ethernet.
 */
char *get_ethname_by_ip(const char *ip, char *ethname, size_t len) {
    struct ifaddrs *ips, *iter;
    int rc = getifaddrs(&ips);
    if (unlikely(rc == -1)) {
        SF_SYSLOG("getifaddrs() failed (%s)", strerror(errno));
        freeifaddrs(ips);
        return NULL;
    }

    char temp_ip[INET_ADDRSTRLEN];
    for (iter = ips; iter != NULL; iter = iter->ifa_next) {
        if (iter->ifa_addr->sa_family == AF_INET) {
            sockaddr_in *local_ip = (sockaddr_in *)iter->ifa_addr;
            const char *p = inet_ntop(AF_INET, &local_ip->sin_addr, temp_ip, INET_ADDRSTRLEN);
            if (unlikely(p == NULL)) {
                SF_SYSLOG("inet_ntop() failed (%s)", strerror(errno));
                freeifaddrs(ips);
                return NULL;
            } else {
                if (strcmp(ip, p) != 0)
                    continue;
                else
                    strncpy(ethname, iter->ifa_name, len);
            }

            freeifaddrs(ips);
            return ethname;
        }
    }

    freeifaddrs(ips);
    return NULL;
}

/*
 * Resolve fqdn to ip address
 * Note: Now we only resolve ipv4 address, if you need to use ipv6,
 *       modify this function. We only use one IP even though resolving
 *       dns gives us AN IP LIST.
 */
int resolve_fqdn_to_ip(const char *fqdn, vector<string> &ips) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(fqdn, NULL, &hints, &res);
    if (unlikely(rc != 0)) {
        SF_SYSLOG("getaddrinfo() failed, host(%s) msg(%s)", fqdn, gai_strerror(rc));
        return -1;
    }

    struct sockaddr_in *addr;
    char ip[INET_ADDRSTRLEN];
    for (; res != NULL; res = res->ai_next) {
        addr = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
        ips.push_back(ip);
    }

    return 0;
}

/*
 * determine whether an IP is valid or not
 */
bool is_valid_ip(const char *host) {
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;

    const char *mark = strchr(host, ':');
    if (mark != NULL) {
        /* ipv6 */
        int rc = inet_pton(AF_INET6, host, &(ipv6.sin6_addr));
        return rc;
    } else {
        /* ipv4 */
        int rc = inet_pton(AF_INET, host, &(ipv4.sin_addr));
        return rc;
    }
}

/*
 * Test 
 */
#if 0
global_config_t g_config;
int main(int argc, char **argv) {
    /*
    vector<string> ip;
    resolve_fqdn_to_ip(argv[1], ip);
    for (int i = 0; i < ip.size(); ++i)
        cout<<"ip: "<<ip[i]<<endl;
    */

    char ethname[32];
    get_ethname_by_ip("127.0.0.1", ethname, 32);
    cout<<"ethname: "<<ethname<<endl;
    get_ethname_by_ip("172.31.43.244", ethname, 32);
    cout<<"ethname: "<<ethname<<endl;

    return 0;
}
#endif
