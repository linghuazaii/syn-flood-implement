#include "utility.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
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
