#define _GNU_SOURCE /**/

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>

#include <arpa/inet.h>

#ifdef DEBUG
#define LOG(fmt, ...)       fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#else
#define LOG(...)
#endif

void DUMP(const char* title, void* msg, int len);

#define HWADDR_MAX          16
#define MAX_PKT_BUFF        1500
#define MAX_MSG_SIZE        2048
#define INTERFACE_STRLEN    12
#define RA_RETRANS_TIMER    300

struct slaac_handle
{
    // Interface Name
    char   ifn_wan[16];
    char   ifn_lan[16];
    // IPv6 prefix
    char   ip6pfx[32];
    // Interface ID
    int    if_wan;
    int    if_lan;
    // Link Layer Address: MAC
    uint8_t   lladdr_lan[8];
    uint8_t   lladdr_wan[8];
    // Sockets of internal and external
    int    icmp6fd;
    int    icmp6ext;
};

// NETLINK related
int open_netlink_socket(struct slaac_handle* rth);
int neighor_addproxy(struct in6_addr* ip6);

// ICMPv6 related
int open_icmp_socket(struct slaac_handle* rth);

int process_icmp6_local(struct slaac_handle* rth);
int process_icmp6_ext(struct slaac_handle* rth);

int prepare_icmp6_ra(struct slaac_handle* rth);
int icmp6_ra_broadcast(struct slaac_handle* rth);

int close_icmp_socket(struct slaac_handle* rth);

//////////////////////////////
//# vim:ts=4
