#include "slaac6.h"

#include <time.h>
#include <poll.h>
#include <net/if.h>

void DUMP(const char* title, void* msg, int len)
{
#ifdef DEBUG    
    int i;
    fprintf(stderr, "\n==== BEGIN(%s) ====\nBuffer:%p\tLength:%d", title, msg, len);
    for (i=0;i<len;++i) {
        if (i % 16 == 0) 
            fprintf(stderr, "\n%08X: ", i);
        fprintf(stderr, "%02x ", ((unsigned char*)msg)[i]);
    }
    fprintf(stderr, "\n==== END(%s) ====\n", title);
#else
    fprintf(stdout, "[neighbor6] DUMP: %s %p/%d\n", title, msg, len);
#endif
}

int main(int argc, char *argv[])
{
    struct slaac_handle rth = { .ifn_wan={"eth1"}, .ifn_lan={"br-lan"},
                .icmp6fd = -1, .icmp6ext = -1,
                .if_wan = -1, .if_lan = -1 };
    int             rc;
    time_t          last;
    struct pollfd   fds[2];

    if (argc>=3) {
        strncpy(rth.ifn_lan, argv[1], 16);
        strncpy(rth.ifn_wan, argv[2], 16);
    }
    if (argc>=4) {
        strncpy(rth.ip6pfx, argv[3], sizeof(rth.ip6pfx));
    } else {
        rth.ip6pfx[0] = 0;
    }

    // Interface to ID
    rth.if_lan = if_nametoindex(rth.ifn_lan);
    rth.if_wan = if_nametoindex(rth.ifn_wan);
    if (rth.if_lan<=0 || rth.if_wan<=0) {
        printf("usage: %s <lan> <wan> [IPv6::prefix]\n", argv[0]);
        exit(-1);
    }
    LOG("PROXY LAN:%s#%d to WAN:%s#%d [%s]", rth.ifn_lan, rth.if_lan, rth.ifn_wan, rth.if_wan, rth.ip6pfx);

    rc = open_netlink_socket(&rth);
    if (rc<0) {
        LOG("Can't create NETLINK socket: %d", rc); 
        exit (-2);
    }

RETRY_HERE:
    rc = open_icmp_socket(&rth);
    if (rc<0) {
        LOG("Can't create ICMPv6 socket: %d", rc);
        exit(-3);
    }

    // Poll set
    memset(fds, 0, sizeof(fds));
    fds[0].fd = rth.icmp6fd; // socklan;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = rth.icmp6ext;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    // Keep the time
    time(&last);

    for (;;) {
        rc = poll(fds, sizeof(fds)/sizeof(fds[0]), RA_RETRANS_TIMER * 1000);

        if (time(NULL)-last>=RA_RETRANS_TIMER) {
            icmp6_ra_broadcast(&rth);
            // remember the time
            time(&last);
        }

        if ( rc < 0 ) {
            perror("poll error:");
            close_icmp_socket(&rth);
            sleep(3);
            // Allow a moment for things to maybe return to normal...
            goto RETRY_HERE;
        }

        // It is a timeout
        if (rc==0) {
            //LOG("Timed out of poll(). Timeout was %d ms", RA_RETRANS_TIMER);
            continue;
        }

        if (fds[0].revents & POLLIN)
            process_icmp6_local(&rth);

        if (fds[1].revents & POLLIN)
            process_icmp6_ext(&rth);
    }

    return (0);
}

//////////////////////////////
//# vim:ts=4
