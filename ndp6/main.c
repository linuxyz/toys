#include "slaac6.h"

#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>

void dump(const char* title, void* msg, int len)
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
    msg;
    len;
#endif
}


int main(int argc, char *argv[])
{
    struct slaac_handle rth = { .ifn_wan={"eth1"}, .ifn_lan={"br-lan"},
                .icmp6fd = -1, .icmp6ext = -1,
                .if_wan = -1, .if_lan = -1 };
    int             rc;
    struct pollfd   fds[2];
    struct ifreq    req;

    if (argc>=3) {
        strncpy(rth.ifn_lan, argv[1], 16);
        strncpy(rth.ifn_wan, argv[2], 16);
    }
    if (argc>=4) {
        strncpy(rth.ip6pfx, argv[3], sizeof(rth.ip6pfx));
    } else {
        // use default - can be updated by Router Advert
        strncpy(rth.ip6pfx, "2402:f000:5:2d01::", sizeof(rth.ip6pfx));
    }

    // Interface to ID
    rth.if_lan = if_nametoindex(rth.ifn_lan);
    rth.if_wan = if_nametoindex(rth.ifn_wan);
    if (rth.if_lan<=0 || rth.if_wan<=0) {
        printf("usage: %s <lan> <wan> <IPv6::prefix>\n", argv[0]);
        exit(-1);
    }
    LOG("PROXY LAN:%s#%d to WAN:%s#%d as %s", rth.ifn_lan, rth.if_lan, rth.ifn_wan, rth.if_wan, rth.ip6pfx);

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

    // Get the MAC addresses
    strcpy(req.ifr_name, rth.ifn_lan);
    if (ioctl(rth.icmp6fd, SIOCGIFHWADDR, &req)<0) {
        perror("Unable to get the MAC address of LAN");
        close_icmp_socket(&rth);
        exit(-4);
    }
    memcpy(rth.lladdr_lan, req.ifr_hwaddr.sa_data, 6);

    // Get the MAC addresses
    strcpy(req.ifr_name, rth.ifn_wan);
    if (ioctl(rth.icmp6ext, SIOCGIFHWADDR, &req)<0) {
        perror("Unable to get the MAC address of WAN");
        close_icmp_socket(&rth);
        exit(-4);
    }
    memcpy(rth.lladdr_wan, req.ifr_hwaddr.sa_data, 6);

    // RA message
    prepare_icmp6_ra(&rth);

    // Poll set
    memset(fds, 0, sizeof(fds));
    fds[0].fd = rth.icmp6fd; // socklan;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = rth.icmp6ext;
    fds[1].events = POLLIN;
    fds[1].revents = 0;
    //fds[2].fd = -1;
    //fds[2].events = 0;
    //fds[2].revents = 0;

    for (;;) {
        rc = poll(fds, sizeof(fds)/sizeof(fds[0]), DISPATCH_TIMEOUT);

        if (rc==0) {
            LOG("Timed out of poll(). Timeout was %d ms", DISPATCH_TIMEOUT);
            icmp6_ra_broadcast(&rth);
            continue;
        }

        if ( rc < 0 ) {
            perror("poll error:");
            close_icmp_socket(&rth);
            sleep(3);
            // Allow a moment for things to maybe return to normal...
            goto RETRY_HERE;
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

