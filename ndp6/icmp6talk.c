#include "slaac6.h"

#include <netinet/icmp6.h>
//#include <linux/icmpv6.h>

#define ICMPV6_MLD2_REPORT      143
#define MLD2_MODE_IS_EXCLUDE    2
#define MLD2_CHANGE_TO_EXCLUDE  4


// We use it to save the Router Advert message
unsigned char _ra_msg[256];
int _len;

static int icmp_socket(int if_scope, struct icmp6_filter* xfilter)
{
    int sock, err, optval;
    struct sockaddr_in6 in6addr;
    struct ipv6_mreq mreq;

    // create socket
    LOG("Creating PF_INET6 ICMPv6 socket.");
    sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0) {
        perror("Can't create socket(PF_INET6/RAW/ICMPV6):");
        return (-1);
    }

    // Bind the socket to the interface we're interested in
    memset(&in6addr, 0, sizeof(in6addr));
    in6addr.sin6_family = AF_INET6;
    in6addr.sin6_scope_id = if_scope; //if_nametoindex(lan);
    err = bind(sock, (struct sockaddr *)&in6addr, sizeof(in6addr));
    if (err < 0) {
        perror("packet socket bind return failed:");
        close(sock);
        return -__LINE__;
    }
    LOG("ICMPv6 socket bind to interface %d OK", if_scope); //if_nametoindex(lan));

    optval = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval)) < 0) {
        perror("Error! setsockopt(IPV6_RECVPKTINFO)"); /* XXX err? */
        close(sock);
        return -__LINE__;
    }

    // Set IPV6_MULTICAST_LOOP
    optval = 0;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &optval, sizeof(optval)) <0 ) {
        perror("Error! setsockopt(IPV6_MULTICAST_LOOP)");
        close(sock);
        return -__LINE__;
    }

    // Set the ICMPv6 filter
    if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &xfilter, sizeof(xfilter)) <0 ) {
        perror("Error! setsockopt(ICMP6_FILTER)");
        close(sock);
        return -__LINE__;
    }

    // Join the all nodes multicast group: FF02::1
    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_interface = if_scope;
    mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xff;
    mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
    mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP, ff02::01)");
        close(sock);
        return -__LINE__;
    }

    return sock;
}

int open_icmp_socket(struct slaac_handle* rth)
{
    int sock; //, optval;
    struct icmp6_filter xfilter;
    struct ipv6_mreq mreq;

    // Set the ICMPv6 filter
    ICMP6_FILTER_SETBLOCKALL(&xfilter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &xfilter);
    ICMP6_FILTER_SETPASS(ICMPV6_MLD2_REPORT, &xfilter); // MLDv2 report
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_SOLICIT, &xfilter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &xfilter);
    //ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &xfilter);
    sock = icmp_socket(rth->if_lan, &xfilter);
    if (sock < 0) {
        perror("Can't create socket(PF_INET6/RAW/ICMPV6):");
        return -__LINE__;
    }

    // Join the all routers multicast group: FF02::2
    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_interface = rth->if_lan;
    mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xff;
    mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
    mreq.ipv6mr_multiaddr.s6_addr[15] = 0x02;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP, ff02::02)");
        close(sock);
        return -__LINE__;
    }

    // Join the MLDv2 multicast group: FF02::16
    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_interface = rth->if_lan;
    mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xff;
    mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
    mreq.ipv6mr_multiaddr.s6_addr[15] = 0x16;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP, ff02::01)");
        close(sock);
        return -__LINE__;
    }

    rth->icmp6fd = sock;
    LOG("LAN ICMPv6 socket OK.");

    // Set the ICMPv6 filter
    ICMP6_FILTER_SETBLOCKALL(&xfilter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &xfilter);
    sock = icmp_socket(rth->if_wan, &xfilter);
    if (sock < 0) {
        perror("Can't create socket(PF_INET6/RAW/ICMPV6):");
        close_icmp_socket(rth);
        return -__LINE__;
    }
    rth->icmp6ext = sock;
    LOG("WAN ICMPv6 socket OK.");

    // Mark it
    _ra_msg[0] = 0;

    return 0;
}

// Using local variant directly!

static int receive_icmp6(int fd, struct sockaddr_in6* addr, unsigned char* msg)
{
    struct iovec iov;
    struct msghdr mhdr;
    char ipstr[64]; // IP address
    int len = 0;

    memset(&iov, 0, sizeof(iov));
    iov.iov_len = MAX_MSG_SIZE;
    iov.iov_base = (caddr_t) msg;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)addr;
    mhdr.msg_namelen = sizeof(*addr);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = NULL;
    mhdr.msg_controllen = 0;

    len = recvmsg(fd, &mhdr, 0);
    if (len < 0) {
        perror("recvmsg failed:");
        return len;
    }

#ifdef DEBUG
    sprintf(ipstr, "%x:%x:%x:%x:%x:%x:%x:%x",
            ntohs(addr->sin6_addr.s6_addr16[0]),
            ntohs(addr->sin6_addr.s6_addr16[1]),
            ntohs(addr->sin6_addr.s6_addr16[2]),
            ntohs(addr->sin6_addr.s6_addr16[3]),
            ntohs(addr->sin6_addr.s6_addr16[4]),
            ntohs(addr->sin6_addr.s6_addr16[5]),
            ntohs(addr->sin6_addr.s6_addr16[6]),
            ntohs(addr->sin6_addr.s6_addr16[7]));
    LOG("ICMPv6 from %s type:%d code:%d", ipstr, msg[0], msg[1]);
#endif

    /* Impossible.. But let's not take chances */
    if (len > MAX_MSG_SIZE) {
        LOG("Read more data from socket than we can handle. Ignoring it.");
        len = 0;
    }

    return len;
}

static void swaplladdr(unsigned char* icmp6opt, int len, unsigned char* mac)
{
    int pos = 0;
    while (pos < len) {
        // this is the Link Layer Address of Source
        if ( (icmp6opt[pos] & 0x03)  && icmp6opt[pos+1]==1) {
            memcpy(icmp6opt+pos+2, mac, 6);
            break;
        }

        if (icmp6opt[pos+1]==0)
            pos += 8;
        else
            pos += icmp6opt[pos+1] * 8;
    }
}

int process_icmp6_local(struct slaac_handle* rth)
{
    int len, rtn;
    struct sockaddr_in6 saddr;
    unsigned char msg[MAX_MSG_SIZE * 2];
    struct icmp6_hdr* _icmp6 = (struct icmp6_hdr*)msg;

    len = receive_icmp6(rth->icmp6fd, &saddr, msg);
    if (len<=0)
        return len;

    // Handle the Router Solicited request
    if (_icmp6->icmp6_type == ND_ROUTER_SOLICIT) {
        struct sockaddr_in6 in6addr;

        memset(&in6addr, 0, sizeof(in6addr));
        in6addr.sin6_family = AF_INET6;
        in6addr.sin6_scope_id = rth->if_wan; //if_nametoindex(lan);
        in6addr.sin6_addr.s6_addr[ 0] = 0xff;
        in6addr.sin6_addr.s6_addr[ 1] = 0x02;
        in6addr.sin6_addr.s6_addr[15] = 0x02;

        dump("<--ND_ROUTER_SOLICIT", msg, len);

        if (_ra_msg[0] == ND_ROUTER_ADVERT && _len>=28) {
            in6addr.sin6_addr.s6_addr[15] = 0x01;
            rtn = sendto(rth->icmp6fd, _ra_msg, _len, 0, (struct sockaddr*)&in6addr, sizeof(in6addr));
            if (rtn<len) {
                perror("Error! sendto(MC_ALL_NODES)");
            }
            LOG("Response ROUTER ADVERT with cache to LAN!");
            return rtn;
        }

        // update the source MAC
        swaplladdr(msg+8, len-8, rth->lladdr_wan);
        rtn = sendto(rth->icmp6ext, msg, len, 0, (struct sockaddr*)&in6addr, sizeof(in6addr));
        if (rtn<len) {
            perror("Error! sendto(MC_ALL_ROUTERS)");
        }
        LOG("Forward ROUTER SOLICIT to WAN!");
        return rtn;
    }

    // Join the Solicited-Node Multicast Address FF02::1:FF00:0
    // You need to mangle the Solicited-Node multicast traffic to it.
    // http://tools.ietf.org/html/rfc4291
    if (_icmp6->icmp6_type == ICMPV6_MLD2_REPORT) { // ICMPV6_MLD2_REPORT

        int pos, i, nmcast;
        struct in6_addr snma = { { { 0xff,2,0,0,0,0,0,0,0,0,0,1,0xff,0,0,0 } } };
        struct ipv6_mreq mreq = { .ipv6mr_interface = rth->if_lan };
    
        // refer to http://tools.ietf.org/html/rfc3810 5.2
        dump("<--ICMPV6_MLD2_REPORT", msg, len);

        pos = 8;
        nmcast = ntohs(_icmp6->icmp6_data16[1]);
        for (i=0;i<nmcast && len>=pos+20;
            //   FIX LEN + AUX        + All Source Addresses
            pos += 20 + msg[pos+1]*4 + msg[pos+2]*256*16 + msg[pos+3]*16, i++) {

            // only exclude mode is right
            if (msg[pos]!=MLD2_CHANGE_TO_EXCLUDE)
                continue;
            // Test the multicast group
            if (memcmp(msg+pos+4, &snma, 13)!=0) {
                continue;
            }
            LOG("Add to Solicited-node Multicast Group");
            memcpy(mreq.ipv6mr_multiaddr.s6_addr, msg+pos+4, 16);
            if (setsockopt(rth->icmp6fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP)");
        }

        return len;
    }

    /* Add to neigh proxy */
    if (_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT && len>=24) {

        // Only do Global Unicast IPv6 Address range is 2000::/3
        if (((unsigned char)(msg[8]) & 0xE0) != 0x20) {
            // It isn't global unicast IPv6
            return len;
        }
    
        dump("<--NEIGHBOR_SOLICIT", msg, len);

        rtn = neighor_addproxy(rth, (struct in6_addr*)(msg+8));
        LOG("add neigh proxy return: %d", rtn);
        return rtn;
    }

    /* Add to neigh proxy, OSX is using Neighbor Advert */
    if (_icmp6->icmp6_type == ND_NEIGHBOR_ADVERT && len>=24) {
    
        // Only handle the unsigned IPv6 messages
        if (   saddr.sin6_addr.s6_addr32[0] != 0
            || saddr.sin6_addr.s6_addr32[1] != 0
            || saddr.sin6_addr.s6_addr32[2] != 0
            || saddr.sin6_addr.s6_addr32[3] != 0 )
        {
            return len;
        }

        dump("<--NEIGHBOR_ADVERT", msg, len);

        // Only do Global Unicast IPv6 Address range is 2000::/3
        if (((unsigned char)(msg[8]) & 0xE0) != 0x20) {
            // It isn't global unicast IPv6
            return len;
        }
    
        rtn = neighor_addproxy(rth, (struct in6_addr*)(msg+8));
        LOG("add neigh proxy return: %d", rtn);
        return rtn;
    }

    return len;
}

int process_icmp6_ext(struct slaac_handle* rth)
{
    struct sockaddr_in6 saddr;
    unsigned char msg[MAX_MSG_SIZE * 2];
    struct icmp6_hdr* _icmp6 = (struct icmp6_hdr*)msg;
    int len, rtn;

    len = receive_icmp6(rth->icmp6ext, &saddr, msg);
    if (len<=0)
        return len;

    // Handle the Router Advert forward to all nodes
    if (_icmp6->icmp6_type == ND_ROUTER_ADVERT) {
        struct sockaddr_in6 in6addr;

        memset(&in6addr, 0, sizeof(in6addr));
        in6addr.sin6_family = AF_INET6;
        in6addr.sin6_scope_id = rth->if_lan; //if_nametoindex(lan);
        in6addr.sin6_addr.s6_addr[ 0] = 0xff;
        in6addr.sin6_addr.s6_addr[ 1] = 0x02;
        in6addr.sin6_addr.s6_addr[15] = 0x01;

        dump("-->ND_ROUTER_ADVERT ?", msg, len);

        swaplladdr(msg+16, len-16, rth->lladdr_lan);
        // save it
        if (len<sizeof(_ra_msg)) {
            _len = len;
            memcpy(_ra_msg, msg, _len);
            LOG("Save ROUTER ADVERT message!");
        }
        rtn = sendto(rth->icmp6fd, msg, len, 0, (struct sockaddr*)&in6addr, sizeof(in6addr));
        if (rtn<len) {
            perror("Error! sendto(MC_ALL_NODES)");
        }
        LOG("Forward ROUTER ADVERT to LAN!");
        return rtn;
    }

    return len;
}

int close_icmp_socket(struct slaac_handle* rth)
{
    LOG("Close ICMPv6 sockets.");
    if (rth->icmp6ext>0)
        close(rth->icmp6ext);
    rth->icmp6ext = 0;

    if (rth->icmp6fd>0)
        close(rth->icmp6fd);
    rth->icmp6fd = 0;
    return 0;
}

//////////////////////////////
//# vim:ts=4
