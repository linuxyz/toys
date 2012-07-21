#include "slaac6.h"

#include <netinet/icmp6.h>
//#include <linux/icmpv6.h>

#define ICMPV6_MLD2_REPORT      143
#define MLD2_MODE_IS_EXCLUDE    2

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

    return 0;
}

// Using local variant directly!
static struct sockaddr_in6 _saddr;
static struct msghdr _mhdr;
static struct iovec _iov;
static unsigned char   _msg[MAX_MSG_SIZE * 2];
static struct icmp6_hdr* _icmp6 = (struct icmp6_hdr*)_msg;

static int receive_icmp6(int fd)
{
    int len = 0;
    char ipstr[64]; // IP address

    _iov.iov_len = MAX_MSG_SIZE;
    _iov.iov_base = (caddr_t) _msg;

    memset(&_mhdr, 0, sizeof(_mhdr));
    _mhdr.msg_name = (caddr_t)&_saddr;
    _mhdr.msg_namelen = sizeof(_saddr);
    _mhdr.msg_iov = &_iov;
    _mhdr.msg_iovlen = 1;
    _mhdr.msg_control = NULL;
    _mhdr.msg_controllen = 0;

    len = recvmsg(fd, &_mhdr, 0);
    if (len < 0) {
        perror("recvmsg failed:");
        return len;
    }

#ifdef DEBUG
    sprintf(ipstr, "%x:%x:%x:%x:%x:%x:%x:%x",
            ntohs(_saddr.sin6_addr.s6_addr16[0]),
            ntohs(_saddr.sin6_addr.s6_addr16[1]),
            ntohs(_saddr.sin6_addr.s6_addr16[2]),
            ntohs(_saddr.sin6_addr.s6_addr16[3]),
            ntohs(_saddr.sin6_addr.s6_addr16[4]),
            ntohs(_saddr.sin6_addr.s6_addr16[5]),
            ntohs(_saddr.sin6_addr.s6_addr16[6]),
            ntohs(_saddr.sin6_addr.s6_addr16[7]));
    LOG("ICMPv6 from %s type:%d code:%d", ipstr, _msg[0], _msg[1]);
#endif

    /* Impossible.. But let's not take chances */
    if (len > MAX_MSG_SIZE) {
        LOG("Read more data from socket than we can handle. Ignoring it.");
        len = 0;
    }

    return len;
}

int process_icmp6_local(struct slaac_handle* rth)
{
    int len, rtn;

    len = receive_icmp6(rth->icmp6fd);
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

        dump("ND_ROUTER_SOLICIT", _msg, len);

        rtn = sendto(rth->icmp6ext, _msg, len, 0, (struct sockaddr*)&in6addr, sizeof(in6addr));
        if (rtn<len) {
            perror("Error! sendto(MC_ALL_ROUTERS)");
        }
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
        dump("ICMPV6_MLD2_REPORT", _msg, len);

        pos = 8;
        nmcast = ntohs(_icmp6->icmp6_data16[1]);
        for (i=0;i<nmcast && len>=pos+20;
            //   FIX LEN + AUX        + All Source Addresses
            pos += 20 + _msg[pos+1]*4 + _msg[pos+2]*256*16 + _msg[pos+3]*16, i++) {

            // only exclude mode is right
            if (_msg[pos]!=MLD2_MODE_IS_EXCLUDE)
                continue;
            // Test the multicast group
            if (memcmp(_msg+pos+4, &snma, 13)!=0) {
                continue;
            }
            LOG("Add to Solicited-node Multicast Group");
            memcpy(mreq.ipv6mr_multiaddr.s6_addr, _msg+pos+4, 16);
            if (setsockopt(rth->icmp6fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP)");
        }

        return len;
    }

    /* Add to neigh proxy */
    if (_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT && len>=24) {

        // Only do Global Unicast IPv6 Address range is 2000::/3
        if (((unsigned char)(_msg[8]) & 0xE0) != 0x20) {
            // It isn't global unicast IPv6
            return len;
        }
    
        dump("NEIGHBOR_SOLICIT", _msg, len);

        rtn = neighor_addproxy(rth, (struct in6_addr*)(_msg+8));
        LOG("add neigh proxy return: %d", rtn);
        return rtn;
    }

    /* Add to neigh proxy, OSX is using Neighbor Advert */
    if (_icmp6->icmp6_type == ND_NEIGHBOR_ADVERT && len>=24) {
    
        // Only handle the unsigned IPv6 messages
        if (   _saddr.sin6_addr.s6_addr32[0] != 0
            || _saddr.sin6_addr.s6_addr32[1] != 0
            || _saddr.sin6_addr.s6_addr32[2] != 0
            || _saddr.sin6_addr.s6_addr32[3] != 0 )
        {
            return len;
        }

        dump("NEIGHBOR_ADVERT", _msg, len);

        // Only do Global Unicast IPv6 Address range is 2000::/3
        if (((unsigned char)(_msg[8]) & 0xE0) != 0x20) {
            // It isn't global unicast IPv6
            return len;
        }
    
        rtn = neighor_addproxy(rth, (struct in6_addr*)(_msg+8));
        LOG("add neigh proxy return: %d", rtn);
        return rtn;
    }

    return len;
}

int process_icmp6_ext(struct slaac_handle* rth)
{
    int len, rtn;

    len = receive_icmp6(rth->icmp6ext);
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

        dump("ND_ROUTER_ADVERT", _msg, len);

        rtn = sendto(rth->icmp6fd, _msg, len, 0, (struct sockaddr*)&in6addr, sizeof(in6addr));
        if (rtn<len) {
            perror("Error! sendto(MC_ALL_NODES)");
        }
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
