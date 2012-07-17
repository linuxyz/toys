#include "slaac6.h"

int open_icmp_socket(struct slaac_handle* rth)
{
    int sock, err, optval;
    struct sockaddr_in6 in6addr;
    struct icmp6_filter xfilter;
    struct ipv6_mreq mreq;
    
    sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0)
    {
        perror("Can't create socket(PF_INET6/RAW/ICMPV6):");
        return (-1);
    }
    LOG("Created PF_INET6 socket OK.");

    // Bind the socket to the interface we're interested in
    memset(&in6addr, 0, sizeof(in6addr));
    in6addr.sin6_family = AF_INET6;
    in6addr.sin6_scope_id = rth->if_lan; //if_nametoindex(lan);
    err=bind(sock, (struct sockaddr *)&in6addr, sizeof(in6addr));
    if (err < 0)
    {
        perror("packet socket bind return failed:");
        return (-1);
    }    
    LOG("ICMPv6 socket bind to interface %d OK", rth->if_lan); //if_nametoindex(lan));
    
    optval = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval)) < 0)
        perror("Error! setsockopt(IPV6_RECVPKTINFO)"); /* XXX err? */

    // Set the ICMPv6 filter
    ICMP6_FILTER_SETBLOCKALL(&xfilter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_SOLICIT, &xfilter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &xfilter);
    ICMP6_FILTER_SETPASS(143, &xfilter); // MLDv2 report
    if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &xfilter, sizeof(xfilter)) <0 )
        perror("Error! setsockopt(ICMP6_FILTER)"); 

    // Join the all nodes multicast group: FF02::1
    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_interface = rth->if_lan;
    mreq.ipv6mr_multiaddr.s6_addr16[0] = htons(0xff02);
    mreq.ipv6mr_multiaddr.s6_addr16[7] = htons(0x01);
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP)"); 

    // Join the MLDv2 multicast group
    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_interface = rth->if_lan;
    mreq.ipv6mr_multiaddr.s6_addr16[0] = htons(0xff02);
    mreq.ipv6mr_multiaddr.s6_addr16[7] = htons(0x16);
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP)"); 
    
    rth->icmp6fd = sock;

    return sock;
}

int process_icmp6(struct slaac_handle* rth, unsigned char *msg) 
{
    struct sockaddr_in6 saddr;
    struct msghdr mhdr;
    struct iovec iov;
    int len; //, idx, pos;
    char ipstr[64];

    iov.iov_len = MAX_MSG_SIZE;
    iov.iov_base = (caddr_t) msg;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)&saddr;
    mhdr.msg_namelen = sizeof(saddr);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = NULL;
    mhdr.msg_controllen = 0;

    len = recvmsg(rth->icmp6fd, &mhdr, 0);

    /* Impossible.. But let's not take chances */
    if (len > MAX_MSG_SIZE) {
        LOG("Read more data from socket than we can handle. Ignoring it.");
    }
    
    if (len < 0) {
        perror("recvmsg failed:");
        return -1;
    }

    sprintf(ipstr, "%x:%x:%x:%x:%x:%x:%x:%x", 
            ntohs(saddr.sin6_addr.s6_addr16[0]),
            ntohs(saddr.sin6_addr.s6_addr16[1]),
            ntohs(saddr.sin6_addr.s6_addr16[2]),
            ntohs(saddr.sin6_addr.s6_addr16[3]),
            ntohs(saddr.sin6_addr.s6_addr16[4]),
            ntohs(saddr.sin6_addr.s6_addr16[5]),
            ntohs(saddr.sin6_addr.s6_addr16[6]),
            ntohs(saddr.sin6_addr.s6_addr16[7]));
    LOG("ICMPv6 from %s type:%d code:%d", ipstr, msg[0], msg[1]);

    // Join the Solicited-Node Multicast Address FF02:0:0:0:0:1:FF00:1
    // You need to mangle the Solicited-Node multicast traffic to it.
    // http://tools.ietf.org/html/rfc4291
    if (msg[0] == 143) { // ICMPV6_MLD2_REPORT 

        struct in6_addr snma = { { { 0xff,2,0,0,0,0,0,0,0,0,0,1,0xff,0,0,0 } } };
        struct ipv6_mreq mreq = { .ipv6mr_interface = rth->if_lan };
    
        // Only handle the unsigned IPv6 messages
        if (   saddr.sin6_addr.s6_addr32[0] != 0
            || saddr.sin6_addr.s6_addr32[1] != 0
            || saddr.sin6_addr.s6_addr32[2] != 0
            || saddr.sin6_addr.s6_addr32[3] != 0 )
        {
            return len;
        }

        dump("MLD2_REPORT", msg, len);

        // Add into multicast group
        //memset(&mreq, 0, sizeof(mreq));
        //mreq.ipv6mr_interface = rth->if_lan;
        if (memcmp(msg+12, &snma, 13)!=0) {
            return len;
        }
        memcpy(mreq.ipv6mr_multiaddr.s6_addr, msg+12, 16);
        if (setsockopt(rth->icmp6fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
            perror("Error! setsockopt(IPV6_ADD_MEMBERSHIP)"); 
        else 
            LOG("Add to Solicited-node Multicast Group");
    }

    /* Add to neigh proxy */
    if (msg[0] == ND_NEIGHBOR_SOLICIT && len>=24) {
        int rtn;
    
        dump("NEIGHBOR_SOLICIT", msg, len);

        // Only do Global Unicast IPv6 Address range is 2000::/3
        if (((unsigned char)(msg[8]) & 0xE0) != 0x20) {
            // It isn't global unicast IPv6
            return len;
        }
    
        rtn = neighor_addproxy(rth, (struct in6_addr*)(msg+8));
        LOG("add neigh proxy return: %d", rtn);
    }

    /* Add to neigh proxy, OSX is using Neighbor Advert */
    if (msg[0] == ND_NEIGHBOR_ADVERT && len>=24) {
        int rtn;
    
        dump("NEIGHBOR_ADVERT", msg, len);

        // Only handle the unsigned IPv6 messages
        if (   saddr.sin6_addr.s6_addr32[0] != 0
            || saddr.sin6_addr.s6_addr32[1] != 0
            || saddr.sin6_addr.s6_addr32[2] != 0
            || saddr.sin6_addr.s6_addr32[3] != 0 )
        {
            return len;
        }

        // Only do Global Unicast IPv6 Address range is 2000::/3
        if (((unsigned char)(msg[8]) & 0xE0) != 0x20) {
            // It isn't global unicast IPv6
            return len;
        }
    
        rtn = neighor_addproxy(rth, (struct in6_addr*)(msg+8));
        LOG("add neigh proxy return: %d", rtn);
    }

    return len;
}

//////////////////////////////
//# vim:ts=4
