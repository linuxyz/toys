#include "slaac6.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/icmp6.h>
//#include <linux/icmpv6.h>

#define ICMPV6_MLD2_REPORT      143
#define MLD2_MODE_IS_EXCLUDE    2
#define MLD2_CHANGE_TO_EXCLUDE  4


// Router Advert
struct ra_msg_t {
    struct nd_router_advert   hdr;
    struct nd_opt_prefix_info prefix;
    struct nd_opt_mtu mtu;
    unsigned char   src[8];
    struct icmp6_opt {
        unsigned char   type;
        unsigned char   length; // should less than 32
        unsigned short  reserved; // 0
        unsigned int    lifetime; //
        struct in6_addr servers[3];
    } rdnss;
};

static struct ra_msg_t ra_msg_ = {
    .hdr = { .nd_ra_hdr = {.icmp6_type = 0}}
};

static struct sockaddr_in6 ip6_allnodes_;
static struct sockaddr_in6 ip6_allrouters_;

int prepare_icmp6_ra(struct slaac_handle* rth)
{
    if (ra_msg_.hdr.nd_ra_hdr.icmp6_type == ND_ROUTER_ADVERT)
        return 0;

    memset(&ra_msg_, 0, sizeof(ra_msg_));

    // MESSAGE
    //ra_msg_.hdr.nd_ra_hdr.icmp6_type = ND_ROUTER_ADVERT;
    ra_msg_.hdr.nd_ra_hdr.icmp6_code = 0;
    ra_msg_.hdr.nd_ra_curhoplimit = 64;
    ra_msg_.hdr.nd_ra_flags_reserved = 0;
    ra_msg_.hdr.nd_ra_router_lifetime = htons(RA_RETRANS_TIMER*3); //htons(1800);
    ra_msg_.hdr.nd_ra_reachable =  htonl(30000);
    ra_msg_.hdr.nd_ra_retransmit = htonl(1000);

    // option source MAC address
    ra_msg_.src[0] = 1;
    ra_msg_.src[1] = 1;
    memcpy(ra_msg_.src+2, rth->lladdr_lan, 6); // MAC address
    // prefix data
    ra_msg_.prefix.nd_opt_pi_type = 3;
    ra_msg_.prefix.nd_opt_pi_len = 4;
    ra_msg_.prefix.nd_opt_pi_prefix_len = 64;
    ra_msg_.prefix.nd_opt_pi_flags_reserved = 0xC0;
    ra_msg_.prefix.nd_opt_pi_valid_time = htonl(604800);
    ra_msg_.prefix.nd_opt_pi_preferred_time = htonl(86400);
    if (inet_pton(AF_INET6, rth->ip6pfx, &(ra_msg_.prefix.nd_opt_pi_prefix))>0) {
        // User specify a valid prefix - enable the cache
        ra_msg_.hdr.nd_ra_hdr.icmp6_type = ND_ROUTER_ADVERT;
    }
    // MTC
    ra_msg_.mtu.nd_opt_mtu_type = 5;
    ra_msg_.mtu.nd_opt_mtu_len = 1;
    ra_msg_.mtu.nd_opt_mtu_mtu = htons(1500);
    // RDNSS
    ra_msg_.rdnss.type = 25;
    ra_msg_.rdnss.length = 7;
    ra_msg_.rdnss.reserved = 0;
    ra_msg_.rdnss.lifetime = htonl(1500);
    inet_pton(AF_INET6, "2001:470:20::2", &(ra_msg_.rdnss.servers[0])); //, sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2001:4860:4860::8888", &(ra_msg_.rdnss.servers[1])); //, sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2620:0:ccc::2", &(ra_msg_.rdnss.servers[2])); //, sizeof(struct in6_addr));

    // LOCAL ALL NODE
    memset(&ip6_allnodes_, 0, sizeof(ip6_allnodes_));
    ip6_allnodes_.sin6_family = AF_INET6;
    ip6_allnodes_.sin6_scope_id = rth->if_lan; //if_nametoindex(lan);
    ip6_allnodes_.sin6_addr.s6_addr[ 0] = 0xff;
    ip6_allnodes_.sin6_addr.s6_addr[ 1] = 0x02;
    ip6_allnodes_.sin6_addr.s6_addr[15] = 0x01;

    // LOCAL ALL NODE
    memset(&ip6_allrouters_, 0, sizeof(ip6_allnodes_));
    ip6_allrouters_.sin6_family = AF_INET6;
    ip6_allrouters_.sin6_scope_id = rth->if_wan; //if_nametoindex(wan);
    ip6_allrouters_.sin6_addr.s6_addr[ 0] = 0xff;
    ip6_allrouters_.sin6_addr.s6_addr[ 1] = 0x02;
    ip6_allrouters_.sin6_addr.s6_addr[15] = 0x02;

    return sizeof(ra_msg_); // - sizeof(ra_msg_.rdnss);
}

int icmp6_ra_broadcast(struct slaac_handle* rth)
{
    int rtn = 0;

    // ensure there is a valid RA message
    if (ra_msg_.hdr.nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT)
        return rtn;

    rtn = sendto(rth->icmp6fd, &ra_msg_, sizeof(ra_msg_), 0, (struct sockaddr*)&ip6_allnodes_, sizeof(ip6_allnodes_));
    LOG("ROUTER ADVERT: %d", rtn);
    if (rtn< sizeof(ra_msg_)) {
        perror("Error! sendto(MC_ALL_NODES)");
    }

    return rtn;
}

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

    // Set the Hop Limits to 255
    optval = 255;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &optval, sizeof(optval)) <0 )
        perror("setsockopt IPV6_UNICAST_HOPS");
    optval = 255;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &optval, sizeof(optval)) <0 )
        perror("setsockopt IPV6_UNICAST_HOPS");

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
    struct ifreq    req;
    struct icmp6_hdr icmp6_rs;
    unsigned char icmp6_src[8];

    // Set the ICMPv6 filter
    ICMP6_FILTER_SETBLOCKALL(&xfilter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &xfilter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_SOLICIT, &xfilter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &xfilter);
    //ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &xfilter);
    ICMP6_FILTER_SETPASS(ICMPV6_MLD2_REPORT, &xfilter); // MLDv2 report
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

    // Get the MAC addresses
    strcpy(req.ifr_name, rth->ifn_lan);
    if (ioctl(rth->icmp6fd, SIOCGIFHWADDR, &req)<0) {
        perror("Unable to get the MAC address of LAN");
        close_icmp_socket(rth);
        return -__LINE__;
    }
    memcpy(rth->lladdr_lan, req.ifr_hwaddr.sa_data, 6);

    // Get the MAC addresses
    strcpy(req.ifr_name, rth->ifn_wan);
    if (ioctl(rth->icmp6ext, SIOCGIFHWADDR, &req)<0) {
        perror("Unable to get the MAC address of WAN");
        close_icmp_socket(rth);
        return -__LINE__;
    }
    memcpy(rth->lladdr_wan, req.ifr_hwaddr.sa_data, 6);

    DUMP("WAN MAC", rth->lladdr_wan, 6);
    DUMP("LAN MAC", rth->lladdr_lan, 6);

    // Prepare the ROUTER ADVERT message
    prepare_icmp6_ra(rth);

    // Send ROUTER Solicit
    memset(&icmp6_rs, 0, sizeof(icmp6_rs));
    icmp6_rs.icmp6_type = ND_ROUTER_SOLICIT;
    icmp6_src[0] = 1;   // option src address
    icmp6_src[1] = 1;   // option length
    memcpy(icmp6_src+2, rth->lladdr_wan, 6);    // MAC address
    return sendto(rth->icmp6ext, &icmp6_rs, sizeof(icmp6_rs)+sizeof(icmp6_src), 0,
                  (struct sockaddr*)&ip6_allrouters_, sizeof(ip6_allrouters_));
}

// Using local variant directly!

static int receive_icmp6(int fd, struct sockaddr_in6* addr, unsigned char* msg)
{
    struct iovec iov;
    struct msghdr mhdr;
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
    {
        char ipstr[64]; // IP address
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
    }
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
    struct sockaddr_in6 saddr;
    unsigned char msg[MAX_MSG_SIZE * 2];
    struct icmp6_hdr* _icmp6 = (struct icmp6_hdr*)msg;

    len = receive_icmp6(rth->icmp6fd, &saddr, msg);
    if (len<=0)
        return len;

    // Handle the Router Solicited request - Response to host only
    if (_icmp6->icmp6_type == ND_ROUTER_SOLICIT) {
        // ignore it if there isn't ROUTER ADVERT,
        if (ra_msg_.hdr.nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT)
            return len;

        // Response RA
        rtn = sendto(rth->icmp6fd, &ra_msg_, sizeof(ra_msg_), 0, (struct sockaddr*)&saddr, sizeof(saddr));
        LOG("Response local default ROUTER ADVERT: %d", rtn);
        if (rtn< sizeof(ra_msg_)) {
            perror("Error! sendto(Link Local Host)");
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
        DUMP("<--ICMPV6_MLD2_REPORT", msg, len);

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
            DUMP("ADD_MEMBERSHIP: ", msg+pos+4, 16);
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
    
        DUMP("<--NEIGHBOR_SOLICIT", msg, len);

        rtn = neighor_addproxy((struct in6_addr*)(msg+8));
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

        DUMP("<--NEIGHBOR_ADVERT", msg, len);

        // Only do Global Unicast IPv6 Address range is 2000::/3
        if (((unsigned char)(msg[8]) & 0xE0) != 0x20) {
            // It isn't global unicast IPv6
            return len;
        }
    
        rtn = neighor_addproxy((struct in6_addr*)(msg+8));
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
    int len;

    len = receive_icmp6(rth->icmp6ext, &saddr, msg);
    if (len<=0)
        return len;

    // Handle the Router Advert forward to all nodes
    if (_icmp6->icmp6_type == ND_ROUTER_ADVERT) {
        int pos = 16;

        DUMP("-->ND_ROUTER_ADVERT", msg, len);

        LOG("Save ROUTER ADVERT message!");
        while (pos < len) {
            // this is the prefix data
            if ((msg[pos]==3)  && msg[pos+1]==4) {
                memcpy(&(ra_msg_.prefix), msg+pos, 32); // prefix is a fix length
                // Enable the Router Advert
                ra_msg_.hdr.nd_ra_hdr.icmp6_type = ND_ROUTER_ADVERT;
                LOG("IPv6 Router prefix info updated!");
                break;
            }

            if (msg[pos+1]==0)
                pos += 8;
            else
                pos += msg[pos+1] * 8;
        }

        // SEND
        icmp6_ra_broadcast(rth);
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
