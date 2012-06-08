#define _GNU_SOURCE /**/

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <poll.h>

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#ifdef DEBUG
#define LOG(fmt, ...)       fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#define HWADDR_MAX          16
#define MAX_PKT_BUFF        1500
#define MAX_MSG_SIZE        2048
#define INTERFACE_STRLEN    12
#define DISPATCH_TIMEOUT    300000          // milliseconds 300000 = 5 mins

struct rtnl_handle
{
    int    nlfd;
    struct sockaddr_nl    local;
    struct sockaddr_nl    peer;
    __u32  seq;
    __u32  dump;
    int    icmp6fd;
    int    if_wan;
    int    if_lan;
};

static void dump(const char* title, void* msg, int len)
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

static int rtnl_talk(struct rtnl_handle *rtnl, 
            struct nlmsghdr *n, struct nlmsghdr *answer)
{
    int status;
    unsigned seq;
    struct nlmsghdr *h;
    struct sockaddr_nl nladdr;
    struct iovec iov = {
        .iov_base = (void*) n,
        .iov_len = n->nlmsg_len
    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    char   buf[4096];

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    n->nlmsg_seq = seq = ++rtnl->seq;

    if (answer == NULL)
        n->nlmsg_flags |= NLM_F_ACK;

    dump("nladdr", &nladdr, sizeof(nladdr));
    dump("nlmsg", n, n->nlmsg_len);

    /*msg here*/
    status = sendmsg(rtnl->nlfd, &msg, 0);
    if (status < 0) {
        perror("RTNETLINK: Cannot talk to rtnetlink");
        return -1;
    }

    memset(buf,0,sizeof(buf));
    iov.iov_base = buf;

    while (1) {
        iov.iov_len = sizeof(buf);
        status = recvmsg(rtnl->nlfd, &msg, 0);
        LOG("RTNETLINK: recvmsg %d length:%d", status, msg.msg_namelen);

        if (status < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;

            perror("RTNETLINK: receive error");
            return -1;
        }
        if (status == 0) {
            perror("RTNETLINK: EOF on netlink");
            return -1;
        }
        if (msg.msg_namelen != sizeof(nladdr)) {
            LOG("RTNETLINK: warning! sender address length == %d", msg.msg_namelen);
            return -2;
        }

        // There is only one request, 
        for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if (l < 0 || len>status) {
                if (msg.msg_flags & MSG_TRUNC) {
                    LOG("RTNETLINK: Truncated message");
                    return -1;
                }
                LOG("RTNETLINK: !!!malformed message: len=%d", len);
                return -3;
            }

            if (nladdr.nl_pid != 0 ||
                h->nlmsg_pid != 0 ||
                h->nlmsg_seq != seq) {
                /* Don't forget to skip that message. */
                status -= NLMSG_ALIGN(len);
                h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                continue;
            }

            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                if (l < sizeof(struct nlmsgerr)) {
                    LOG("RTNETLINK: ERROR truncated");
                } else {
                    errno = -err->error;
                    if (errno == 0) {
                        if (answer)
                            memcpy(answer, h, h->nlmsg_len);
                        return 0;
                    }
                    perror("RTNETLINK: answers");
                }
                return -1;
            }

            if (answer) {
                memcpy(answer, h, h->nlmsg_len);
                return 0;
            }

            //LOG("Unexpected reply!!!");
            status -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC) {
            LOG("RTNETLINK: Message truncated\n");
            continue;
        }
        if (status) {
            LOG("RTNETLINK: Remnant of size %d\n!!!", status);
        }
        break;
    }
    return 0;
}


#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + RTA_ALIGN((nmsg)->nlmsg_len)))


static int neighor_addproxy(struct rtnl_handle* rth, struct in6_addr* ip6)
{
    struct {
        struct nlmsghdr    n;
        struct ndmsg    ndm;
        char            buf[256];
    } req;
    struct rtattr *rta;
    int len;
    
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.n.nlmsg_type = RTM_NEWNEIGH;
    req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
    req.n.nlmsg_pid = 0;
    req.ndm.ndm_family = AF_INET6;
    req.ndm.ndm_ifindex = rth->if_wan;
    req.ndm.ndm_state = NUD_PERMANENT;
    req.ndm.ndm_flags = NTF_PROXY;

    //LOG("PROXY LAN:%d to WAN:%d", rth.if_lan, rth.if_wan);

    // Adope the IPv6 address into the payload
    len = RTA_LENGTH(16);
    if (NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(len) > sizeof(req)) {
        LOG("RTNETLINK: message exceeded bound of %d\n", sizeof(req));
        return -1;
    }
    rta = NLMSG_TAIL(&(req.n));
    rta->rta_len = len;
    rta->rta_type = NDA_DST;
    memcpy(RTA_DATA(rta), ip6, 16);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(len);
    
    // Netlink talk to kernel
    if (rtnl_talk(rth, &req.n, 0) < 0) {
        LOG("RTNETLINK: Error!");
    }

    return 0;
}

static int open_netlink_socket(struct rtnl_handle *rth) 
{
    socklen_t addr_len;
    int iobuf = 4096;

    rth->nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rth->nlfd < 0) {
        perror("Cannot open netlink socket");
        return -1;
    }

    if (setsockopt(rth->nlfd,SOL_SOCKET,SO_SNDBUF,&iobuf,sizeof(iobuf)) < 0) {
        perror("SO_SNDBUF");
        return -1;
    }

    if (setsockopt(rth->nlfd,SOL_SOCKET,SO_RCVBUF,&iobuf,sizeof(iobuf)) < 0) {
        perror("SO_RCVBUF");
        return -1;
    }

    memset(&rth->local, 0, sizeof(rth->local));
    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = 0; //subscriptions;

    if (bind(rth->nlfd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
        perror("Cannot bind netlink socket");
        return -1;
    }
    addr_len = sizeof(rth->local);
    if (getsockname(rth->nlfd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
        perror("Cannot getsockname");
        return -1;
    }
    if (addr_len != sizeof(rth->local)) {
        LOG("Wrong address length %d\n", addr_len);
        return -1;
    }
    if (rth->local.nl_family != AF_NETLINK) {
        LOG("Wrong address family %d\n", rth->local.nl_family);
        return -1;
    }
    rth->seq = 31415; // time(NULL);
    return 0;
}


static int open_icmp_socket(struct rtnl_handle* rth)
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
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &xfilter);
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

static int process_icmp6(struct rtnl_handle* rth, unsigned char *msg) 
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


static char wan[16] = {"eth1"};
static char lan[16] = {"br-lan"};

int main(int argc, char *argv[])
{
    int             rc;
    struct pollfd   fds[2];
    unsigned int    msglen;
    unsigned char   msgdata[MAX_MSG_SIZE * 2];
    struct rtnl_handle rth = { .nlfd = -1, .icmp6fd = -1, .if_wan = -1, .if_lan = -1 };
    //memset(&rth, 0, sizeof(rth));

    if (argc>=3) {
        rth.if_lan = if_nametoindex(argv[1]);
        rth.if_wan = if_nametoindex(argv[2]);
        LOG("PROXY LAN:%s to WAN:%s", argv[1], argv[2]);
    } else {
        rth.if_lan = if_nametoindex(lan);
        rth.if_wan = if_nametoindex(wan);
        LOG("PROXY LAN:%s to WAN:%s", lan, wan);
    }
    if (rth.if_lan<=0 || rth.if_wan<=0) {
        printf("usage: %s <lan> <wan>\n", argv[0]);
        exit(-1);
    }
    LOG("PROXY LAN:%d to WAN:%d", rth.if_lan, rth.if_wan);

    rc = open_netlink_socket(&rth);
    if (rc<0) {
        LOG("Can't create NETLINK socket: %d", rc); 
        exit (-2);
    }

    rc = open_icmp_socket(&rth);
    if (rc<0) {
        LOG("Can't create ICMPv6 socket: %d", rc);
        exit(-3);
    }

    memset(fds, 0, sizeof(fds));
    fds[0].fd = rth.icmp6fd; // socklan;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = -1;
    fds[1].events = 0;
    fds[1].revents = 0;

    for (;;)
    {
        rc = poll(fds, sizeof(fds)/sizeof(fds[0]), DISPATCH_TIMEOUT);

        if (rc > 0)
        {
            if (   fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)
                || fds[1].revents & (POLLERR | POLLHUP | POLLNVAL) )
            {
                LOG("Major socket error on fds[0 or 1].fd");
                // Try and recover
                close(rth.icmp6fd);
                // Allow a moment for things to maybe return to normal...
                sleep(1);
                rc = open_icmp_socket(&rth);
                if (rc<0) {
                    LOG("open_icmp_sockets: failed to reinitialise one or both sockets.");
                    exit(1);
                }
                memset(fds, 0, sizeof(fds));
                fds[0].fd = rth.icmp6fd;
                fds[0].events = POLLIN;
                fds[0].revents = 0;
                fds[1].fd = -1;
                fds[1].events = 0;
                fds[1].revents = 0;
                continue;
            }
            else if (fds[0].revents & POLLIN)
            {
                msglen = process_icmp6(&rth, msgdata);
                // msglen is checked for sanity already within get_rx()
                LOG("process_icmp6() gave msg with len = %d", msglen);

                continue;
            }
            else if ( rc == 0 )
            {
                LOG("Timer event");
                // Timer fired?
                // One day. If we implement timers.
            }
            else if ( rc == -1 )
            {
                LOG("Weird poll error: %s", strerror(errno));
                continue;
            }

            LOG("Timed out of poll(). Timeout was %d ms", DISPATCH_TIMEOUT);
        }
    }

    return (0);
}

//////////////////////////////
//# vim:ts=4

