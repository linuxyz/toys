#include "slaac6.h"

static int rtnl_talk(struct slaac_handle *rtnl, 
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


int neighor_addproxy(struct slaac_handle* rth, struct in6_addr* ip6)
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
        LOG("RTNETLINK: message exceeded bound of %lu\n", sizeof(req));
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

int open_netlink_socket(struct slaac_handle *rth) 
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

//////////////////////////////
//# vim:ts=4
