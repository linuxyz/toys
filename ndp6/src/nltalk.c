#include "slaac6.h"

#include <linux/rtnetlink.h>

static struct nl_handle {
    // NetLink
    int    nlfd;
    struct sockaddr_nl    local;
    struct sockaddr_nl    peer;
    __u32  seq;
    __u32  dump;
    int    if_wan;
    int    if_lan;
} handle_;

static int rtnl_talk(struct nlmsghdr *n, struct nlmsghdr *answer)
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

    n->nlmsg_seq = seq = ++handle_.seq;

    if (answer == NULL)
        n->nlmsg_flags |= NLM_F_ACK;

    DUMP("nladdr", &nladdr, sizeof(nladdr));
    DUMP("nlmsg", n, n->nlmsg_len);

    /*msg here*/
    status = sendmsg(handle_.nlfd, &msg, 0);
    if (status < 0) {
        perror("RTNETLINK: Cannot talk to rtnetlink");
        return -__LINE__;;
    }

    memset(buf,0,sizeof(buf));
    iov.iov_base = buf;

    while (1) {
        iov.iov_len = sizeof(buf);
        status = recvmsg(handle_.nlfd, &msg, 0);
        LOG("RTNETLINK: recvmsg %d length:%d", status, msg.msg_namelen);

        if (status < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;

            perror("RTNETLINK: receive error");
            return -__LINE__;;
        }
        if (status == 0) {
            perror("RTNETLINK: EOF on netlink");
            return -__LINE__;;
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
                    return -__LINE__;;
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
                return -__LINE__;;
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

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

int netlink_addroute(struct in6_addr *ip6)
{
    struct {
    	struct nlmsghdr 	n;
    	struct rtmsg 		r;
    	char   			buf[1024];
    } req;
    int val, rtn = 0;
    
    memset(&req, 0, sizeof(req));
    
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_type = RTM_NEWROUTE;
    req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
    req.n.nlmsg_pid = 0;
    req.r.rtm_family = AF_INET6;
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_protocol = RTPROT_STATIC;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE; // RT_SCOPE_LINK should work as well.
    req.r.rtm_type = RTN_UNICAST;
    req.r.rtm_dst_len = 128;	// this is host only
    // prefix
    addattr_l(&req.n, sizeof(req), RTA_DST, ip6, sizeof(*ip6));
    // dev br-lan
    val = handle_.if_lan;
    addattr_l(&req.n, sizeof(req), RTA_OIF, &val, sizeof(int));
    // metric - the hardcoded 200 is greater than the default 256 
    val = 200;
    addattr_l(&req.n, sizeof(req), RTA_PRIORITY, &val, sizeof(int));

    // Netlink talk to kernel
    rtn = rtnl_talk(&req.n, 0);
    if (rtn < 0)
        LOG("RTNETLINK: add route - Error!");
    else 
    	LOG("RTNETLINK: add route - succeeded!");
	return rtn;
}

int netlink_addproxy(struct in6_addr *ip6)
{
    struct {
        struct nlmsghdr    n;
        struct ndmsg    ndm;
        char            buf[256];
    } req;
    int rtn;
    
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.n.nlmsg_type = RTM_NEWNEIGH;
    req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
    req.n.nlmsg_pid = 0;
    req.ndm.ndm_family = AF_INET6;
    req.ndm.ndm_ifindex = handle_.if_wan;
    req.ndm.ndm_state = NUD_PERMANENT;
    req.ndm.ndm_flags = NTF_PROXY;

    //LOG("PROXY LAN:%d to WAN:%d", rth.if_lan, rth.if_wan);
    addattr_l(&req.n, sizeof(req), NDA_DST, ip6, sizeof(*ip6));

    // Netlink talk to kernel
    rtn = rtnl_talk(&req.n, 0);
    if (rtn < 0)
        LOG("RTNETLINK: add proxy - Error!");
    else 
    	LOG("RTNETLINK: add proxy - succeeded!");

	return rtn;
}

int netlink_addclient(struct in6_addr *ip6) 
{
	int rtn = netlink_addproxy(ip6);
	if (rtn >= 0) {
		rtn = netlink_addroute(ip6);
	}

	return rtn;
}

int open_netlink_socket(struct slaac_handle* rth)
{
    socklen_t addr_len;
    int iobuf = 4096;

    // Interface index
    handle_.if_wan = rth->if_wan;
    handle_.if_lan = rth->if_lan;

    handle_.nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (handle_.nlfd < 0) {
        perror("Cannot open netlink socket");
        return -__LINE__;;
    }

    if (setsockopt(handle_.nlfd,SOL_SOCKET,SO_SNDBUF,&iobuf,sizeof(iobuf)) < 0) {
        perror("SO_SNDBUF");
        return -__LINE__;;
    }

    if (setsockopt(handle_.nlfd,SOL_SOCKET,SO_RCVBUF,&iobuf,sizeof(iobuf)) < 0) {
        perror("SO_RCVBUF");
        return -__LINE__;;
    }

    memset(&handle_.local, 0, sizeof(handle_.local));
    handle_.local.nl_family = AF_NETLINK;
    handle_.local.nl_groups = 0; //subscriptions;

    if (bind(handle_.nlfd, (struct sockaddr*)&handle_.local, sizeof(handle_.local)) < 0) {
        perror("Cannot bind netlink socket");
        return -__LINE__;;
    }
    addr_len = sizeof(handle_.local);
    if (getsockname(handle_.nlfd, (struct sockaddr*)&handle_.local, &addr_len) < 0) {
        perror("Cannot getsockname");
        return -__LINE__;;
    }
    if (addr_len != sizeof(handle_.local)) {
        LOG("Wrong address length %d\n", addr_len);
        return -__LINE__;;
    }
    if (handle_.local.nl_family != AF_NETLINK) {
        LOG("Wrong address family %d\n", handle_.local.nl_family);
        return -__LINE__;;
    }
    handle_.seq = 31415; // time(NULL);
    return 0;
}

//////////////////////////////
//# vim:ts=4
