#define _GNU_SOURCE /**/

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stddef.h>
#include <poll.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>

//#define LOG_ERR			stderr
//#define LOG_DEBUG		stderr
//#define LOG	fprintf
//#define LOG(...)        fprintf(stderr, __VA_ARGS__)
#define LOG(fmt, ...)        fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define HWADDR_MAX          16
#define MAX_PKT_BUFF        1500
#define MAX_MSG_SIZE        2048
#define INTERFACE_STRLEN    12
#define DISPATCH_TIMEOUT    300000          // milliseconds 300000 = 5 mins

int open_icmp_socket(const char* lan)
{
    int sock, err, optval;
    //struct sockaddr_ll lladdr;
    struct sockaddr_in6 in6addr;

    sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0)
    {
        LOG("Can't create socket(PF_INET6/RAW/ICMPV6): %s", strerror(errno));
        return (-1);
    }
    LOG("Created PF_INET6 socket OK.");

    // Bind the socket to the interface we're interested in
    memset(&in6addr, 0, sizeof(in6addr));
    in6addr.sin6_family = AF_INET6;
    in6addr.sin6_scope_id = if_nametoindex(lan);
    err=bind(sock, (struct sockaddr *)&in6addr, sizeof(in6addr));
    if (err < 0)
    {
        LOG("packet socket bind return %d failed: %s", err, strerror(errno));
        return (-1);
    }    
    LOG("packet socket bind to interface %d OK", if_nametoindex(lan));
    
	optval = 1;
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval)) < 0)
		LOG("Error! setsockopt(IPV6_RECVPKTINFO)"); /* XXX err? */
#else  /* old adv. API */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &optval, sizeof(optval)) < 0)
		LOG("Error! setsockopt(IPV6_PKTINFO)"); /* XXX err? */
#endif

    return sock;
}


int get_rx(int socklan, unsigned char *msg) 
{
    struct sockaddr_in6 saddr;
    struct msghdr mhdr;
    struct iovec iov;
    int len, idx, pos;
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

    len = recvmsg(socklan, &mhdr, 0);

    /* Impossible.. But let's not take chances */
    if (len > MAX_MSG_SIZE)
    {
        LOG("Read more data from socket than we can handle. Ignoring it.");
        return -1;
    }
    
    if (len < 0)
    {
        if (errno != EINTR)
            LOG("recvmsg failed with: %s", strerror(errno));
        return -1;
    }

    /* print address */
    for(pos=0,idx=0;pos<7;++pos) {
        idx += sprintf(ipstr+idx, "%x:", ntohs(saddr.sin6_addr.s6_addr16[pos]));
    }
    sprintf(ipstr+idx, "%x", ntohs(saddr.sin6_addr.s6_addr16[7]));
    LOG("ICMPv6 from %s type:%d code:%d", ipstr, msg[0], msg[1]);


    return len;
}

int main(int argc, char *argv[])
{
    int             socklan;
    int             rc;
    struct pollfd   fds[2];
    unsigned int    msglen;
    unsigned char   msgdata[MAX_MSG_SIZE * 2];

	socklan = open_icmp_socket(argv[1]);
	if (socklan<=0) {
		LOG("Can't create ICMPv6 socket: %d", socklan);
		return (-1);
	}

    memset(fds, 0, sizeof(fds));
    fds[0].fd = socklan;
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
                close(socklan);
                // Allow a moment for things to maybe return to normal...
                sleep(1);
                socklan = open_icmp_socket(argv[1]);
                if (socklan<=0)
                {
                    LOG("open_icmp_sockets: failed to reinitialise one or both sockets.");
                    exit(1);
                }
                memset(fds, 0, sizeof(fds));
                fds[0].fd = socklan;
                fds[0].events = POLLIN;
                fds[0].revents = 0;
                fds[1].fd = -1;
                fds[1].events = 0;
                fds[1].revents = 0;
                continue;
            }
            else if (fds[0].revents & POLLIN)
            {
                msglen = get_rx(socklan, msgdata);
                // msglen is checked for sanity already within get_rx()
                LOG("get_rx() gave msg with len = %d", msglen);

                // Have processNS() do the rest of validation and work...
                //processNS(msgdata, msglen);
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
