#include "slaac6.h"

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


static char wan[16] = {"eth1"};
static char lan[16] = {"br-lan"};

int main(int argc, char *argv[])
{
    int             rc;
    struct pollfd   fds[2];
    unsigned int    msglen;
    unsigned char   msgdata[MAX_MSG_SIZE * 2];
    struct slaac_handle rth = { .nlfd = -1, .icmp6fd = -1, .if_wan = -1, .if_lan = -1 };
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

