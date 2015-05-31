/*
    cpu packet handler
*/
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>

#include <pthread.h>

typedef struct bfnl_intf_ {
    char name[128];
    char peer_name[128];
    int fd;
    char mac_addr[6];
} bfnl_intf_t;

typedef struct __attribute__((__packed__)) bfnl_cpu_header_ {
    union {
        struct {
            uint16_t ether_type        : 16;

            uint8_t fabric_qos         : 8;
            uint8_t pad                : 1;
            uint8_t pkt_version        : 2;
            uint8_t type               : 3;
            uint8_t hdr_version        : 2;

            uint16_t lif               : 16;
            uint16_t bridge_domain     : 16;

            uint16_t bypass_ingress    : 1;
            uint16_t egress_queue      : 5;
            uint16_t reserved          : 10;

            uint16_t egress_port       : 16;
        } d;
        struct {
            uint16_t w0;
            uint16_t w1;
            uint16_t w2;
            uint16_t w3;
            uint16_t w4;
            uint16_t w5;
        } w;
    };
} bfnl_cpu_header_t;

#define BFNL_NUM_INTERFACES 4
static bfnl_intf_t g_intf[] = {
    {"swp1",    "veth1", 0, ""},
    {"swp2",    "veth3", 0, ""},
    {"swp3",    "veth5", 0, ""},
    {"swp4",    "veth7", 0, ""},
    {"veth251", "veth250",  0, ""},
};
static char *g_cpu_intf_name = "veth251";
static uint32_t g_cpu_intf_ifindex = 0;
static int g_sock_fd = -1;
static int g_nlsk_fd = -1;
static struct nl_sock *g_nlsk = NULL;
static bool g_verbose = false;

static void
bfnl_swap_cpu_header(bfnl_cpu_header_t *hdr, bool flag) {
    if (flag) {
        hdr->w.w0 = ntohs(hdr->w.w0);
        hdr->w.w1 = ntohs(hdr->w.w1);
        hdr->w.w2 = ntohs(hdr->w.w2);
        hdr->w.w3 = ntohs(hdr->w.w3);
        hdr->w.w4 = ntohs(hdr->w.w4);
        hdr->w.w5 = ntohs(hdr->w.w5);
    } else {
        hdr->w.w0 = htons(hdr->w.w0);
        hdr->w.w1 = htons(hdr->w.w1);
        hdr->w.w2 = htons(hdr->w.w2);
        hdr->w.w3 = htons(hdr->w.w3);
        hdr->w.w4 = htons(hdr->w.w4);
        hdr->w.w5 = htons(hdr->w.w5);
    }
}

static void
bfnl_process_packet_from_user(int intf) {
    int ret, fd, i;
    static char in_buf[10000];
    static char out_buf[10000];

    // read packet from switch port
    fd = g_intf[intf].fd;
    while((ret = read(fd, in_buf, sizeof(in_buf))) > 0) {
        if (g_verbose) {
            for(i = 0; i < ret;) {
                printf("%02X", (unsigned char)in_buf[i]);
                i++;
                if (i && ((i % 16) == 0))  {
                    printf("\n");
                } else if (i && ((i % 8) == 0)) {
                    printf("  ");
                } else {
                    printf(" ");
                }
            }
            printf("\n\n");
        }

        // ignore the packet if it is not sourced from one of the
        // device's interface
        char *src_mac_addr = in_buf + 6;
        int i = 0;
        bool src_found = false;
        for (i = 0; i < BFNL_NUM_INTERFACES; i++) {
            if (memcmp(src_mac_addr, g_intf[i].mac_addr, 6) == 0) {
                src_found = true;
                break;
            }
        }
        if (!src_found) {
            printf("Dropped %d bytes from %s\n", ret, g_intf[intf].name);
            continue;
        }

        // create metaheader
        bfnl_cpu_header_t meta_hdr;
        memset(&meta_hdr, 0, sizeof(meta_hdr));
        meta_hdr.d.type = 4;
        meta_hdr.d.pad = 0;
        meta_hdr.d.ether_type = 0x9000;
        meta_hdr.d.egress_port = intf + 1;
        meta_hdr.d.bypass_ingress = 1;

        // convert to network byte order;
        bfnl_swap_cpu_header(&meta_hdr, 0);

        // copy eth src and dst
        memcpy(out_buf, in_buf, 12);
        // insert metaheader
        memcpy(out_buf+12, &meta_hdr, sizeof(meta_hdr));
        // copy rest of the packet
        memcpy(out_buf+12+sizeof(meta_hdr), in_buf+12, ret-12);

        // write to cpu interface of model
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(addr));
        addr.sll_ifindex = g_cpu_intf_ifindex;
        if (sendto(g_sock_fd, out_buf, ret+sizeof(meta_hdr), 0,
                   (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("sendto");
        }
        printf("switched %d bytes from %s to %s\n", ret, g_intf[intf].name,
               g_cpu_intf_name);
    }
}

static void
bfnl_process_packet_from_tofino() {
    int ret, fd, i, rv;
    static char in_buf[10000];
    static char out_buf[10000];

    // read packet from cpu port
    fd = g_sock_fd;
    while((ret = read(fd, in_buf, sizeof(in_buf))) > 0) {
        if (g_verbose) {
            for(i = 0; i < ret;) {
                printf("%02X", (unsigned char)in_buf[i]);
                i++;
                if (i && ((i % 16) == 0))  {
                    printf("\n");
                } else if (i && ((i % 8) == 0)) {
                    printf("  ");
                } else {
                    printf(" ");
                }
            }
            printf("\n\n");
        }

        bfnl_cpu_header_t *meta_hdr;
        meta_hdr = (bfnl_cpu_header_t *)(in_buf + 12);

        // convert cpu header to host format
        bfnl_swap_cpu_header(meta_hdr, 1);
        uint32_t out_intf = meta_hdr->d.lif;
        if(out_intf >= BFNL_NUM_INTERFACES) {
            printf("Invalid out_intf %d\n", out_intf);
            continue;
        }
        out_intf--;

        // create output packet
        memcpy(out_buf, in_buf, 12);
        memcpy(out_buf+12, in_buf + 12 + sizeof(bfnl_cpu_header_t),
               ret-(12+sizeof(bfnl_cpu_header_t)));

        // write to switch port interface
        if ((rv=write(g_intf[out_intf].fd, out_buf,
                  ret-sizeof(bfnl_cpu_header_t))) < 0) {
            printf("sendto failed %d\n", rv);
            perror("sendto");
        }

        printf("switched %ld bytes from %s to %s\n",
               ret-sizeof(bfnl_cpu_header_t), g_cpu_intf_name,
               g_intf[out_intf].name);
    }
}

static int
bfnl_tunnel_alloc(int intf) {
    int fd, err;
    char *dev = g_intf[intf].name;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    // open the tap interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("tunsetiff");
        close(fd);
        return err;
    }

    // set connection to be non-blocking
    int sock_flags = fcntl(fd, F_GETFL, 0);
    if ((err = fcntl(fd, F_SETFL, sock_flags | O_NONBLOCK)) < 0) {
        perror("f_setfl");
        close(fd);
        return err;
    }

    // fetch the mac address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, SIOCGIFHWADDR, (void *)&ifr)) < 0) {
        perror("ioctl");
        close(fd);
        return err;
    }
    int i;
    for (i = 0; i < 6; i++) {
        g_intf[intf].mac_addr[i] = ifr.ifr_addr.sa_data[i];
    }

    return fd;
}

static void
bfnl_packetd_init() {
    int i;

    // initialize raw socket
    if ((g_sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("failed to open raw socket");
        exit(1);
    }

    // initialize cpu port
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, g_cpu_intf_name, IFNAMSIZ);
    if (ioctl(g_sock_fd, SIOCGIFINDEX, (void *)&ifr) < 0) {
        perror("failed to get ifindex of cpu interface");
        exit(1);
    }
    g_cpu_intf_ifindex = ifr.ifr_ifindex;

    // bind to cpu port
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = g_cpu_intf_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(g_sock_fd, (struct sockaddr *)&addr,
             sizeof(struct sockaddr_ll)) < 0) {
        perror("bind to cpu interface failed");
        exit(1);
    }

    // set cpu port to be non-blocking
    int sock_flags = fcntl(g_sock_fd, F_GETFL, 0);
    if (fcntl(g_sock_fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
        perror("f_setfl on cpu interface failed");
        exit(1);
    }

    // initialize switch ports
    for (i = 0; i < BFNL_NUM_INTERFACES; i++) {
        g_intf[i].fd = bfnl_tunnel_alloc(i);
        assert(g_intf[i].fd > 0);
    }
}

static void
bfnl_process_link_msg(struct nlmsghdr *nlmsg) {
    int hdrlen, attrlen;
    struct nlattr *attr;
    bool mac_addr_valid = false;
    uint64_t lladdr;
    char link_name[128];

    hdrlen = sizeof(struct ifinfomsg);
    attrlen = nlmsg_attrlen(nlmsg, hdrlen);
    attr = nlmsg_attrdata(nlmsg, hdrlen);
    while (nla_ok(attr, attrlen)) {
       int attr_type = nla_type(attr);
        switch (attr_type) {
            case IFLA_IFNAME:
                strncpy(link_name, nla_get_string(attr), 128);
                break;
            case IFLA_ADDRESS: {
                mac_addr_valid = true;
                lladdr = nla_get_u64(attr);
                break;
            }
            default:
                break;
        }
        attr = nla_next(attr, &attrlen);
    }

    if (mac_addr_valid) {
        int i;
        for(i = 0; i < BFNL_NUM_INTERFACES; i++) {
            if (strncmp(g_intf[i].name, link_name, 128) == 0) {
                memcpy(g_intf[i].mac_addr, &lladdr, 6);
            }
        }
    }
}

static int
bfnl_process_netlink_msg(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nlmsg = nlmsg_hdr(msg);
    int nlmsg_sz = nlmsg_get_max_size(msg);
    while (nlmsg_ok(nlmsg, nlmsg_sz)) {
        if (nlmsg->nlmsg_type == RTM_NEWLINK) {
            bfnl_process_link_msg(nlmsg);
        }
        nlmsg = nlmsg_next(nlmsg, &nlmsg_sz);
    }
    return 0;
}

static void
cleanup_nl_sock(struct nl_sock *nlsk) {
    // free the socket
    nl_socket_free(nlsk);
}

static void
bfnl_nl_sock_init() {
    int sock_flags;

    // allocate a new socket
    g_nlsk = nl_socket_alloc();
    if (g_nlsk == NULL) {
        perror("nl_socket_alloc");
        return;
    }

    // disable sequence number checking
    nl_socket_disable_seq_check(g_nlsk);

    // set the callback function
    nl_socket_modify_cb(g_nlsk, NL_CB_VALID, NL_CB_CUSTOM,
                        bfnl_process_netlink_msg, NULL);

    // connect to the netlink route socket
    if (nl_connect(g_nlsk, NETLINK_ROUTE) < 0) {
        perror("nl_connect:NETLINK_ROUTE");
        cleanup_nl_sock(g_nlsk);
        return;
    }

    // register for the following messages
    nl_socket_add_memberships(g_nlsk, RTNLGRP_LINK, 0);

    // set socket to be non-blocking
    g_nlsk_fd = nl_socket_get_fd(g_nlsk);
    if (g_nlsk_fd < 0) {
        cleanup_nl_sock(g_nlsk);
        perror("nl_socket_get_fd");
        return;
    }

    sock_flags = fcntl(g_nlsk_fd, F_GETFL, 0);
    if (fcntl(g_nlsk_fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
        cleanup_nl_sock(g_nlsk);
        perror("fcntl");
        return ;
    }
}

void *start_bfnl_packet_server(void *args) {
    int i;

    bfnl_packetd_init();
    bfnl_nl_sock_init();
    assert(g_nlsk_fd != -1);

    while (1) {
        int ret, nfds = -1;
        fd_set read_fds;
        FD_ZERO(&read_fds);
        for (i = 0; i < BFNL_NUM_INTERFACES; i++) {
            FD_SET(g_intf[i].fd, &read_fds);
            nfds = (g_intf[i].fd > nfds) ? g_intf[i].fd : nfds;
        }
        FD_SET(g_sock_fd, &read_fds);
        FD_SET(g_nlsk_fd, &read_fds);
        nfds = (g_sock_fd > nfds) ? g_sock_fd : nfds;
        nfds = (g_nlsk_fd > nfds) ? g_nlsk_fd : nfds;
        nfds++;

        ret = select(nfds, &read_fds, NULL, NULL, NULL);
        if (ret == -1) {
            perror("select");
            return NULL;
        } else if (ret == 0) {
        } else {
            for (i = 0; i < BFNL_NUM_INTERFACES; i++) {
                if (FD_ISSET(g_intf[i].fd, &read_fds)) {
                    bfnl_process_packet_from_user(i);
                }
            }
            if (FD_ISSET(g_sock_fd, &read_fds)) {
                bfnl_process_packet_from_tofino();
            }
            if (FD_ISSET(g_nlsk_fd, &read_fds)) {
                nl_recvmsgs_default(g_nlsk);
            }
        }
    }
}

pthread_t cpu_handler_thread;
void start_cpu_packet_handler()
{
    pthread_create(&cpu_handler_thread, NULL,
                       start_bfnl_packet_server, NULL);
}

