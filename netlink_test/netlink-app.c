#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NETLINK_USER 17


/**
 * Returns a pointer to the first rtattr following the nlmsghdr *nlh and the
 * 'usual' netlink data x like 'struct xfrm_usersa_info'
 */
#define XFRM_RTA(nlh, x) ((struct rtattr*)(NLMSG_DATA(nlh) + \
    NLMSG_ALIGN(sizeof(x))))
/**
 * Returns the total size of attached rta data
 * (after 'usual' netlink data x like 'struct xfrm_usersa_info')
 */
#define XFRM_PAYLOAD(nlh, x) NLMSG_PAYLOAD(nlh, sizeof(x))


typedef struct mydata_t{
    int a;
    int b;
}mydata_t;
typedef struct mydata2_t{
    int a;
}mydata2_t;
enum{
    MY_TYPE_1 = 0x10+1,
    MY_TYPE_2,
    MY_TYPE_3,
    MY_TYPE_4
};
enum {
    MY_ATTR_FOO = 1,
    MY_ATTR_BAR,
    __MY_ATTR_MAX,
};
typedef u_char netlink_buf_t[1024] __attribute__((aligned(4)));


/**
 * Described in header.
 */
void* netlink_reserve(struct nlmsghdr *hdr, int buflen, int type, int len)
{
    struct rtattr *rta;

    if (NLMSG_ALIGN(hdr->nlmsg_len) + RTA_LENGTH(len) > buflen)
    {
        printf("unable to add attribute, buffer too small \n");
        return NULL;
    }

    rta = ((void*)hdr) + NLMSG_ALIGN(hdr->nlmsg_len);
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + rta->rta_len;

    return RTA_DATA(rta);
}


void main()
{
    static int sock_fd;
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) return;


    struct nlmsghdr *hdr, *out;
    struct sockaddr_nl addr;
    netlink_buf_t request;
    size_t len;
    int addr_len = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0; /* to kernel */
    addr.nl_groups = 0;  /* no multicast */
    if (bind(sock_fd, (struct sockaddr*)&addr, addr_len))
    {
        goto __gotoexit;
    }


    /* TRANSMIT */
    memset(&request, 0, sizeof(request));
    hdr = (struct nlmsghdr*)request;
    hdr->nlmsg_flags = NLM_F_REQUEST;
    hdr->nlmsg_type = MY_TYPE_2;
    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct mydata_t));
    hdr->nlmsg_seq = 3;
    hdr->nlmsg_pid = getpid();

    mydata_t *senddata = (struct mydata_t*)NLMSG_DATA(hdr);
    senddata->a = 1;
    senddata->b = 2;

    struct mydata2_t *xmrk;
    xmrk = netlink_reserve(hdr, sizeof(request), MY_ATTR_FOO, sizeof(mydata2_t));
    if(xmrk){
        xmrk->a = 33;
    }
    xmrk = netlink_reserve(hdr, sizeof(request), MY_ATTR_BAR, sizeof(mydata2_t));
    if(xmrk){
        xmrk->a = 55;
    }

    len = sendto(sock_fd, hdr, hdr->nlmsg_len, 0, (struct sockaddr*)&addr, addr_len);
    if (len != hdr->nlmsg_len)
    {
        printf("send fail ! \n");
        goto __gotoexit;
    }


    /* RECEIVE */
    netlink_buf_t recvbuf;
    memset(&recvbuf, 0, sizeof(recvbuf));
    len = recvfrom(sock_fd, recvbuf, sizeof(recvbuf), MSG_DONTWAIT, (struct sockaddr*)&addr, &addr_len);
    if (len < 0)
    {
        printf("receive fail ! \n");
        goto __gotoexit;
    }

    out = (struct nlmsghdr*)recvbuf;
    printf("flags: %d, len: %d, pid: %d, seq: %d, type: %d \n",
           out->nlmsg_flags,
           out->nlmsg_len,
           out->nlmsg_pid,
           out->nlmsg_seq,
           out->nlmsg_type);
    mydata_t *recvdata = (mydata_t *)NLMSG_DATA(out);
    printf("receive main data: %d %d \n", recvdata->a, recvdata->b);

    struct rtattr *rta = XFRM_RTA(out, mydata_t);
    size_t rtasize = XFRM_PAYLOAD(out, mydata_t);

    printf("attributes: rtasize: %d, rta_len: %d, rta_type: %d\n", rtasize, rta->rta_len, rta->rta_type);
    while (RTA_OK(rta, rtasize))
    {

        if (rta->rta_type == MY_ATTR_FOO)
        {
            mydata2_t *ret =(mydata2_t *)RTA_DATA(rta);
            printf("receive MY_ATTR_FOO: %d \n", ret->a);
        }else{
            mydata2_t *ret =(mydata2_t *)RTA_DATA(rta);
            printf("receive MY_ATTR_BAR: %d \n", ret->a);
        }
        rta = RTA_NEXT(rta, rtasize);
    }


__gotoexit:
    close(sock_fd);
}
