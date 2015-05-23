#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_USER 17


struct sock *nl_sk = NULL;
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


//############ attributes ##############
enum {
    MY_ATTR_FOO = 1,
    MY_ATTR_BAR,
    __MY_ATTR_MAX,
};

#define MY_ATTR_MAX (__MY_ATTR_MAX - 1)
static struct nla_policy my_policy[MY_ATTR_MAX+1] = {
    [MY_ATTR_FOO] = { .len = sizeof(mydata2_t) },
    [MY_ATTR_BAR] = { .len = sizeof(mydata2_t)},
};

void parse_msg(struct nlmsghdr *nlh)
{
    struct nlattr *attrs[MY_ATTR_MAX+1];
    if (nlmsg_parse(nlh, sizeof(mydata_t), attrs, MY_ATTR_MAX, my_policy) < 0) return;

    struct nlattr *rt = attrs[MY_ATTR_FOO];
    if (!rt) return;
    struct mydata2_t *algp = nla_data(rt);
    printk("value MY_ATTR_FOO: %d \n", algp->a);


    rt = attrs[MY_ATTR_BAR];
    if (!rt) return;
    algp = nla_data(rt);
    printk("value MY_ATTR_BAR: %d \n", algp->a);

}


static void hello_nl_recv_msg(struct sk_buff *skb)
{

    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int pid;
    int res;
    mydata_t *testdata = NULL;


    /* RECEIVE */
    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /*pid of sending process */

    printk(KERN_INFO "flags: %d, len: %d, pid: %d, seq: %d, type: %d \n",
           nlh->nlmsg_flags,
           nlh->nlmsg_len,
           nlh->nlmsg_pid,
           nlh->nlmsg_seq,
           nlh->nlmsg_type);

    testdata = (mydata_t *)nlmsg_data(nlh);
    printk(KERN_INFO "Netlink received msg payload: %d %d \n", testdata->a, testdata->b);

    parse_msg(nlh);


    /* TRANSMIT */
    skb_out = nlmsg_new(sizeof(mydata_t), GFP_KERNEL);
    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    nlh = nlmsg_put(skb_out, 0 /*from kernel*/, 0, MY_TYPE_2/*NLMSG_DONE*/, sizeof(mydata_t), NLM_F_REQUEST);
    mydata_t outdata;
    outdata.a = 32;
    outdata.b = 45;
    memcpy(nlmsg_data(nlh), (void *)&outdata, sizeof(mydata_t));

    mydata2_t attdata = { 12};
    nla_put(skb_out, MY_ATTR_FOO, sizeof(mydata2_t), (void*)&attdata);

    mydata2_t attdata2 = { 121};
    nla_put(skb_out, MY_ATTR_FOO, sizeof(mydata2_t), (void*)&attdata2);


    nlmsg_end(skb_out, nlh);

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}

static int __init hello_init(void)
{
    printk(KERN_INFO "init netlink module\n");

    struct netlink_kernel_cfg cfg = {
        .groups	= 0, /* no multicast */
                .input	= hello_nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

    if (!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit hello_exit(void)
{

    printk(KERN_INFO "exiting netlink module\n");
    netlink_kernel_release(nl_sk);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
