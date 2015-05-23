/* * Author: andrei@fcns.eu * GPLv3 License applies to this code. * * */
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "netfilter2.h"

#define DEBUG 1

struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct udphdr *udp_header;
struct rpmphdr *rpmp_header;
static struct nf_hook_ops nfho;

static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{ 
	sock_buff = skb;
	if (!sock_buff) {
		return NF_ACCEPT;
	} else {
		ip_header = (struct iphdr *)skb_network_header(sock_buff);
		if (!ip_header) { return NF_ACCEPT;
		} else {
			if (ip_header->protocol == IPPROTO_ICMP) {
				rpmp_header = (struct rpmphdr *)(skb_transport_header(sock_buff)+sizeof(struct iphdr));
#if DEBUG > 0
				printk(KERN_INFO "[RPMP] DEBUG: th: 0p%p\n", rpmp_header);
				printk(KERN_INFO "[RPMP] DEBUG: nh: 0p%p\n", skb_network_header(sock_buff));
				printk(KERN_INFO "[RPMP] DEBUG: mh: 0p%p\n", skb_mac_header(sock_buff));
				printk(KERN_INFO "[RPMP] DEBUG: Length: rpmp_header=%d | dport=%d | type=%d.\n",
					   sizeof(rpmp_header), sizeof(rpmp_header->dport), sizeof(rpmp_header->type));
				printk(KERN_INFO "[RPMP] DEBUG: From IP address: %d.%d.%d.%dn",
					   ip_header->saddr & 0x000000FF, (ip_header->saddr & 0x0000FF00) >> 8,
					   (ip_header->saddr & 0x00FF0000) >> 16,  (ip_header->saddr & 0xFF000000) >> 24);
#endif
				printk(KERN_INFO "[RPMP] Got a RPMP packet for port=%d (type:%d).\n",
					   ntohs(rpmp_header->dport), ntohs(rpmp_header->type));

				/* Callback function here*/
				return NF_DROP;
			} else {
				return NF_ACCEPT;
			}
		}
	}
}

/*

static int process_pkt()
{
#if DEBUG > 0
	printk(KERN_INFO "[RPMP] DEBUG: Inside the callback!\n");
#endif
	return 0;
}

*/


#if 0
/* IP Hooks */
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5
#endif

static int __init init_main(void) 
{
	nfho.hook = hook_func;
	nfho.hooknum = 1;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	
#if DEBUG > 0
	printk(KERN_INFO "[RPMP] Successfully inserted protocol module into kernel.\n");
#endif
	return 0;
}

static void __exit cleanup_main(void) {
	nf_unregister_hook(&nfho);
#if DEBUG > 0
	printk(KERN_INFO "[RPMP] Successfully unloaded protocol module.\n");
#endif
}

module_init(init_main);
module_exit(cleanup_main);


MODULE_LICENSE("GPLv3");          /* Declaring code as GPL. */
MODULE_AUTHOR(DRIVER_AUTHOR);     /* Who wrote this module? */
MODULE_DESCRIPTION(DRIVER_DESC);  /* What this module does */

