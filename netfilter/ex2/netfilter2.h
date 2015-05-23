/* * Author: andrei@fcns.eu * GPLv3 License applies to this code. * * */ 
#include <linux/types.h> 
#define DRIVER_AUTHOR "Andrei SAMBRA " 
#define DRIVER_DESC "icmp" 
#define IPPROTO_ICMP 1 
struct rpmphdr { 
	__be16 dport; 
	__u16 type; 
}; 
	
