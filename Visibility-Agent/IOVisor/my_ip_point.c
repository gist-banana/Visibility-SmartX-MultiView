/* 
 Name          : mcd_planes_tacing.c
 Description   : A script for tracing network packets at kernel-level

 Created by    : Muhammad Usman
 Version       : 0.1
 Last Update   : March, 2018
*/

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 	6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

BPF_HASH(hash_test, u64 , unsigned int);
// the function

int ip_filter(struct __sk_buff *skb) { 

	u8 *cursor = 0;	// unsigned 8 bits = unsigned 1 byte
	
	// MAP TEST - START
	
	u64 test_1 = 0;
	u64 test_2 = 1;
	u64 test_3 = 2;
	unsigned int dummy_data = 0;
	unsigned int dummy_data2 = 0;
	unsigned int dummy_data3 = 123;

	// XDP TEST - START
	struct xdp_rxq_info{
		struct net_device *dev;
		u32 queue_index;
		u32 reg_state;
	} ____cacheline_aligned;
	// The rxq field points to some additional per receive queue metadata which is populated at ring setup time(not at XDP runtime)

	struct xdp_buff {
		void *data; // points to the start of the packet data in the page
		void *data_end; // points to the end of the packet data
		void *data_meta; // initially points to the same location as data but [bpf_xdp_adjust_meta()] can move the pointer
		// towards [data_hard_start] as well in order to provide room for custom metadat which is invisible to the normal kernel networking stack
		// data_meta can also be used solely for passing state between tail calls similarly to the [skb->cb[]] control block case accessible in tc BPF programs
		void *data_hard_start; // points to the maximum possible headroom start in the page
		// When the packet should be encapsulated, then data is moved closer towards [data_hard_start] via [bpf_xdp_adjust_head()]
		struct xdp_rxq_info *rxq;
	};

	// XDP TEST - END

	// MAP TEST - END

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));  // ethernet header (frame)
	if (!(ethernet->type == 0x0800)) {	
		goto DROP;	
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));	// IP header (datagram)
	if (ip->nextp != IP_TCP) {
		if (ip->nextp != IP_UDP){
			if (ip->nextp != IP_ICMP){
			goto DROP;}}
	}
	// MAP TEST - START
	dummy_data = ip -> dst;
	dummy_data2 = ip -> src;
	hash_test.update(&test_1,&dummy_data);
	hash_test.update(&test_2,&dummy_data2);
	hash_test.insert(&test_3,&dummy_data3);
	

//	if (ip -> dst == )
//		goto KEEP;
//	else
//		goto DROP;

	// MAP TEST - END
	if (ip -> src == 3421320511)
		goto KEEP;
	else
		goto DROP;

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	//keep the packet and send it to userspace retruning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;
}
