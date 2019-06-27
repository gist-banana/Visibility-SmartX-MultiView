#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys

flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode\n")
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= 2 << 0

    if "-S" == sys.argv[1]:
        device = sys.argv[2]
    else:
        device = sys.argv[1]

mode = BPF.XDP
#mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_PASS"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"



# load BPF program
b = BPF(text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


//BPF_TABLE("percpu_array", uint32_t, long, dropcnt, 256);
BPF_ARRAY(hash_test, unsigned char,6);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

int xdp_prog1(struct CTXTYPE *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;
    u64 in0 = 0;
    u64 in1 = 1;
    u64 in2 = 2;
    u64 in3 = 3;
    u64 in4 = 4;
    u64 in5 = 5;
    u64 dummy_data1, dummy_data2, dummy_data3, dummy_data4, dummy_data5, dummy_data0;
    struct iphdr *iph;

    struct eth_info {
        unsigned char addr[6];
    };

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return rc;

    h_proto = eth->h_proto;
    
    dummy_data0 = eth -> h_source[0];
    dummy_data1 = eth -> h_source[1];
    dummy_data2 = eth -> h_source[2];
    dummy_data3 = eth -> h_source[3];
    dummy_data4 = eth -> h_source[4];
    dummy_data5 = eth -> h_source[5];
    /*
    dummy_data0 = eth -> h_dest[0];
    dummy_data1 = eth -> h_dest[1];
    dummy_data2 = eth -> h_dest[2];
    dummy_data3 = eth -> h_dest[3];
    dummy_data4 = eth -> h_dest[4];
    dummy_data5 = eth -> h_dest[5];
    */
    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                return rc;
                h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

// htons() converts the unsigned short integer hostshort from host byte order to network byte order
// host byte order can be little/big endian while network byte order is big endian
    if (h_proto == htons(ETH_P_IP)){
        index = parse_ipv4(data, nh_off, data_end);
        /*
        if (iph + 1 > data_end)
         {
         iph = data + nh_off;
         dummy_data = iph -> protocol;
         }
         */

        }
    else if (h_proto == htons(ETH_P_IPV6))
       index = parse_ipv6(data, nh_off, data_end);
    else
        index = 0;
    
 //   if (dummy_data0 == 144) {
    hash_test.update(&in0, &dummy_data0);
    hash_test.update(&in1, &dummy_data1);
    hash_test.update(&in2, &dummy_data2);
    hash_test.update(&in3, &dummy_data3);
    hash_test.update(&in4, &dummy_data4);
    hash_test.update(&in5, &dummy_data5);
//    }        

  //  value = dropcnt.lookup(&index);
 //   if (value)
 //       *value += 1;

    return rc;
}
""", cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype])

fn = b.load_func("xdp_prog1", mode)

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

hash_test = b.get_table("hash_test")
#dropcnt = b.get_table("dropcnt")
prev = [0] * 256
print("Printing drops per IP protocol-number, hit CTRL+C to stop")
while 1:
    print("primal hunt")
    try:
        for k,v in hash_test.items():
            print("{: 20d} {: 20d}".format(k.value, v.value))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
