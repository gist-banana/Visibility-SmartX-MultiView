# Licensed under the Apache License, Version 2.0 (the "License")
from kafka import KafkaProducer
from bcc import BPF
import pyroute2
import time
import sys
from ctypes import *

bootstrap_servers = ['lcaolhost:9092','localhost:9091','localhost:9090']
topicName = 'xdp_kafka_topic'

producer = KafkaProducer(bootstrap_servers = bootstrap_servers)
producer = KafkaProducer()

def convert_ip_to_bin(data):
        data =  "{0:b}".format(data.value).zfill(28)
        #    data = ''.join(str((int((data[0:4]),2))))
        # 0:4 - 1
        # 4:12 - 1
        # 12:20 - 168
        # 20:28

        one = ''.join(str((int((data[20:28]),2))))
        two = ''.join(str((int((data[12:20]),2))))
        three = ''.join(str((int((data[4:12]),2))))
        four = ''.join(str((int((data[0:4]),2))))
        back = one +'.' + two + '.'+ three +'.' + four
        return back


flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode\n")
    print("       -H: use hardware offload mode\n")
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

offload_device = None
if len(sys.argv) == 2:
    device = sys.argv[1]
elif len(sys.argv) == 3:
    device = sys.argv[2]

_xdp_file = "backup_xdp_4_dos.c"

maptype = "percpu_array"
if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= (1 << 1)
    if "-H" in sys.argv:
        # XDP_FLAGS_HW_MODE
        maptype = "array"
        offload_device = device
        flags |= (1 << 3)

mode = BPF.XDP
#mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_PASS"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(src_file = _xdp_file, cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype, "-DMAPTYPE=\"%s\"" % maptype], )

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

hash_addr = b.get_table("hash_addr")
dropcnt = b.get_table("dropcnt")

prev = [0] * 256
print("Printing drops per IP protocol-number, hit CTRL+C to stop")
#ip_addr = str(convert_ip_to_bin((hash_addr.items()[0][1])))
while 1:
    #under while
#    try:
        # here
    for k in dropcnt.keys():
        val = dropcnt[k].value if maptype == "array" else dropcnt.sum(k).value
        i = k.value
        ip_addr = str(convert_ip_to_bin((hash_addr.items()[0][1])))
#        print('\n')
        if val:
                #
            delta = val - prev[i]
            prev[i] = val
            contents = str(ip_addr) + ' ' + str(delta)
            print(contents)
            print('\n')
            ack = producer.send(topicName, contents)
            time.sleep(5)
#        time.sleep(1)
#    except KeyboardInterrupt:
#        print("Removing filter from device")
#        break;

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
