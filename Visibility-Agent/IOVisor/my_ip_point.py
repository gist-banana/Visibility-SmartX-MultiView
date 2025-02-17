#!/usr/bin/python
#
# Name          : net_ip_point.py
# Description   : A script for processing network packets at user-level
#
# Created by    : Networked Computing Systems Laboratory
# Maintained by : Jun-Sik Shin and Muhammad Usman
# Version       : 0.4
# Last Update   : August, 2018

from __future__ import print_function

import os
import socket
import time
import logging
import signal
import sys
import zmq
import json
import yaml
from datetime import datetime

import netifaces as ni
from bcc import BPF


class NetworkIpPacketPoint:
    def __init__(self, point_config):
        self._logger = logging.getLogger(self.__class__.__name__)
        self.map_test = None
        self._bpf_file = "my_ip_point.c"
        self._bpf_func = "ip_filter"

        self._bpf_bytecode = None
        self._socket_filter = None
        self._socket = None
        self._socket_fd = None

        # point_conf = dict()
        # point_conf["point"] = "NetworkIpPacketPoint"
        # point_conf["level"] = "resource"
        # point_conf["type"] = "physical_networking"
        #
        # mq_opt = dict()
        # mq_opt["ipaddress"] = "127.0.0.1"
        # mq_opt["port"] = 50070
        # point_conf["msg_queue"] = mq_opt
        #
        # point_opt = dict()
        # point_opt["output_type"] = "stream"
        # point_opt["target"] = "eno1"
        # point_conf["option"] = point_opt
    
        self._point = None
        self._level = None
        self._type = None
        self._option = None

        self._mq_context = None
        self._mq_sock = None

        self._load_config(point_config)
        self._prepare_mq_conn(point_config["msg_queue"])

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def _load_config(self, point_config):
        # Variables that have to be defined in point_config
        self._point = point_config["point"]
        self._level = point_config["level"]
        self._type = point_config["type"]
        self._option = point_config["option"]

    def _prepare_mq_conn(self, mq_config):
        self._mq_context = zmq.Context()
        self._mq_sock = self._mq_context.socket(zmq.PUSH)
        self._mq_sock.connect("tcp://{}:{}".format(mq_config["ipaddress"], mq_config["port"]))
        self._logger.debug("MQ Socket is connected to {}:{}".format(mq_config["ipaddress"], mq_config["port"]))

    def signal_handler(self, signal, frame):
        self._logger.info("Visibility Point {} was finished successfully".format(self.__class__.__name__))
        self._bpf_bytecode.cleanup()
        self._socket.close()
        sys.exit(0)

    def collect(self):
        self._init_bpf()
        self._logger.debug("MachineIP Hostname   ipver     Src IP Addr          Dst IP Addr    src Port    Dst Port   "
                           "   protocol  TCP_Window_Size Packet_Length")
        while True:
            # For detailed information, please find "_not_used_func()" method.
            time.sleep(0.5)
            packet_all_info = dict()
            for k, v in self.map_test.items():
                print("\n map is here : \n")
 #               print("{:d} ".format (k.value))
                print("{: 20d} {: 20d}".format(k.value, v.value))
#                print(v.value)

            # retrieve raw packet from socket
            packet_str = os.read(self._socket_fd, 2048)

            # convert packet into bytearray
            packet_bytearray = bytearray(packet_str)

            self._store_packet_overall_info(packet_bytearray, packet_all_info)
            self._store_packet_ip_info(packet_bytearray, packet_all_info)
            self._store_packet_tcp_info(packet_bytearray, packet_all_info)
            if self._option["output_type"] == "file":
                message = self._gen_msg_str(packet_all_info)
                filename = self._get_filename()
                self._write_file(filename, message)
            elif self._option["output_type"] == "stream":
                message = self._get_influx_msg(packet_all_info)
                self._send_msg(message)

    def _init_bpf(self):
        # initialize BPF - load source code from http-parse-simple.c
        self._bpf_bytecode = BPF(src_file=self._bpf_file, debug=0)
        self.map_test = self._bpf_bytecode.get_table("hash_test")
        # load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
        # more info about eBPF program types http://man7.org/linux/man-pages/man2/bpf.2.html
        function_ip_filter = self._bpf_bytecode.load_func(self._bpf_func, BPF.SOCKET_FILTER)

        # create raw socket, bind it to eth0
        # attach bpf program to socket created
        BPF.attach_raw_socket(function_ip_filter, self._option["nic"])

        # get file descriptor of the socket previously created inside BPF.attach_raw_socket
        self._socket_fd = function_ip_filter.sock

        # create python socket object, from the file descriptor
        self._socket = socket.fromfd(self._socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)

        # set it as blocking socket
        self._socket.setblocking(True)

    def _store_packet_overall_info(self, packet_bytearray, packet_info):
        # ethernet header length
        ETH_HLEN = 14

        # calculate packet total length
        total_length = packet_bytearray[ETH_HLEN + 2]  # load MSB
        total_length = total_length << 8  # shift MSB
        total_length = total_length + packet_bytearray[ETH_HLEN + 3]  # add LSB
        packet_info["total_length"] = total_length

    def _store_packet_ip_info(self, packet_bytearray, packet_info):
        # parsing ip version from ip packet header
        ipversion = str(bin(packet_bytearray[14])[2:5])
        packet_info["ip_version"] = str(int(ipversion,2))
        
        # ADDED - START

        packet_info["ip_ttl"] = packet_bytearray[22]
        temp = packet_bytearray[14]
        temp = bin(temp)[2:].zfill(8)
        packet_info["ip_header_len"]=int(temp[4:8],2)*4
        packet_info["ip_flags"] = hex((packet_bytearray[20]<<8) + packet_bytearray[21])
        packet_info["ip_protocol"] = packet_bytearray[23]
        packet_info["ip_header_chk_sum"] = hex((packet_bytearray[24] << 8) + packet_bytearray[25])
        packet_info["ip_identification"] =(packet_bytearray[18] << 8) + packet_bytearray[19]

        packet_info["ether_dst_addr"] = "{:x}.{:x}.{:x}.{:x}.{:x}.{:x}".format(packet_bytearray[0],packet_bytearray[1],packet_bytearray[2],packet_bytearray[3],packet_bytearray[4],packet_bytearray[5])
        packet_info["ether_src_addr"] = "{:x}.{:x}.{:x}.{:x}.{:x}.{:x}".format(packet_bytearray[6],packet_bytearray[7],packet_bytearray[8],packet_bytearray[9],packet_bytearray[10],packet_bytearray[11])


        # ADDED - END


        # parsing source ip address, destination ip address from ip packet header
        src_addr = str(packet_bytearray[26]) + "." + str(packet_bytearray[27]) + "." + \
                   str(packet_bytearray[28]) + "." + str(packet_bytearray[29])
        dst_addr = str(packet_bytearray[30]) + "." + str(packet_bytearray[31]) + "." + \
                   str(packet_bytearray[32]) + "." + str(packet_bytearray[33])
        packet_info["src_ip_addr"] = src_addr
        packet_info["dst_ip_addr"] = dst_addr
        
        # ADDED - START

 # ETHERNET[LOG] - STRAT
 #      self._logger.info("\n\n\n") # leave some space for viewers
        self._logger.info("ether_dst_addr = {}, ether_src_addr = {}, ether_total_length = {}".format(packet_info["ether_dst_addr"], packet_info["ether_src_addr"], packet_info["total_length"]))

  # ETHERNET[LOG] - END

   # IP[LOG] - START

        self._logger.info("ip_ttl = {}, ip_header_len = {}, ip_flags = {}, ip_protocol = {}".format(packet_info["ip_ttl"],packet_info["ip_header_len"],packet_info["ip_flags"],packet_info["ip_protocol"]))
        self._logger.info("ip_version = {}, ip_identification = {}, src_ip_addr = {}, dst_ip_addr = {}".format(packet_info["ip_version"], packet_info["ip_identification"], packet_info["src_ip_addr"], packet_info["dst_ip_addr"]))
        self._logger.info("ip_header_chk_sum = {}".format(packet_info["ip_header_chk_sum"]))

     # IP[LOG] - END


        # ADDED - END
        
    def _store_packet_tcp_info(self, packet_bytearray, packet_info):
        # parsing source port and destination port
        if packet_bytearray[23] == 6:
            protocol = 6
            src_port = packet_bytearray[34] << 8 | packet_bytearray[35]
            dst_port = packet_bytearray[36] << 8 | packet_bytearray[37]
            tcp_window_size = packet_bytearray[48] << 8 | packet_bytearray[49]
        elif packet_bytearray[23] == 1:
            protocol = 1
            src_port = -1
            dst_port = -1
            tcp_window_size = 0
        elif packet_bytearray[23] == 17:
            protocol = 17
            src_port = packet_bytearray[34] << 8 | packet_bytearray[35]
            dst_port = packet_bytearray[36] << 8 | packet_bytearray[37]
            tcp_window_size = 0
        else:
            protocol = -1
            src_port = packet_bytearray[34] << 8 | packet_bytearray[35]
            dst_port = packet_bytearray[36] << 8 | packet_bytearray[37]
            tcp_window_size = 0

        packet_info["protocol"] = str(protocol)
        packet_info["src_port"] = str(src_port)
        packet_info["dst_port"] = str(dst_port)
        packet_info["tcp_window_size"] = tcp_window_size

        # ADDED - START

        packet_info["tcp_segment_len"] = packet_bytearray[16]
        packet_info["tcp_header_len"]= int(bin(packet_bytearray[46])[2:].zfill(8)[0:4],2)*4
        packet_info["tcp_window_size"] = (packet_bytearray[48] << 8) + packet_bytearray[49]
        packet_info["tcp_checksum"] = hex((packet_bytearray[50] << 8) + packet_bytearray[51])
        packet_info["tcp_urgent_pointer"] = (packet_bytearray[52] << 8) + packet_bytearray[53]

        #ADDED - END


        # TEST[LOG] - START

    #    self._logger.info("tcp_segment_len = {}, tcp_header_len = {}, tcp_window_size = {}, tcp_checksum = {}".format(packet_info["tcp_segment_len"],packet_info["tcp_header_len"],packet_info["tcp_window_size"],packet_info["tcp_checksum"]))
    #    self._logger.info("tcp_urgent_pointer = {}, tcp_protocol = {}, tcp_src_port = {}, tcp_dst_port = {}".format(packet_info["tcp_urgent_pointer"], packet_info["protocol"], packet_info["src_port"], packet_info["dst_port"]))
    #    self._logger.info("tcp_window_size = {}".format(packet_info["tcp_window_size"]))

        # TEST[LOG] - END


    def _gen_msg_str(self, packet_info):
        mgmt_ip = self._get_mgmt_ip_address()
        message = "{},0,{},{},{},{},{},{},{},{},{},{}".format(
            str(int(round(time.time() * 1000000))), socket.gethostname(), mgmt_ip,
            packet_info["ip_version"], packet_info["src_ip_addr"], packet_info["dst_ip_addr"],
            packet_info["src_port"], packet_info["dst_port"], packet_info["protocol"], str(packet_info["tcp_window_size"]),
            str(packet_info["total_length"])
        )
        self._logger.debug(message)
        return message

    def _get_mgmt_ip_address(self):
        mgmt_nic = ni.gateways().get("default").get(ni.AF_INET)[1]
        ni.ifaddresses(mgmt_nic)
        mgmt_ip = ni.ifaddresses(mgmt_nic)[ni.AF_INET][0]['addr']
        return mgmt_ip

    def _write_file(self, filename, msg):
        if not os.path.exists(self._option["log_dir"]):
            self._logger.debug("Hello")
            os.mkdir(self._option["log_dir"])

        f = open(filename, "a")
        f.write("%s\n" % msg)
        f.close()

    def _get_filename(self):
        current_min = int(time.strftime("%M"))
        box_name = socket.gethostname()

        min_mul_five = current_min - current_min % 5
        filename = "{}{}-{}-{}-{:02d}".format(self._option["log_dir"], box_name, self._option["net_type"],
                                          time.strftime("%Y-%m-%d-%H"), min_mul_five)
        self._logger.debug(filename)
        return filename

    def _get_influx_msg(self, pkt_all_info):
        # Need to get
        # Physical / Virtual
        # Compute / Networking/ Storage

        # measurement: Physical / Virtual + Compute / Networking / Storage
        # tags: Box Name, NIC
        # fields: ip_ver, srcipaddr, dstipaddr, srcport, dstport, protocol, tcpwindowsize, totalpktlength
        msg = dict()
        msg["measurement"] = self._type

        msg["time"] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        tags = dict()
        tags["box"] = socket.gethostname()
        tags["nic"] = self._option["nic"]
        tags["src_ip_addr"] = str(pkt_all_info.pop("src_ip_addr"))
        tags["dst_ip_addr"] = str(pkt_all_info.pop("dst_ip_addr"))
        tags["src_port"] = str(pkt_all_info.pop("src_port"))
        tags["dst_port"] = str(pkt_all_info.pop("dst_port"))
        msg["tags"] = tags
        msg["fields"] = pkt_all_info

        influx_msg = json.dumps([msg])

        return influx_msg

    def _send_msg(self, msg):
        m = msg
        if isinstance(msg, dict):
            m = json.dumps(msg)
        elif isinstance(msg, list):
            m = json.dumps(msg)
        zmq_msg = "{}/{}".format(self._level, m)
        self._logger.debug(zmq_msg)
        self._mq_sock.send_string(zmq_msg)

    def to_hex(self, s):
        # convert a bin string into a string of hex char
        # helper function to print raw packet in hex
        lst = []
        for ch in s:
            hv = hex(ord(ch)).replace('0x', '')
            if len(hv) == 1:
                hv = '0' + hv
            lst.append(hv)

        return reduce(lambda x, y: x + y, lst)

    def _not_used_func(self):
        # DEBUG - print raw packet in hex format
        # packet_hex = toHex(packet_str)
        # print ("%s" % packet_hex)

        # IP HEADER
        # https://tools.ietf.org/html/rfc791
        # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |Version|  IHL  |Type of Service|          Total Length         |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #
        # IHL : Internet Header Length is the length of the internet header
        # value to multiply * 4 byte
        # e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
        #
        # Total length: This 16-bit field defines the entire packet size,
        # including header and data, in bytes.


        # calculate ip header length
        # ip_header_length = packet_bytearray[ETH_HLEN]  # load Byte
        # ip_header_length = ip_header_length & 0x0F  # mask bits 0..3
        # ip_header_length = ip_header_length << 2  # shift to obtain length

        # TCP HEADER
        # https://www.rfc-editor.org/rfc/rfc793.txt
        #  12              13              14              15
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  Data |           |U|A|P|R|S|F|                               |
        # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        # |       |           |G|K|H|T|N|N|                               |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #
        # Data Offset: This indicates where the data begins.
        # The TCP header is an integral number of 32 bits long.
        # value to multiply * 4 byte
        # e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

        # calculate tcp header length
        # tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  # load Byte
        # tcp_header_length = tcp_header_length & 0xF0  # mask bit 4..7
        # tcp_header_length = tcp_header_length >> 2  # SHR 4 ; SHL 2 -> SHR 2

        # calculate payload offset
        # payload_offset = ETH_HLEN + ip_header_length + tcp_header_length
        pass


if __name__ == "__main__":
    logging.basicConfig(format="[%(asctime)s / %(levelname)s] %(filename)s,%(funcName)s(#%(lineno)d): %(message)s",
                        level=logging.INFO)

    point_conf = dict()
    file_path = None
    if len(sys.argv) == 2:
        # Load configuration from a file passed by second argument in the command
        file_path = sys.argv[1]
    else:
        file_path = "net_ip_point.yaml"

    with open(file_path) as f:
        cfg_str = f.read()
        point_conf = yaml.load(cfg_str)
        print (point_conf)

    point = NetworkIpPacketPoint(point_conf)
    point.collect()
