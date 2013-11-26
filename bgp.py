#! /usr/bin/env python

import dpkt
import socket
import sys

for file_name in sys.argv[1:]:
    with open(file_name, 'rb') as f:
        try:
            for ts, pkt in dpkt.pcap.Reader(f):

                eth=dpkt.ethernet.Ethernet(pkt)
                if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip=eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue

                tcp = ip.data
                if tcp.dport == 179 or tcp.dport == 179:
                    print file_name
                    break
        except:
            print "bad name", file_name
