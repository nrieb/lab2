#! /usr/bin/env python

import dpkt
import socket
import sys

def type_to_string(num):
    if num == 1:
        return "OPEN"
    elif num == 2:
        return "UPDATE"
    elif num == 3:
        return "NOTIFICATION"
    elif num == 4:
        return "KEEPALIVE"
    elif num == 5:
        return "ROUTE_REFRESH"


# trying 24b-router.pcap for now... probably a better pcap file
for file_name in sys.argv[1:]:
    with open(file_name, 'rb') as f:
        for ts, pkt in dpkt.pcap.Reader(f):
            
            eth=dpkt.ethernet.Ethernet(pkt)
            if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                continue
            
            ip=eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            
            tcp = ip.data
            
            # tcp data shouldn't be blank; dunno why it can be, just dropping them for now
            if (tcp.dport == 179 or tcp.dport == 179) and len(tcp.data):
                try:
                    print type(dpkt.bgp.BGP(tcp.data))
                    bgp = dpkt.bgp.BGP(tcp.data)
                    print type_to_string(bgp.type)
                    if bgp.type == dpkt.bgp.UPDATE:
                        for attr in bgp.update.attributes:
                            if attr.type == dpkt.bgp.AS_PATH:
                                print path_to_str(attr.as_path)
                                break
                        
                except:
                    # misformed bgp packets will cause an exception, i believe
                    # if there are a ton of them, we may have to handle them, but otherwise its ok
                    continue
