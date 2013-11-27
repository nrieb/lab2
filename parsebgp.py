#! /usr/bin/env python

import dpkt
import socket
import sys
import fileinput

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

bad_bgp = 0
bgp_type = [0 for x in xrange(0,5)]
# trying 24b-router.pcap for now... probably a better pcap file
#for file_name in sys.argv[1:]:
for file_name in fileinput.input():
    try:
        with open(file_name.strip(), 'rb') as f:
            for ts, pkt in dpkt.pcap.Reader(f):
                eth=dpkt.ethernet.Ethernet(pkt)
                
                if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                    continue
                
                ip=eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                
                tcp = ip.data
                
                # tcp data shouldn't be blank; dunno why it can be, just dropping them for now
                if type(tcp) != str and len(tcp.data) and (tcp.dport == 179 or tcp.dport == 179):
                    try:
                        # print type(dpkt.bgp.BGP(tcp.data))
                        bgp = dpkt.bgp.BGP(tcp.data)
                        bgp_type[bgp.type - 1] += 1
                        '''
                        print type_to_string(bgp.type)
                        if bgp.type == dpkt.bgp.UPDATE:
                        for attr in bgp.update.attributes:
                        if attr.type == dpkt.bgp.AS_PATH:
                        print path_to_str(attr.as_path)
                        break
                                ''' 
                    except:
                        # misformed bgp packets will cause an exception, i believe
                        # if there are a ton of them, we may have to handle them, but otherwise its ok
                        bad_bgp += 1
        print ''
        print file_name.strip()
        print 'bad', [type_to_string(idx+1) for idx in xrange(0,5)]
        print bad_bgp,  bgp_type
        bad_bgp = 0
        bgp_type = [0 for x in xrange(0,5)]
    except dpkt.dpkt.NeedData:
        continue
