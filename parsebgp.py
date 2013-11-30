#! /usr/bin/env python

'''
usage:
python parsebgp.py <pcap file>
Note: this currently assumes that the AS in the AS path
are 4 octets long NOT 2 octets.  If this is not true, this
will break
'''

import socket
import sys
import fileinput
import struct
import dpkt

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

def update_parse(bgp_update):
    assert bgp_update.type == dpkt.bgp.UPDATE
    for attr in bgp_update.update.attributes:
        if attr.type == bgp.AS_PATH:
            print path_to_str(attr.as_path)
            break

def bgp_parse(raw_tcp_data, packet_num):
    tcp_len = len(raw_tcp_data)
    header_len = 16+2+1
    l = []
    i = 0
    while tcp_len > 0:
        try:
            data_len = struct.unpack(">H", raw_tcp_data[16:18])[0]
        except:
            #print dpkt.hexdump(raw_tcp_data)
            #print packet_num, "failed on sub-packet" , i, log_len, tcp_len
            return l
        try:
            l.append(dpkt.bgp.BGP(raw_tcp_data[:header_len + data_len]))
        except dpkt.dpkt.UnpackError:
            print packet_num, "failed on sub-packet" , i
            pass

            
        #print len(raw_tcp_data[:data_len])
        #print dpkt.hexdump(raw_tcp_data[:header_len])
        raw_tcp_data = raw_tcp_data[data_len:]
        tcp_len -= data_len
        i+=1
    return l


#ip4 4 octet to string
def ip4_to_str(ip4):
    return "%d.%d.%d.%d" % struct.unpack("@BBBB", ip4)
    

bad_bgp = 0
count = 0
withdrawn_count = 0
# trying 24b-router.pcap
for file_name in sys.argv[1:]:
#for file_name in fileinput.input():
    try:
        i = 0
        with open(file_name.strip(), 'rb') as f:
            for ts, pkt in dpkt.pcap.Reader(f):
                i+=1
                eth=dpkt.ethernet.Ethernet(pkt)
                
                if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                    continue
                
                ip=eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                
                tcp = ip.data
                
                # ignore tcp setup (len == 0)
                if (tcp.dport == 179 or tcp.sport == 179) and len(tcp.data):
                    try:
                        for bgp in bgp_parse(tcp.data, i):
                            #parse bgp here
                            #process(bgp)
                                if bgp.type == dpkt.bgp.UPDATE:
                                    print ""
                                    print bgp.update.withdrawn
                                    print bgp.update.announced
                                    print ""
                                    if len(bgp.update.withdrawn):
                                        withdrawn_count += 1
                    except:
                        #print "fail on packet", i, ip4_to_str(ip.src), ip4_to_str(ip.dst)
                        bad_bgp += 1
                        raise
            #print withdrawn_count
    except dpkt.dpkt.NeedData:
        continue
