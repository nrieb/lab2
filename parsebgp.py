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
from ASgraph import *

FOUR_OCTET_AS = 65

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

def get_AS(bgp_open):
    AS = bgp_open.asn
    for param in bgp_open.parameters:
        if param.type == dpkt.bgp.CAPABILITY and param.capability.code == FOUR_OCTET_AS:
            AS = struct.unpack(">I", param.capability.data)[0]
            break
    return AS

def unpack_segments(segments):
    return [x.data for x in segments]

def process_update(graph, bgp_update, src_AS):
    #add in a singleton path for when there is not AS path
    #attribute.  This is because we can withdraw when there is no
    #path
    path = [src_AS]
    for attribute in bgp_update.attributes:
        if attribute.type == dpkt.bgp.AS_PATH:
            [path] = unpack_segments(attribute.as_path.segments)
            break

    graph.add(path, bgp_update.announced, bgp_update.withdrawn)

#ip4 4 octet to string
def ip4_to_str(ip4):
    return "%d.%d.%d.%d" % struct.unpack("@BBBB", ip4)
    

bad_bgp = 0
count = 0
withdrawn_no_path_count = 0
# Assuming that pcap started part way through.  these are the AS numbers of the ips directly talking to 109
ip_list = {'192.168.212.116': 65716, '192.168.212.113': 65713, '192.168.212.112': 65812}
# trying 24b-router.pcap
for file_name in sys.argv[1:]:
#for file_name in fileinput.input():
    try:
        i = 0
        with open(file_name.strip(), 'rb') as f:
            graph = ASGraph()
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
                # 192.168.212.109 looks like the router.  only look at things that talk at it
                interesting_ip = struct.pack("BBBB", 192, 168, 212, 109)
                if (tcp.dport == 179 or tcp.sport == 179) and len(tcp.data) and ip.dst == interesting_ip:
                    try:
                        for bgp in bgp_parse(tcp.data, i):
                            if bgp.type == dpkt.bgp.OPEN:
                                #AS = get_AS(bgp.open)
                                #ip_list[ip4_to_str(ip.src)] = AS
                                pass
                            elif bgp.type == dpkt.bgp.UPDATE:
                                process_update(graph, bgp.update, ip_list[ip4_to_str(ip.src)])
                                pass
                                
                    except:
                        #print "fail on packet", i, ip4_to_str(ip.src), ip4_to_str(ip.dst)
                        bad_bgp += 1
                        raise
            for AS, node in graph.nodes.viewitems():

                if '0.0.0.0/0' in node.subnets:
                    print AS, len(node.subnets)
                '''
                if len(node.withdrawn):
                    print sorted(node.subnets)
                    print sorted(node.withdrawn)
                '''
    except dpkt.dpkt.NeedData:
        continue
