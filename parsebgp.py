#! /usr/bin/env python

'''
usage:
python parsebgp.py <pcap file>
Note: this currently assumes that the AS in the AS path
are 4 octets long NOT 2 octets.  If this is not true, this
will break

Also, this script assumes nets9b-router-04-tap0.pcap is the pcap file
if it is not, ip_list and interesting_ip need to be changed.  ip_list is 
just the AS of of the ips directly talking to interesting_ip.  interesting_ip
was just the destination ip with the most tcp packets talking bgp in the pcap
file.  These can be computed with a pass through the pcap file before the pass
that creates the graph.
'''

import socket
import sys
import struct
import dpkt
from ASgraph import *

FOUR_OCTET_AS = 65

def bgp_parse(raw_tcp_data, packet_num):
    tcp_len = len(raw_tcp_data)
    header_len = 16+2+1
    l = []
    i = 0
    while tcp_len > 0:
        try:
            data_len = struct.unpack(">H", raw_tcp_data[16:18])[0]
        except:
            #trailing bytes that don't make up another bgp packet
            #just return the list we have
            return l
        try:
            l.append(dpkt.bgp.BGP(raw_tcp_data[:header_len + data_len]))
        except dpkt.dpkt.UnpackError:
            #misconstructed bgp packet
            print packet_num, "failed on sub-packet" , i
            pass
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
    

# Assuming that pcap started part way through.  these are the AS numbers of the ips directly talking to 109
ip_list = {'192.168.212.116': 65716, '192.168.212.113': 65713, '192.168.212.112': 65812}
for file_name in sys.argv[1:]:
    try:
        i = 0
        bgp_update_count = 0
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
                    for bgp in bgp_parse(tcp.data, i):
                        if bgp.type == dpkt.bgp.OPEN:
                            #uncomment to populate ip_list
                            #AS = get_AS(bgp.open)
                            #ip_list[ip4_to_str(ip.src)] = AS
                            pass
                        elif bgp.type == dpkt.bgp.UPDATE:
                            bgp_update_count += 1
                            process_update(graph, bgp.update, ip_list[ip4_to_str(ip.src)])
                            #make a time series
                            if not bgp_update_count % 71:
                                graph.draw_to("output"+str(bgp_update_count)+".png")
                            pass
            
            graph.draw_to("output_final.png")
    except dpkt.dpkt.NeedData:
        continue
