#!/usr/bin/env python


import os
import sys
import click 
import pyshark
import time
import threading

class myThread(threading.Thread):

    lockMe = threading.Lock()
    def __init__(self, counts):
        threading.Thread.__init__(self)
        self.counts = counts

    def run(self):
         self.lockMe.acquire()
         for key,val in self.counts.items():
                     print("{0}:{1}\t-->\t{2}:{3}\t{4} packets".format(key.src, key.src_port, key.dst, key.dst_port, val)) 
         time.sleep(2)
         os.system('clear')
         self.lockMe.release()



class tcpPacket:
    def __init__(self, src, src_port, dst, dst_port):
        self.src = src
        self.src_port = src_port
        self.dst = dst
        self.dst_port = dst_port
    def __repr__(self):
        return "{0},{1},{2},{3}".format(self.src, self.src_port, self.dst, self.dst_port)

    def __eq__(self, other):
        if not isinstance(other, tcpPacket):
            return NotImplemented
        return self.src == other.src and self.src_port == other.src_port and self.dst == other.dst and self.dst_port == other.dst_port

    def __hash__(self):
        return hash((self.src, self.src_port, self.dst, self.dst_port))

def list_interfaces():
    proc = os.popen("tshark -D")
    tshark_out = proc.read()
    interfaces = tshark_out.splitlines()
    for i in range(len(interfaces)):
        interface = interfaces[i].strip(str(i+1)+".")
        print(interface)

def get_ip_version(packet):
    for layer in packet.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6

def dump_packets(capture):
    i = 1
    counts = {}
    for packet in capture.sniff_continuously():
        if packet.transport_layer == 'TCP':

            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            global tcp
            tcp = tcpPacket(ip.src, packet.tcp.srcport, ip.dst, packet.tcp.dstport) 
            if tcp not in counts:
                counts[tcp] = 1
            else:
                counts[tcp] += 1
            thread = myThread(counts)
            thread.start()
        i += 1
    thread.join()



@click.command()
@click.option('--nic', default=None, help='Network interface for live capture (default=None, if file specified)')
@click.option('--file', default=None, help='PCAP file for file capture (default=None, if nic specified)')
@click.option('--list', is_flag=True, help='List the network interfaces')
def main(nic, file, list):
    if list:
        list_interfaces()
        sys.exit(0)
    elif nic == None and file == None:
        print( 'You must specify either a network interface or packet capture file')
        sys.exit(1)

    capture = None
    if nic == None:
        capture = pyshark.FileCapture(file)
    elif file == None:
        capture = pyshark.LiveCapture(interface=nic)

    dump_packets(capture)
if __name__ == '__main__':
     main()
