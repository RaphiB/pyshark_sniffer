#!/usr/bin/env python


import os
import sys
import click
import pyshark
import threading
import netifaces as ni
import socket
from texttable import Texttable

bcolors = {"BLUE": '\033[94m',
           "HIGH": '\033[93m',
           "OKAY": '\033[92m',
           "FAIL": '\033[91m',
           "BOLD": '\033[1m',
           "LINE": '\033[4m',
           "ENDC": '\033[0m'
           }

class myThread(threading.Thread):

    lockMe = threading.Lock()

    def __init__(self, counts, nic):
        threading.Thread.__init__(self)
        self.counts = counts
        self.ip = get_ip_from_interface(nic)

    def run(self):
         self.lockMe.acquire()
         for key,val in self.counts.items():
                    # Only prints ip and occurences
                     print("{0}\t\t-->\t\t{2}\t\t{4} packets".format(key.src, key.src_port, key.dst, key.dst_port, val).replace(self.ip,bcolors["BLUE"]+"My_Computer"+bcolors["ENDC"]))
         input("Press enter to update connections")
         os.system('clear')
         self.lockMe.release()



class tcpPacket:
    def __init__(self, src, src_port, dst, dst_port, src_hostname, dst_hostname):
        self.src = src
        self.src_port = src_port
        self.dst = dst
        self.dst_port = dst_port
        self.src_hostname = src_hostname
        self.dst_hostname = dst_hostname

    def __repr__(self):
        return "{0},{1},{2},{3}".format(self.src, self.src_port, self.dst, self.dst_port)

#Ignores same connection with different port number. Therefore will print the first occurence portnummer and counts alle further packages even if the portnumber changes
    def __eq__(self, other):
        if not isinstance(other, tcpPacket):
            return NotImplemented
        return self.src == other.src and self.dst == other.dst 

    def __hash__(self):
        return hash((self.src, self.dst))

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

def get_ip_from_interface(interface):
        return ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

counts = {}

def dump_packets(capture, nic):
    i = 1
    log = 1
    #counts = {}
    src_hostname = ""
    dst_hostname = ""
    for packet in capture.sniff_continuously():
        if packet.transport_layer == 'TCP':

            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            global tcp
            try:
                src_hostname = socket.gethostbyaddr(ip.src)[0]
                dst_hostname = socket.gethostbyaddr(ip.dst)[0]
            except Exception as error:
               log += 1 
            tcp = tcpPacket(ip.src, packet.tcp.srcport, ip.dst, packet.tcp.dstport, src_hostname, dst_hostname)
            if tcp not in counts:
                counts[tcp] = 1
            else:
                counts[tcp] += 1
            thread = myThread(counts, nic)
            thread.start()
        i += 1
    thread.join()

def showDomains():
    print("\n")
    t = Texttable()
    t.add_row(['Source','DN','Port','Destination','DN','Port','packets'])
    for key, value in counts.items():
        t.add_row([key.src, key.src_hostname,key.src_port, key.dst, key.dst_hostname, key.dst_port, value])
    print(t.draw())




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
    try:
        dump_packets(capture, nic)
    except KeyboardInterrupt:
        showDomains()
        sys.exit(0)
if __name__ == '__main__':
     main()
