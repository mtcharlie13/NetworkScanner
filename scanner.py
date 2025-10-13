import ipaddress
import os
import struct
import sys
import time

# calculate checksum
def get_checksum(data):
    if len(data) % 2:
        data += b'\x00'# make data length even

    checksum = 0
    for i in range(0, len(data), 2):
        data = (data[i] << 8) + data[i + 1]# combine data into 16-bit word
        checksum += data
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # invert bits and return 16 bits
    return ~checksum & 0xffff

class ICMPPing:
    # create ICMP packet and ping target host
    def __init__(self, target_addr):
        self.packet_ID = os.getpid() & 0xffff
        self.timeout = 2
        self.sequence_num = 0

        packet = self.create_packet

    # create ICMP packet
    def create_packet(self):
        header = struct.pack('!BBHHH', 8, 0, 0, self.packet_ID, self.sequence_num)

        payload = struct.pack('!d', time.time())# record time sent

        extra_data_len = 48# length needed to reach 64 bytes
        extra_data = str.encode(extra_data_len * 'A')

        checksum = get_checksum(header + payload + extra_data)

        # reconstruct packet with checksum
        header = struct.pack('!BBHHH', 8, 0, checksum, self.packet_ID, self.sequence_num)

        return header + payload + extra_data

    # send ICMP Echo Request to target
    # def send_request(self, target_addr):

    # receive ICMP Echo Reply from target
    # def receive_reply(self, target_addr):

    # ping host specified by address
    # def ping_host(self, target_addr):

class NetworkScanner:
    # scan a single host and output address if host is active
    def scan_host(self, target_addr):
        print(target_addr)

    # scan each host in network range
    def scan_network(self, network_addr):
        # TODO check network address is in the correct format
        
        addr_count = 2 ** (32 - int(network_addr.split('/')[1]))
        print('Scanning %d hosts on %s...' % (addr_count, network_addr))

        network = ipaddress.ip_network(network_addr, strict=False)
        for addr in network.hosts():
            self.scan_host(addr)

network_addr = sys.argv[1]
scanner = NetworkScanner()
scanner.scan_network(network_addr)