import ipaddress
import os
import socket
import struct
import sys
import time
import traceback

# TODO ckeck administrator privileges are enabled

# calculate checksum
def get_checksum(data):
    if len(data) % 2:
        data += b'\x00'# make data length even

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]# combine data into 16-bit word
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    # invert bits and return 16 bits
    return ~checksum & 0xffff

class ICMPPing:
    # create ICMP packet and ping target host
    def __init__(self, target_addr):
        self.packet_ID = os.getpid() & 0xffff
        self.timeout = 2
        self.sequence_num = 0

        packet = self.create_packet()

        self.ping_host(target_addr, packet)

    # create ICMP packet
    def create_packet(self):
        header = struct.pack('!BBHHH', 8, 0, 0, self.packet_ID, self.sequence_num)

        extra_data_len = 56# length needed to reach 64 bytes
        extra_data = str.encode(extra_data_len * 'A')

        checksum = get_checksum(header + extra_data)

        # reconstruct packet with checksum
        header = struct.pack('!BBHHH', 8, 0, checksum, self.packet_ID, self.sequence_num)

        return header + extra_data

    # set up socket and ping host specified by address
    def ping_host(self, target_addr, packet):
        try:
            dst_addr = socket.gethostbyname(target_addr)
        except socket.gaierror as e:
            print('Error: cannot resolve hostname %s' % (target_addr))

        # create ICMP socket and set timeout
        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        except socket.error as e:
            traceback.print_exception(e)
            return

        icmp_socket.settimeout(self.timeout)

        # send ICMP Echo Request to target
        try:
            bytes_sent = icmp_socket.sendto(packet, (dst_addr, 0))
            time_sent = time.time()
            print('Sent %d bytes to %s' % (bytes_sent, dst_addr))
        except socket.error as e:
            traceback.print_exception(e)
            icmp_socket.close()
            return

        # receive ICMP Echo Reply from target and record rtt
        reply_packet = None

        try:
            reply_packet, src_addr = icmp_socket.recvfrom(1024)# read up to 1024 bytes from socket
            time_received = time.time()
            rtt = time_received - time_sent
        except socket.timeout:
            print('Request timed out')
            return
        except socket.error as e:
            traceback.print_exception(e)
            return
        finally:
            icmp_socket.close()

        # TODO check source and destination addresses match

        # parse Echo Reply
        ip_header = reply_packet[:20]# first 20 bytes of reply packet is the IP header
        version_and_ihl, tos, packet_len, identification, flags_and_offset, ttl, protocol, checksum, src_ip, dst_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        ip_header_len = (version_and_ihl & 0x0f) * 4# bit masking to extract IP header length

        icmp_header = reply_packet[ip_header_len:ip_header_len + 8]
        icmp_type, code, checksum, packet_id, sequence_num = struct.unpack('!BBHHH', icmp_header)

        # TODO check ID and sequence numbers match

        print('Reply received from %s' % (dst_addr))

target_addr = sys.argv[1]
ping = ICMPPing(target_addr)

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