# !/usr/bin/env python
"""packet.py
Project 1: Packet Analyser
An application that reads a set of packets and produces a detailed summary of those packets
"""
__author__ = "Savitha Jayasankar"

import binascii
import sys
import struct
import socket


def get_hex(filename):
    hex_data = b''
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(32), b''):
            hex_data += binascii.hexlify(chunk)

    return hex_data


def analyse_packet_ethernet_header(hex_data):
    destination_mac = get_mac(hex_data[0:12])
    source_mac = get_mac(hex_data[12:24])
    ether_type = hex_data[24:28]
    print("\nETHER : -----Ether header-----")
    print("ETHER : ")
    print("ETHER: Destination MAC = {}".format(destination_mac))
    print("ETHER: Source MAC = {}".format(source_mac))
    print("ETHER: EtherType = {} (IP)".format(ether_type))
    print("ETHER : ")


def get_mac(raw_mac):
    raw_mac = raw_mac.decode('utf-8')
    return ':'.join([raw_mac[i:i + 2] for i, j in enumerate(raw_mac) if not (i % 2)])


def analyse_packet_ip_header(hex_data):
    version = hex_data[:1]
    header_length = int(hex_data[1:2]) * 4
    type_of_service_raw = '{:08b}'.format(int(hex_data[2:4], 16))
    precedence = type_of_service_raw[:3]
    type_of_service = type_of_service_raw[3:]

    total_length = int(hex_data[4:8], 16)
    identification_decimal = int(hex_data[8:12], 16)
    identification_hex = hex_data[8:12]

    value_flag_offset = '{:016b}'.format(int(hex_data[12:16], 16))
    flag_value = hex(int(value_flag_offset[:4], 2))
    reserve_flag = value_flag_offset[0:1]
    df_flag = value_flag_offset[1:2]
    mf_flag = value_flag_offset[2:3]

    fragment_offset = value_flag_offset[3:]

    time_to_live = int(hex_data[16:18], 16)

    protocol_field = int(hex_data[18:20], 16)

    header_checksum = hex_data[20:24]

    source_ip = get_ip(int(hex_data[24:32], 16))
    try:
        source_host = socket.gethostbyaddr(source_ip)[0]
    except:
        source_host = 'Unknown host'

    destination_ip = get_ip(int(hex_data[32:40], 16))
    try:
        destination_host = socket.gethostbyaddr(destination_ip)[0]
    except:
        destination_host = 'Unknown host'

    print("\nIP : -----IP header-----")
    print("IP : ")
    print('IP: Version = {}'.format(version))
    print('IP: Header length = {} bytes'.format(header_length))

    print('IP: Type of service = {} '.format(hex(int(type_of_service, 2))))
    print('IP:      xxx. .... = {} ( precedence )'.format(precedence))
    print('IP:      ...{} .... = normal  delay'.format(type_of_service[:1]))
    print('IP:      .... {}... = normal throughput'.format(type_of_service[1:2]))
    print('IP:      .... .{}.. = normal reliability'.format(type_of_service[2:3]))
    print('IP: Total length = {} bytes'.format(total_length))
    print('IP: Identification = {} ( {} )'.format(identification_hex, identification_decimal))
    print('IP: Flags = {}'.format(flag_value))
    print('IP:      {}... .... = reserve flag'.format(reserve_flag))
    print('IP:      .{}... .... = do not fragment '.format(df_flag))
    print('IP:      ..{}. .... = last fragment'.format(mf_flag))
    print('IP: Fragment Offset = {} bytes'.format(int(fragment_offset, 2) * 4))
    print('IP: Time to live = {} seconds/hops'.format(time_to_live))
    print('IP: Protocol Field = {}'.format(protocol_field))
    print('IP: Header Checksum = {}'.format(header_checksum))
    print('IP: Source IP = {} , {}'.format(source_ip, source_host))
    print('IP: Destination IP = {} , {}'.format(destination_ip, destination_host))
    print("IP : ")

    return protocol_field


def get_ip(raw_ip):
    rough_ip = socket.inet_ntoa(struct.pack("<L", raw_ip))

    return ".".join(str(x) for x in reversed(rough_ip.split('.')))


def analyse_packet_tcp(tcp_header):
    print(tcp_header)
    source_port = int(tcp_header[:4], 16)
    destination_port = int(tcp_header[4:8], 16)

    sequence_number = int(tcp_header[8:16], 16)
    acknowledgement_number = int(tcp_header[16:24], 16)

    data_offset = int(tcp_header[24:25]) * 4

    raw_reserve_control = '{:012b}'.format(int(tcp_header[25:28], 16))
    reserved = raw_reserve_control[:3]
    nonce = raw_reserve_control[3:4]
    cwr = raw_reserve_control[4:5]
    ecn = raw_reserve_control[5:6]
    URG = raw_reserve_control[6:7]
    ACK = raw_reserve_control[7:8]
    PSH = raw_reserve_control[8:9]
    RST = raw_reserve_control[9:10]
    SYN = raw_reserve_control[10:11]
    FIN = raw_reserve_control[11:12]

    window = int(tcp_header[28:32], 16)
    checksum = tcp_header[32:36]
    urgent = tcp_header[36:40]
    data = tcp_header[40:]
    print("\nTCP : -----TCP header-----")
    print("TCP : ")
    print("TCP: Source Port = {}".format(source_port))
    print("TCP: Destination Port = {}".format(destination_port))
    print("TCP: Sequence Number = {}".format(sequence_number))
    print("TCP: ACK = {}".format(acknowledgement_number))
    print("TCP: Data Offset = {} bytes".format(data_offset))

    print("TCP: Reserved = {}".format(reserved))
    print("TCP: Nonce = {}".format(nonce))
    print("TCP: CWR = {}".format(cwr))
    print("TCP: ECN = {}".format(ecn))
    print("TCP : Flags = {}".format(hex(int(raw_reserve_control, 2))))
    print("TCP:     ..{}. .... = No urgent pointer".format(URG))
    print("TCP:     ...{} .... = Acknowledgement".format(ACK))
    print("TCP:     .... {}... = Push".format(PSH))
    print("TCP:     .... .{}.. = No reset".format(RST))
    print("TCP:     .... ..{}. = No Syn".format(SYN))
    print("TCP:     .... ...{} = No fin".format(FIN))
    print("TCP: Window = {}".format(window))
    print("TCP: Checksum = {}".format(checksum))
    print("TCP: Urgent = {}".format(urgent))
    print("TCP: DATA = {}".format(data))


def analyse_packet_udp(udp_header):
    source_port = int(udp_header[:4], 16)
    destination_port = int(udp_header[4:8], 16)
    length = int(udp_header[8:12], 16)
    checksum = udp_header[12:16]
    data = udp_header[16:]
    print("\nUDP : -----UDP header-----")
    print("UDP : ")
    print("UDP: Source Port = {}".format(source_port))
    print("UDP: Destination Port = {}".format(destination_port))
    print("UDP: Length = {} bytes".format(length))
    print("UDP: CheckSum = {}".format(checksum))
    print("UDP: Data = {}".format(data))


def analyse_packet_icmp(icmp_header):
    icmp_type = int(icmp_header[:2], 16)
    code = int(icmp_header[2:4], 16)
    checksum = icmp_header[4:8]
    be_identifier = icmp_header[8:12]
    le_identifier = icmp_header[12:16]
    be_sequence = icmp_header[16:20]
    le_sequence = icmp_header[20:24]
    data = icmp_header[24:]
    print("\nICMP : -----ICMP header-----")
    print("ICMP : ")
    print("ICMP: Type={}".format(icmp_type))
    print("ICMP: Code={}".format(code))
    print("ICMP: Checksum={}".format(checksum))
    print("ICMP: BE Identifier={}".format(be_identifier))
    print("ICMP: LE Identifier={}".format(le_identifier))
    print("ICMP: BE Sequence={}".format(be_sequence))
    print("ICMP: LE Sequence={}".format(le_sequence))
    print("ICMP: Data={}".format(data))


if __name__ == '__main__':
    hex_data = get_hex(sys.argv[1])
    analyse_packet_ethernet_header(hex_data[0:28])
    protocol_field = analyse_packet_ip_header(hex_data[28:68])
    if protocol_field == 6:
        analyse_packet_tcp(hex_data[68:])
    elif protocol_field == 17:
        analyse_packet_udp(hex_data[68:])
    elif protocol_field == 1:
        analyse_packet_icmp(hex_data[68:])
