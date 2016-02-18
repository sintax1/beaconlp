#!/usr/bin/env python

import sys
import os
sys.path.append(os.getcwd())

from scapy.all import *  # noqa
from messages import Beacon
import time


def send_icmp_beacon(dst=None, beacon=None):
    print "Sending ICMP:", beacon.toJson()
    print beacon.pack().encode('hex')
    packet = IP(dst=dst)/ICMP()/beacon.pack()
    send(packet)


def send_udp_beacon(dst=None, beacon=None):
    print "Sending UDP:", beacon.toJson()
    print beacon.pack().encode('hex')
    packet = IP(dst=dst)/UDP(dport=53)/beacon.pack()
    send(packet)


def send_tcp_beacon(dst=None, beacon=None):
    print "Sending TCP:", beacon.toJson()
    print beacon.pack().encode('hex')
    packet = IP(dst=dst)/TCP(dport=443)/beacon.pack()
    send(packet)


if __name__ == "__main__":
    implant_uuid = 'b9dbdeb0-85de-49b7-b9a3-6f6f02dcde77'
    type = 0x01
    format = 0x01
    message_data = 'testing message'

    dest_ip = '172.16.201.245'

    beacon_ping = Beacon(
        uuid='b9dbdeb0-85de-49b7-b9a3-6f6f02dcde77',
        type=0x00,
        format=0x00)

    beacon_data = Beacon(
        uuid='b9dbdeb0-85de-49b7-b9a3-6f6f02dcde77',
        type=0x01,
        format=0x00,
        data='test')

    while True:

        beacon = beacon_ping
        beacon.uuid = 'b9dbdeb0-85de-49b7-b9a3-6f6f02dcde01'
        send_icmp_beacon(dst=dest_ip, beacon=beacon)
        time.sleep(5)

        beacon = beacon_data
        beacon.uuid = 'b9dbdeb0-85de-49b7-b9a3-6f6f02dcde02'
        send_icmp_beacon(dst=dest_ip, beacon=beacon)
        time.sleep(5)

        beacon = beacon_ping
        beacon.uuid = 'b9dbdeb0-85de-49b7-b9a3-6f6f02dcde03'
        send_udp_beacon(dst=dest_ip, beacon=beacon)
        time.sleep(5)

        beacon = beacon_data
        beacon.uuid = 'b9dbdeb0-85de-49b7-b9a3-6f6f02dcde04'
        send_udp_beacon(dst=dest_ip, beacon=beacon)
        time.sleep(5)

        beacon = beacon_ping
        beacon.uuid = 'b9dbdeb0-85de-49b7-b9a3-6f6f02dcde05'
        send_tcp_beacon(dst=dest_ip, beacon=beacon)
        time.sleep(5)

        beacon = beacon_data
        beacon.uuid = 'b9dbdeb0-85de-49b7-b9a3-6f6f02dcde06'
        send_tcp_beacon(dst=dest_ip, beacon=beacon)
        time.sleep(5)
