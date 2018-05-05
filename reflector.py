#!/usr/bin/env python
from scapy.all import *

victimIp = ''
victimMac = ''
reflectorIp = ''
reflectorMac = ''
interface = ''


def sendArpResponse(packet):
    if packet[ARP].pdst != victimIp and packet[ARP].pdst != reflectorIp:
        return
    arpVictimPacket = ARP(psrc = victimIp, pdst = packet[ARP].psrc, op=ARP.is_at, hwsrc = victimMac, hwdst='ff:ff:ff:ff:ff:ff')
    send(arpVictimPacket)
    arpReflectorPacket = ARP(psrc = reflectorIp, pdst = packet[ARP].psrc, op=ARP.is_at, hwsrc = reflectorMac, hwdst='ff:ff:ff:ff:ff:ff')
    send(arpReflectorPacket)


def sendIPResponse(packet):
    ip_packet = packet.getlayer(IP)
    if packet[IP].dst == victimIp:
        arp_packet = ARP(psrc = reflectorIp, pdst = packet[IP].src ,op = 1)
        send(arp_packet)
        ip_packet[IP].dst, ip_packet[IP].src = packet[IP].src, reflectorIp
        del ip_packet[IP].chksum
        if TCP in ip_packet:
            del ip_packet[TCP].chksum
        if UDP in ip_packet:
            del ip_packet[UDP].chksum
        send(ip_packet)
    if packet[IP].dst == reflectorIp:
        arp_packet = ARP(psrc=victimIp, pdst=packet[IP].src, op=1)
        send(arp_packet)
        ip_packet[IP].dst, ip_packet[IP].src = packet[IP].src, victimIp
        del ip_packet[IP].chksum
        if TCP in ip_packet:
            del ip_packet[TCP].chksum
        if UDP in ip_packet:
            del ip_packet[UDP].chksum
        send(ip_packet)


def call_back(packet):
    if ARP in packet:
        sendArpResponse(packet)
    if IP in packet:
        sendIPResponse(packet)


def main():
    sniff(iface=interface, prn=call_back, store=0, count=0)


if __name__ == "__main__":
    params = {}
    for i in range(0, 5):
        params[sys.argv[2*i+1]] = sys.argv[2*i+2]
    print(params)
    victimIp = params['--victim-ip']
    victimMac = params['--victim-ethernet']
    reflectorIp = params['--reflector-ip']
    reflectorMac = params['--reflector-ethernet']
    interface = params['--interface']
    main()