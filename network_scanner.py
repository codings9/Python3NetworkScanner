#!/usr/bin/env python
# NetWork Scanner
# By codings9 AKA MunYa

import scapy.all as scapy

def scan(ip, answered=None):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

#Please note, i wrote this to learn about Python and Network Discovery:
# Change scan value to your Routers Gateway Ip: scan("You Default Gateway")
# Yes, i know you can easily just type: arp-scan -l OR netdiscover but this was fun 4 me, lol!
scan_result = scan("10.185.1.1/24")
print_result(scan_result)
