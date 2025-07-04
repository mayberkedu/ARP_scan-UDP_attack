#!/usr/bin/env python3
import argparse, subprocess, time, threading, socket
from scapy.all import sniff, srp
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt
from scapy.layers.dhcp import DHCP ,BOOTP
def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def detect_network(managed):
    # prefix==0 ise tekrar dene
    while True:
        out = subprocess.check_output(
            ["ip","-4","-o","addr","show","dev",managed],
            stderr=subprocess.DEVNULL
        ).decode().split()
        if "inet" in out:
            ip_pref = out[out.index("inet")+1]  # örn "192.168.1.10/24"
            ip, prefix = ip_pref.split("/")
            if prefix != "0":
                return f"{ip}/{prefix}"
        time.sleep
def enter_monitor(monitor):
    run(["sudo","airmon-ng","start", monitor])
    # airmon-ng çıktısı genellikle "<monitor>mon" arayüzünü açar
    return monitor + "mon"

def exit_monitor(mon):
    run(["sudo","airmon-ng","stop", mon])
    run(["sudo","systemctl","restart","NetworkManager"])

def channel_hopper(iface, stop_evt):
    chans = list(range(1,15))
    i = 0
    while not stop_evt.is_set():
        ch = chans[i % len(chans)]
        run(["sudo","iwconfig", iface, "channel", str(ch)])
        i += 1
        time.sleep(0.3)

def wifi_sniff(monitor, timeout, ap_data):
    stop_hop = threading.Event()
    th = threading.Thread(target=channel_hopper, args=(monitor, stop_hop), daemon=True)
    th.start()

    def pkt_handler(pkt):
        if not pkt.haslayer(Dot11): return
        d11 = pkt.getlayer(Dot11)
        # Beacon
        if pkt.haslayer(Dot11Beacon):
            bssid = d11.addr2
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info else "<hidden>"
            elt = pkt.getlayer(Dot11Elt, 3)
            ch = elt.info[0] if elt else None
            ap_data.setdefault(bssid, {"ssid": ssid, "channel": ch, "clients": set()})
            print(f"[BEACON] SSID='{ssid}'  BSSID={bssid} CH={ch}")
        # ProbeReq
        elif pkt.haslayer(Dot11ProbeReq):
            client = d11.addr2
            print(f"[PROBE] Client probing: {client}")
        # Data frame
        elif d11.type == 2:
            src, dst = d11.addr2, d11.addr1
            if dst in ap_data:
                ap_data[dst]["clients"].add(src)
            print(f"[DATA] {src} → {dst}")

    sniff(iface=monitor, prn=pkt_handler, timeout=timeout, store=False)
    stop_hop.set()
    th.join()

def dhcp_sniff(managed, timeout, dhcp_hosts):
    def handler(pkt):
        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            mac = pkt[Ether].src
            ip = pkt[BOOTP].yiaddr
            name = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0]=="hostname":
                    name = opt[1].decode() if isinstance(opt[1], bytes) else opt[1]
            dhcp_hosts[mac] = (ip, name or "-")
            print(f"[DHCP] {mac} → {ip}  Hostname={name or '-'}")
    sniff(iface=managed, filter="udp and (port 67 or port 68)", prn=handler, timeout=timeout, store=False)

def arp_scan(managed, cidr):
    devices = {}
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr),
                 iface=managed, timeout=3, verbose=False)
    for snd, rcv in ans:
        mac = rcv[Ether].src
        ip  = rcv[ARP].psrc
        # ters DNS dene
        try:
            name = socket.gethostbyaddr(ip)[0]
        except:
            name = "-"
        devices[mac] = (ip, name)
    return devices

def main():
    p = argparse.ArgumentParser("Multi‐Channel Wi-Fi + ARP‐Scan Discovery")
    p.add_argument("-i","--managed-iface", required=True, help="örn. wlan0")
    p.add_argument("-m","--monitor-iface", required=True, help="örn. wlan1 (airmon ile) ")
    p.add_argument("-t","--timeout", type=int, default=15)
    args = p.parse_args()

    # monitor mode başlat
    mon = enter_monitor(args.monitor_iface)
    ap_data    = {}
    dhcp_hosts = {}

    print(f"[+] {args.monitor_iface} → {mon} (monitor mode enabled)")
    # 1) Beacon/Probe/Data sniff
    print(f"🔍 Sniffing Wi-Fi on {mon} for {args.timeout}s…")
    wifi_sniff(mon, args.timeout, ap_data)
    # monitor kapat
    exit_monitor(mon)
    print(f"[+] {mon} stopped, {args.managed_iface} back to managed mode")

    # 2) Ağ detect & DHCP sniff
    cidr = detect_network(args.managed_iface)
    print(f"[*] Detected network: {cidr}")
    print(f"🔍 Sniffing DHCP on {args.managed_iface} for {args.timeout}s…")
    dhcp_sniff(args.managed_iface, args.timeout, dhcp_hosts)

    # 3) ARP scan
    print(f"🔍 ARP-scan on {cidr} via {args.managed_iface}…")
    arp_devs = arp_scan(args.managed_iface, cidr)

    # 4) Sonuçları yazdır
    print("\n===== RESULTS =====\n-- APs & Clients --")
    for bssid, info in ap_data.items():
        ssid, ch, clients = info["ssid"], info["channel"], info["clients"]
        print(f"'{ssid}'  BSSID={bssid}  CH={ch}")
        if clients:
            for c in clients:
                ip,name = arp_devs.get(c, ("-", "-"))
                # DHCP’dan gelen hostname varsa o tercih edilir
                if c in dhcp_hosts:
                    ip,name = dhcp_hosts[c]
                print(f"  • {c}  IP={ip}  Name={name}")
        else:
            print("  • (no clients seen)")

    print("\n-- ARP-scan: MAC → IP → Hostname --")
    for mac,(ip,name) in arp_devs.items():
        # DHCP hostname varsa onu göster
        if mac in dhcp_hosts:
            ip2,name2 = dhcp_hosts[mac]
            name = name2
            ip   = ip2
        print(f"{mac} → {ip}  Name={name}")

if __name__=="__main__":
    main()
