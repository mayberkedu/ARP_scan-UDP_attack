#!/usr/bin/env python3
# wifi_sniffer.py

import argparse, subprocess, sys, signal, threading, time
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq

def enable_monitor(iface):
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
    subprocess.run(["sudo", "airmon-ng", "start", iface], check=True)
    return iface + "mon", True

def disable_monitor(mon_iface, created):
    if created:
        subprocess.run(["sudo", "airmon-ng", "stop", mon_iface], check=True)
        subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], check=True)

def channel_hopper(iface, stop_evt):
    chans = list(range(1,14))
    idx = 0
    while not stop_evt.is_set():
        ch = chans[idx % len(chans)]
        subprocess.run(
            ["sudo","iwconfig", iface, "channel", str(ch)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        idx += 1
        time.sleep(1)

def main():
    parser = argparse.ArgumentParser("802.11 Sniffer (AP + Probe grouping)")
    parser.add_argument("-i","--iface", required=True,
                        help="Managed interface, e.g. wlan0")
    parser.add_argument("-t","--timeout", type=int, default=30,
                        help="Scan duration in seconds")
    args = parser.parse_args()

    mon_iface, created = enable_monitor(args.iface)

    seen = {}
    # { ssid: { "bssid": <bssid>, "channel": <ch>, "clients": set() } }
    unknown = {}
    # { ssid: set(client_macs) }  for SSIDs we saw only via ProbeReq

    stop_evt = threading.Event()
    hopper = threading.Thread(target=channel_hopper, args=(mon_iface,stop_evt), daemon=True)
    hopper.start()

    def handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            stats = pkt[Dot11Beacon].network_stats()
            ssid = stats.get("ssid") or "<hidden>"
            ch   = stats.get("channel") or "?"
            if ssid not in seen:
                seen[ssid] = {"bssid": bssid, "channel": ch, "clients": set()}
                print(f"\n▶ AP: {ssid!r}\n    BSSID: {bssid}\n    Channel: {ch}\n    Clients probing:")

        elif pkt.haslayer(Dot11ProbeReq):
            client = pkt.addr2
            ssid_req = pkt.info.decode(errors="ignore") or "<broadcast>"
            # if this SSID is one of the seen APs
            if ssid_req in seen:
                grp = seen[ssid_req]
                if client not in grp["clients"]:
                    grp["clients"].add(client)
                    print(f"      • {client}")
            else:
                if ssid_req not in unknown:
                    unknown[ssid_req] = set()
                    print(f"\n▶ Unknown SSID probe: {ssid_req!r}\n    Clients probing:")
                if client not in unknown[ssid_req]:
                    unknown[ssid_req].add(client)
                    print(f"      • {client}")

    signal.signal(signal.SIGINT, lambda *a: None)
    signal.signal(signal.SIGTERM, lambda *a: None)

    print(f"[*] Scanning on {mon_iface} for {args.timeout}s…")
    sniff(iface=mon_iface, prn=handler, store=False, timeout=args.timeout)

    stop_evt.set()
    disable_monitor(mon_iface, created)

    # Final summary
    print("\n\n========== Scan Complete ==========\n")
    for ssid, info in seen.items():
        print(f"AP SSID: {ssid!r}")
        print(f"  BSSID  : {info['bssid']}")
        print(f"  Channel: {info['channel']}")
        if info["clients"]:
            print("  Clients probing:")
            for c in info["clients"]:
                print(f"    - {c}")
        else:
            print("  No clients probed this SSID.")
        print()

    if unknown:
        print("Unknown SSIDs probed by clients:")
        for ssid, clients in unknown.items():
            print(f"SSID: {ssid!r}")
            for c in clients:
                print(f"    - {c}")
            print()

if __name__ == "__main__":
    main()
