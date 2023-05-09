import argparse
import os
import logging

from dns import reversename
from ipaddress import ip_address

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.plist import PacketList
from scapy.sendrecv import sr1

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


resolved_hosts = {}


def is_ip(s):
    try:
        ip_address(s)
    except ValueError:
        return False
    return True


def resolve_ip(hostname, qtype="A"):
    dns_resp = sr1(IP(dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname=hostname, qtype=qtype)), verbose=0, timeout=2)
    if dns_resp and dns_resp[DNS]:
        for x in range(dns_resp[DNS].ancount):
            s = dns_resp[DNSRR][x].rdata
            return s
    return None


def get_ip(request, ipv6=False):
    if is_ip(request):
        return request
    return resolve_ip(request, "AAAA" if ipv6 else "A")


def resolve_host(ip_addr):
    r = reversename.from_address(ip_addr)
    dns_resp = sr1(IP(dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname=r.to_text()[:-1], qtype='PTR')), verbose=0,
                   timeout=2)
    resp = []
    if dns_resp and dns_resp[DNS]:
        for x in range(dns_resp[DNS].ancount):
            s = dns_resp[DNSRR][x].rdata
            resp.append(s.decode("utf-8")[:-1])
    return resp


def get_hostnames(ip_addr):
    global resolved_hosts
    if ip_addr not in resolved_hosts:
        hosts = resolve_host(ip_addr)
        resolved_hosts[ip_addr] = hosts
    return resolved_hosts[ip_addr]


def tcp_packet(target_ip, ttl, ipv6):
    if ipv6:
        return IPv6(dst=target_ip, hlim=ttl) / TCP(dport=80, flags="S")
    return IP(dst=target_ip, ttl=ttl) / TCP(dport=80, flags="S")


def udp_packet(target_ip, ttl, ipv6):
    if ipv6:
        return IPv6(dst=target_ip, hlim=ttl) / UDP(dport=33433 + ttl) / DNS()
    return IP(dst=target_ip, ttl=ttl) / UDP(dport=33433 + ttl) / DNS()


def icmp_packet(target_ip, ttl, ipv6):
    if ipv6:
        return IPv6(dst=target_ip, hlim=ttl) / ICMPv6EchoRequest()
    return IP(dst=target_ip, ttl=ttl) / ICMP()


stats = {}


def update_stats(ttl, r=None):
    global stats
    if ttl not in stats:
        stats[ttl] = {"ip": None, "send": 0, "recv": 0}
    if r is not None:
        if stats[ttl]["ip"] is None or stats[ttl]["ip"] != r.src:
            stats[ttl]["ip"] = r.src
            stats[ttl]["send"] = 0
            stats[ttl]["recv"] = 0
        stats[ttl]["recv"] += 1
    stats[ttl]["send"] += 1


def clear_after(ttl, max_hops):
    global stats
    for t in range(ttl + 1, max_hops):
        stats.pop(t, None)


def print_stat_line(ttl):
    global stats
    line = stats[ttl]

    if line["ip"] is None:
        print(f"{ttl}. (waiting for reply)")
    else:
        ip = line["ip"]
        loss = line["recv"] / line["send"]
        hostnames = get_hostnames(ip)
        if hostnames:
            hostname = hostnames[0]
            print(f"{ttl}. {hostname:40s}\t\t\t\t{(1 - loss) * 100:5.1f}% {line['send']:8d}")
            for hostname in hostnames[1:]:
                print(" " * (len(str(ttl)) + 2) + hostname)
        else:
            print(f"{ttl}. {ip:40s}\t\t\t\t{(1 - loss) * 100:5.1f}% {line['send']:8d}")


def print_stats():
    print("Host\t\t\t\t\t\t\t\t\t Loss%\t    Snt")
    global stats
    for ttl in sorted(stats.keys()):
        print_stat_line(ttl)


def is_done(reply, target_ip):
    if reply is None:
        return False
    return reply.src == target_ip


def get_timeout(i, ttl, max_ttl):
    global stats
    if ttl not in stats:
        return 1

    line = stats[ttl]
    if line["ip"] is None:
        if i % max_ttl == ttl:
            return 1
        else:
            return 0.01
    else:
        return 1


def main(args):
    os.system("clear")
    os.system("tput reset")
    target_ip = get_ip(args.hostname, vars(args)['6'])
    ipv6 = vars(args)['6'] or ':' in target_ip
    if target_ip is None:
        print("Unable to resolve " + args.hostname)
        return -1

    if args.udp and args.tcp:
        print("udp and tcp are not allowed at the same time")
        return -1
    form_packet = icmp_packet
    if args.udp:
        form_packet = udp_packet
    elif args.tcp:
        form_packet = tcp_packet

    get_ttl = lambda x: x.ttl
    if ipv6:
        get_ttl = lambda x: x.hlim

    packets = []
    for ttl in range(1, args.max_ttl):
        packet = form_packet(target_ip, ttl, ipv6)
        packets.append(packet)
    packet_list = PacketList(packets)

    for i in range(args.report_cycles):
        for s in packet_list:
            ttl = get_ttl(s)
            r = sr1(s, verbose=0, timeout=get_timeout(i, ttl, args.max_ttl))
            update_stats(ttl, r)
            os.system("tput reset")
            print_stats()

            if is_done(r, target_ip):
                clear_after(ttl, args.max_ttl)
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname")
    parser.add_argument("-6", help="use IPv6 instead of IPv4", action="store_true")
    parser.add_argument("-u", "--udp", help="use UDP instead of ICMP echo", action="store_true")
    parser.add_argument("-T", "--tcp", help="use TCP instead of ICMP echo", action="store_true")
    parser.add_argument("-m", "--max-ttl", type=int, default=30, help="maximum number of hops")
    parser.add_argument("-c", "--report-cycles", type=int, default=5, help="set the number of pings sent")
    args = parser.parse_args()

    main(args)
