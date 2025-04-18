"""
Module to call the different types of scans supported using a dictionary as dipatch table.

Functions:
- dispatch_scan: Dispatcher entry point.
"""
from . import icmp
from . import arp
from . import tcp

def dispatch_icmp(dst_ip, timeout, **extra):
    return icmp.perform_icmp_ping(
        dst_ip=dst_ip, 
        timeout=timeout
    )

def dispatch_arp(dst_ip, timeout, **extra):
    return arp.perform_arp_scan(
        dst_ip=dst_ip, 
        src_iface=extra['src_iface'], 
        timeout=timeout
    )

def dispatch_syn(dst_ip, timeout, **extra):
    return tcp.perform_syn_scan(
        dst_ip=dst_ip, 
        dst_port=extra['dst_port'], 
        timeout=timeout
    )

def dispatch_tcp_connect(dst_ip, timeout, **extra):
    return tcp.perform_tcp_connect_scan(
        dst_ip=dst_ip, 
        dst_port=extra['dst_port'], 
        timeout=timeout
    )

SCAN_DISPATCH_TABLE = {
    'icmp': dispatch_icmp,
    'arp': dispatch_arp,
    'syn': dispatch_syn,
    'tcp_connect': dispatch_tcp_connect,
}

def dispatch_scan(dst_ip, timeout, scan_type, **extra):
    scanner = SCAN_DISPATCH_TABLE.get(scan_type)
    return scanner(dst_ip=dst_ip, timeout=timeout, **extra)