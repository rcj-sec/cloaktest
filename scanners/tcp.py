"""
Handles TCP related information gathering tasks.
"""
import socket
import random
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

import scapy.all as scapy

import scanners.scanner as scanner
import utils.pretty_print as print
import utils.display as display
import utils.validation as validation

from utils import file_reader
from core.record import singleton as record

ports_json_file = 'data/ports.json'

__scan_network_types = {
    'dst_network_ip': str,
    'dst_network_mask': [type(None), int],
    'dst_ports': [int, list, type(None)],
    'max_threads': int,
    'timeout': int,
    'interval': int
}

__scan_addresses_types = {
    'dst_ips': [str, list],
    'dst_ports': [int, list, type(None)],
    'max_threads': int,
    'timeout': int,
    'interval': int
}

__perform_types = {
    'dst_ip': int,
    'dst_port': int, 
    'timeout': int
}

@validation.function_types(__scan_network_types)
def syn_scan_network(dst_network_ip: str, dst_network_mask: int | None = None, dst_ports: list[int] | None = None, max_threads: int = 100, timeout: int = 1, interval: int = 0) -> list[str]:
    """Perform an SYN scan using SYN packets on a given network and return a list of active hosts. **Wrapper for public use**.

    Args:
        dst_network_ip (str): Destination network IP address. Supports subnet mask. (e.g., '192.168.1.0', '192.168.1.0/24').
        dst_network_mask (None | int, optional): Subnet mask (e.g., 24). Can be left empty is already specified in first argument. Defaults to None.
        dst_ports (list[int] | None, optional): Port or list of ports to scan. Loads ports from **data/ports.json**. Defaults to None.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each SYN packets. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the SYN scan.
    """
    dst_ips, dst_network_ip, dst_network_mask = validation.validate_ip_network(dst_network_ip, dst_network_mask)

    print.info(f'[!] Performing SYN scan on network {dst_network_ip}/{dst_network_mask} ({len(dst_ips)} addresses)')

    return _syn_scan(
        dst_ips=dst_ips,
        dst_ports=dst_ports,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )

@validation.function_types(__scan_addresses_types)
def syn_scan_addresses(dst_ips, dst_ports: None | list[int] = None, max_threads: int = 100, timeout: int = 2, interval: int = 0):
    """Perform an SYN scan using SYN packets on one or many hosts. **Wrapper for public use**.

    Args:
        dst_ips (str | list[str]): IP address or list of IP address to scan.
        dst_ports (list[int] | None, optional): Port or list of ports to scan. Loads ports from **data/ports.json**. Defaults to None.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each SYN packets. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the SYN scan.
    """
    dst_ips = validation.validate_ip_addresses(dst_ips)

    if len(dst_ips) == 1:
        print.info(f'[!] Performing SYN scan on {dst_ips[0]}')
    else:
        print.info(f'[!] Performing SYN scan on {len(dst_ips)} addresses')

    return _syn_scan(
        dst_ips=dst_ips,
        dst_ports=dst_ports,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )
    
def _syn_scan(dst_ips, dst_ports, max_threads, timeout, interval):
    dst_ports = validation.validate_ports(dst_ports or file_reader.read_json_file(ports_json_file))

    live_hosts = scanner.multi_thread_scan(
        dst_ips=dst_ips,
        max_threads=max_threads,
        timeout=timeout, 
        scan_type='syn', 
        interval=interval/1000
    )

    display.ports_details(live_hosts, protcol='tcp')

    return live_hosts

@validation.function_types(__scan_network_types)
def tcp_connect_scan_network(dst_network_ip: str, dst_network_mask: int | None = None, dst_ports: list[int] | None = None, max_threads: int = 100, timeout: int = 1, interval: int = 0) -> list[str]:
    """Perform a TCP CONNECT scan using 3-way handshake on a given network and return a list of active hosts. **Wrapper for public use**.

    Args:
        dst_network_ip (str): Destination network IP address. Supports subnet mask. (e.g., '192.168.1.0', '192.168.1.0/24').
        dst_network_mask (None | int, optional): Subnet mask (e.g., 24). Can be left empty is already specified in first argument. Defaults to None.
        dst_ports (list[int] | None, optional): Port or list of ports to scan. Loads ports from **data/ports.json**. Defaults to None.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each SYN packets. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the TCP CONNECT scan.
    """
    dst_ips, dst_network_ip, dst_network_mask = validation.validate_ip_network(dst_network_ip, dst_network_mask)

    print.info(f'[!] Performing TCP CONNECT scan on network {dst_network_ip}/{dst_network_mask} ({len(dst_ips)} addresses)')

    return _tcp_connect_scan(
        dst_ips=dst_ips,
        dst_ports=dst_ports,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )

@validation.function_types(__scan_addresses_types)
def tcp_connect_scan_addresses(dst_ips, dst_ports: None | list[int] = None, max_threads: int = 100, timeout: int = 2, interval: int = 0) -> list[str]:
    """Perform an TCP CONNECT scan using 3-way handshake on one or many hosts. **Wrapper for public use**.

    Args:
        dst_ips (str | list[str]): IP address or list of IP address to scan.
        dst_ports (list[int] | None, optional): Port or list of ports to scan. Loads ports from **data/ports.json**. Defaults to None.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each SYN packets. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the TCP CONNECT scan.
    """
    dst_ips = validation.validate_ip_addresses(dst_ips)

    if len(dst_ips) == 1:
        print.info(f'[!] Performing TCP CONNECT scan on {dst_ips[0]}')
    else:
        print.info(f'[!] Performing TCP CONNECT scan on {len(dst_ips)} addresses')

    return _tcp_connect_scan(
        dst_ips=dst_ips,
        dst_ports=dst_ports,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )

def _tcp_connect_scan(dst_ip, dst_ports, max_threads=100, timeout=2, interval=0):
    dst_ports = validation.validate_ports(dst_ports or file_reader.read_json_file('data/ports.json'))

    live_hosts = scanner.multi_thread_scan(
        dst_ip=dst_ip,
        dst_ports=dst_ports,
        max_threads=max_threads,
        timeout=timeout,
        scan_type='tcp_connect',
        interval=interval/1000
    )

    display.ports_details(live_hosts, protcol='tcp')

    return live_hosts

@validation.function_types(__perform_types)
def perform_syn_scan(dst_ip: int, dst_port: int, timeout: int = 1) -> bool:
    """Performs a single SYN scan on a port of a targeted host. Returns True if host is up.

    Args:
        dst_ip (int): Targeted host address
        dst_port (int): Targeted port 
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.

    Returns:
        bool: True if host is up, False if host is down or unreachable.
    """
    print.info(f'{dst_ip} : {dst_port}')
    response = _send_syn_packet(dst_ip, dst_port, timeout)

    if response is None:
        return False

    if response.haslayer(scapy.TCP):
        if response[scapy.TCP].flags == 0x12: 
            # SYN-ACK response indicates port is open
            print.info(f'[+] {dst_ip}:{dst_port} is OPEN')
            record.add_port(dst_ip, dst_port, 'tcp', 'opened')
            _send_rst_packet(dst_ip=dst_ip, dst_port=dst_port)
        elif response[scapy.TCP].flags == 0x14:
            # RST_ACK reponse indicates port is closed
            record.add_port(dst_ip, dst_port, 'tcp', 'closed')
        else:
            # Any other response is considered filtered or unknown
            record.add_port(dst_ip, dst_port, 'tcp', 'filtered/unreachable')
        
        # Host is up because we have a TCP layer
        return True
    
    # No TCP layer means host is down or unreachable
    return False

@validation.function_types(__perform_types)
def perform_tcp_connect_scan(dst_ip: int, dst_port: int, timeout: int = 1) -> bool:
    """Performs a single TCP CONNECT scan on a port of a targeted host. Returns True if host is up.

    Args:
        dst_ip (int): Targeted host address
        dst_port (int): Targeted port 
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.

    Returns:
        bool: True if host is up, False if host is down or unreachable.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((dst_ip, dst_port))
            if result == 0:
                print.info(f'{dst_ip} : {dst_port} OK')
                return True
    except Exception as e:
        return False

    return False

def _send_syn_packet(dst_ip, dst_port, timeout):
    ip_header = scapy.IP(dst=dst_ip)
    tcp_header = scapy.TCP(dport=dst_port, flags='S', sport=random.randint(1024, 65535))
    packet = ip_header / tcp_header
    return scapy.sr1(packet, timeout=timeout, verbose=False)

def _send_rst_packet(dst_ip, dst_port):
    ip_header = scapy.IP(dst=dst_ip)
    tcp_header = scapy.TCP(dport=dst_port, flags='S', sport=random.randint(1024, 65535))
    packet = ip_header / tcp_header
    return scapy.send(packet, verbose=False)
