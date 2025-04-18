"""
Handles ARP related information gathering tasks.
"""
import requests
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

import scapy.all as scapy

import scanners.scanner as scanner
import utils.pretty_print as print
import utils.display as display
import utils.validation as validation

from core.record import singleton as record

__arp_scan_network_types = {
    'dst_network_ip': str,
    'dst_network_mask': [type(None), int],
    'src_iface': str,
    'max_threads': int,
    'timeout': int,
    'interval': int
}

__scan_arp_addresses_types = {
    'dst_ips': [str, list],
    'src_iface': str,
    'max_threads': int,
    'timeout': int,
    'interval': int
}

__perform_arp_scan_types = {
    'dst_ip': str,
    'src_iface': str,
    'timeout': int
}

@validation.function_types(__arp_scan_network_types)
def arp_scan_network(dst_network_ip: str, src_iface: str, dst_network_mask: None | int = None, max_threads: int = 100, timeout: int = 1, interval: int = 0) -> list[str]:
    """Perform an ARP scan using ARP requests on a given network and return a list of active hosts. **Wrapper for public use**.

    Args:
        dst_network_ip (str): Destination network IP address. Supports subnet mask. (e.g., '192.168.1.0', '192.168.1.0/24').
        src_iface (str): Source network interface to send the ARP request from (e.g., 'wlo1').
        dst_network_mask (None | int, optional): Subnet mask (e.g., 24). Can be left empty is already specified in first argument. Defaults to None.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each ARP request. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the ARP scan.
    """
    dst_ips, dst_network_ip, dst_network_mask = validation.validate_ip_network(dst_network_ip, dst_network_mask)

    print.info(f'[!] Performing ARP scan on network {dst_network_ip}/{dst_network_mask} ({len(dst_ips)} addresses)')

    return _arp_scan(
        dst_ips=dst_ips,
        src_iface=src_iface,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )

@validation.function_types(__scan_arp_addresses_types)
def arp_scan_addresses(dst_ips: str | list[str], src_iface: str, max_threads: int = 100, timeout: int = 1, interval: int = 0) -> list[str]:
    """Perform an ARP scan using ARP requests on one or many hosts. **Wrapper for public use**.

    Args:
        dst_ips (str | list[str]): IP address or list of IP address to scan.
        src_iface (str): _description_
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each ARP request. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the APR scan.
    """
    dst_ips = validation.validate_ip_addresses(dst_ips)

    if len(dst_ips) == 1:
        print.info(f'[!] Performing ARP scan on {dst_ips[0]}')
    else:
        print.info(f'[!] Performing ARP scan on {len(dst_ips)} addresses')

    return _arp_scan(
        dst_ips=dst_ips,
        src_iface=src_iface,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )

def _arp_scan(dst_ips, src_iface, max_threads, timeout, interval):
    live_hosts = scanner.multi_thread_scan(
        dst_ips=dst_ips, 
        src_iface=src_iface, 
        max_threads=max_threads, 
        timeout=timeout,
        scan_type='arp',
        interval=interval/1000
    )

    display.arp_details(live_hosts, src_iface)

    return live_hosts

@validation.function_types(__perform_arp_scan_types)
def perform_arp_scan(dst_ip: str, src_iface: str, timeout: int = 1) -> bool:
    """Performs a single ARP request and hostname resolution on targeted host through the specified interface. Returns True if ARP request is successful.

    Args:
        dst_ip (str): Targeted host address
        src_iface (str): Interface used to send ARP request from.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.

    Returns:
        bool: True if ARP request is successful. False if not.
    """
    mac_address = _send_arp_request(dst_ip, src_iface, timeout)

    if mac_address:
        vendor = _lookup_mac_vendor(mac_address)
        record.add_host_spec(dst_ip, 'MAC address', mac_address)
        record.add_host_spec(dst_ip, 'Vendor', vendor)
        return True
    
    return False

def _send_arp_request(dst_ip, src_iface, timeout):
    arp_request = scapy.ARP(pdst=dst_ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered, _ = scapy.srp(arp_request_broadcast, timeout=timeout, iface=src_iface, verbose=False)

    if answered:
        mac_address = answered[0][1].hwsrc
        return mac_address
    
    return None

def _lookup_mac_vendor(address):
    print.info(f'[!] Looking up {address}')
    url = f'https://www.macvendorlookup.com/api/v2/{address}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()  # Parse JSON response
            if data:
                return data[0].get("company", "Unknown")
            return 'Unknown'
    except Exception as e:
        print.error(f'[!] Error with MAC lookup: {e}')
        return 'Error'