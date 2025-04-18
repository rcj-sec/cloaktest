"""
Handles ICMP related information gathering tasks.
"""
import subprocess

import scanners.scanner as scanner
import utils.display as display
import utils.pretty_print as print
import utils.validation as validation

from core.record import singleton as record

__icmp_scan_network_types = {
    'dst_network_ip': str,
    'dst_network_mask': [type(None), int],
    'max_threads': int,
    'timeout': int,
    'interval': int
}

__icmp_scan_addresses_types = {
    'dst_ips': [str, list],
    'max_threads': int,
    'timeout': int,
    'interval': int
}

__perform_icmp_ping_types = {
    'dst_ip': str,
    'timeout': 1,
}

@validation.function_types(__icmp_scan_network_types)
def icmp_scan_network(dst_network_ip: str, dst_network_mask: None | int = None, max_threads: int = 100, timeout: int = 1, interval: int = 0) -> list[str]:
    """Perform an ICMP scan using **ping** command on a given network and return a list of active hosts. **Wrapper for public use**.

    Args:
        dst_network_ip (str): Destination network IP address. Supports subnet mask. (e.g., '192.168.1.0', '192.168.1.0/24').
        dst_network_mask (None | int, optional): Subnet mask (e.g., 24). Can be left empty is already specified in first argument. Defaults to None.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each ICMP request. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the ICMP scan.
    """
    dst_ips, dst_network_ip, dst_network_mask = validation.validate_ip_network(dst_network_ip, dst_network_mask)

    print.info(f'[!] Performing ICMP scan on network {dst_network_ip}/{dst_network_mask} ({len(dst_ips)} addresses)')

    return _icmp_scan(
        dst_ips=dst_ips,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )

@validation.function_types(__icmp_scan_addresses_types)
def icmp_scan_addresses(dst_ips: str | list[str], max_threads: int = 100, timeout: int = 1, interval: int = 0) -> list[str]:
    """Perform an ICMP scan using **ping** command on one or many hosts. **Wrapper for public use**.

    Args:
        dst_ips (str | list[str]): IP address or list of IP address to scan.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 100.
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.
        interval (int, optional): Milliseconds between each ICMP request. Defaults to 0 (no delay).

    Returns:
        list[str]: List of host IP addresses that responded to the APR scan.
    """
    dst_ips = validation.validate_ip_addresses(dst_ips)

    if len(dst_ips) == 1:
        print.info(f'[!] Performing ICMP scan on {dst_ips[0]}')
    else:
        print.info(f'[!] Performing ICMP scan on {len(dst_ips)} addresses')

    return _icmp_scan(
        dst_ips=dst_ips,
        max_threads=max_threads,
        timeout=timeout,
        interval=interval
    )

def _icmp_scan(dst_ips, max_threads, timeout, interval):
    live_hosts = scanner.multi_thread_scan(
        dst_ips=dst_ips, 
        max_threads=max_threads, 
        timeout=timeout, 
        scan_type='icmp', 
        interval=interval/1000
    )

    display.icmp_ping_details(live_hosts)

    return live_hosts

@validation.function_types(__perform_icmp_ping_types)
def perform_icmp_ping(dst_ip: str, timeout: int = 1) -> bool:
    """Attempt to  ping targeted host. Returns True if ping is successful.

    Args:
        dst_ip (str): Targeted host address
        timeout (int, optional): Seconds to wait for reply. Defaults to 1.

    Returns:
        bool: True if ping is successful. False if not.
    """
    command = ['ping', '-c', '5', '-W', str(timeout), dst_ip]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if 'ttl=' in line.lower():
                ttl = int(line.split('ttl=')[1].split()[0])
                if ttl == 255:
                    os = 'Other network equipment'
                elif ttl >= 128:
                    os = 'Windows'
                elif ttl >= 64:
                    os = 'Linux/Unix'
                else:
                    os = 'Unknown'
                print.info(f'[+] Host up: {dst_ip} ({os}/{ttl})')
                record.add_host_spec(dst_ip, 'OS_TTL', os)
                record.add_host_spec(dst_ip, 'TTL', ttl)
                return True
    
    return False