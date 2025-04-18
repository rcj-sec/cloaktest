"""
Handles launch of information gathering tasks with multi-threading.
"""
import ipaddress
import functools
import time

from concurrent.futures import ThreadPoolExecutor, as_completed

import scanners.dispatcher as dispatcher

import scanners.dns as scdns

from utils import pretty_print as print

def multi_thread_scan(dst_ips, max_threads, timeout, scan_type, interval, **extra):

    dispatcher_job = functools.partial(_call_dispatcher, timeout=timeout, scan_type=scan_type)
    dst_ports = extra.get('dst_ports', [1])

    live_hosts = set()

    with ThreadPoolExecutor(max_threads) as executor:
        if interval:
            time.sleep(interval)

        futures = _submit_dispatcher_executor(executor, dispatcher_job, dst_ips, **extra)

        for future in as_completed(futures):
            ip, _ = futures[future]
            try:
                is_up = future.result()
                if is_up:
                    live_hosts.add(ip)
            except Exception as e:
                print.error(f'[!] Error scanning {ip}: {e}')

    for host in live_hosts:
        scdns.resolve_ip(host)

    return live_hosts

def _call_dispatcher(dst_ip, timeout, scan_type, **extra):
    try:
        return dispatcher.dispatch_scan(dst_ip, timeout, scan_type, **extra)
    except Exception as e:
        print.error(f'[!] An error occurred during {scan_type} ping: ({dst_ip}) {e}')
        return False
    
def _submit_dispatcher_executor(executor, dispatcher_job, dst_ips, **extra):
    dst_ports = extra.get('dst_ports', [1])
    return {executor.submit(dispatcher_job, str(ip), dst_port=dst_port, **extra): (str(ip), dst_port) for ip in dst_ips for dst_port in dst_ports}