
import utils.pretty_print as print

from core.record import singleton as record

def ports_details (hosts, protcol):
    print.info(f'\n[+] Hosts discovered: {len(hosts)}\n')

    headers = ['IP', 'Hostname', 'Port']

    for host in hosts:
        tcp_ports = record.get_ports(host, protocol=protcol)
        host_name = record.get_host_spec(host, 'Resolved hostname')
        rows = []
        for port in tcp_ports.get('opened'):
            row = [host, host_name,port]
            rows.append(row)
        print.table(title=host, headers=headers, rows=rows)
        print.info(f'[+] Closed ports: {len(tcp_ports.get('closed'))}')
        print.info(f'[+] Filtered/Unreachable ports: {len(tcp_ports.get('filtered/unreachable'))}\n')

def icmp_ping_details(hosts):
    print.info(f'\n[+] Hosts discovered: {len(hosts)}\n')

    headers = ['IP', 'Hostname', 'TTL', 'Potential OS']
    rows = []

    for host in hosts:
        host_data = record.get_host(host)
        row = []
        row.append(host)
        row.append(host_data['Resolved hostname'])
        row.append(host_data['TTL'])
        row.append(host_data['OS_TTL'])
        rows.append(row)

        print.table(title='ICMP ping', headers=headers, rows=rows)

def arp_details(hosts, src_iface):
    print.info(f'\n[+] Hosts discovered: {len(hosts)}\n')

    headers = ['IP', 'Hostname', 'MAC', 'Vendor']
    rows = []

    for host in hosts:
        host_data = record.get_host(host)
        row = []
        row.append(host)
        row.append(host_data['Resolved hostname'])
        row.append(host_data['MAC address'])
        row.append(host_data['Vendor'])
        rows.append(row)

    print.table(title=f'ARP requests through {src_iface}', headers=headers, rows=rows)