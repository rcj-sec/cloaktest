import scanners.arp as scarp
import scanners.icmp as scicmp
import scanners.tcp as sctcp

from core.record import singleton as record

from utils import file_reader


if __name__ == '__main__':

    ports = file_reader.read_json_file('data/ports.json')

    #scarp.arp_scan('192.168.8.104/24', src_iface='wlo1')

    #sctcp.syn_scan_network('192.168.8.0/24')

    scarp.arp_scan_network('192.168.8.0/24', 'wlo1')