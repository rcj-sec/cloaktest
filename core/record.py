import threading
import json
import copy

from core import data_structs

class Record:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(Record, cls).__new__(cls)
                cls._instance._init_instance()
        
        return cls._instance
    
    def _init_instance(self):
        self._data_lock = threading.Lock()
        self.hosts = {}

    def add_host(self, host_ip, data):
        with self._data_lock:
            if host_ip not in self.hosts:
                self.hosts[host_ip] = {}
            self.hosts[host_ip].update(data)

    def get_host(self, host_ip):
        with self._data_lock:
            return copy.deepcopy(self.hosts.get(host_ip))

    def add_host_spec(self, host_ip, spec_key, spec_value):
        with self._data_lock:
            if host_ip not in self.hosts:
                self.hosts[host_ip] = {}
            self.hosts[host_ip][spec_key] = spec_value

    def get_host_spec(self, host_ip, spec_key):
        with self._data_lock:
            spec_value = self.hosts.get(host_ip, {}).get(spec_key)
            return copy.deepcopy(spec_value)

    def add_port(self, host_ip, port, protocol, status):
        with self._data_lock:
            host = self.hosts.setdefault(host_ip, {})
            
            ports = host.setdefault('ports', {
                'tcp': data_structs.ExclusiveListManager(['opened', 'closed', 'filtered/unreachable']),
                'udp': data_structs.ExclusiveListManager(['opened', 'closed', 'filtered/unreachable']),
            })
            
            ports[protocol].add(status, port)

    def get_ports(self, host_ip, protocol='', status=''):
        with self._data_lock:
            host = self.hosts.get(host_ip)
            if not host  or 'ports' not in host:
                return None
            
            ports = host['ports']

            if not protocol:
                return copy.deepcopy(ports)
            
            if not status:
                return copy.deepcopy(ports[protocol])
            
            return copy.deepcopy(ports[protocol][status])

    def print_hosts(self):
        print(json.dumps(self._serialize_hosts(), indent=4, sort_keys=True))

    def _serialize_hosts(self):
        serializable_hosts = {}

        for host_ip, host_data in self.hosts.items():
            serializable_hosts[host_ip] = {}
            for key, value in host_data.items():
                if key == 'ports':
                    serializable_hosts[host_ip]['ports'] = {}
                    for protocol, manager in value.items():
                        serializable_hosts[host_ip]['ports'][protocol] = manager.to_dict()
                else:
                    serializable_hosts[host_ip][key] = value

        return serializable_hosts

singleton = Record()
