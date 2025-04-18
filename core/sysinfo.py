import psutil

class SysInfo:
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super (SysInfo, cls).__new__(cls)
            cls._instance._init_instance()
        return cls._instance
    
    def _init_instance (self):
        self._interfaces = None
        self._dns_resolvers = None

    def get_single_interface (self, interface_name):
        self._interfaces = self.get_all_interfaces()
        return self._interfaces[interface_name]

    def get_all_interfaces (self, interface_name=None):
        if not self._interfaces:
            interfaces = {}
            for interface, addresses in psutil.net_if_addrs().items():
                if_data = {}
                for address in addresses:
                    if address.family == 2:
                        if_data['address_v4'] = address.address
                        if_data['netmask_v4'] = address.netmask
                        if_data['broadcast_v4'] = address.broadcast
                        if_data['ptp_v4'] = address.ptp
                    elif address.family == 10:
                        if_data['address_v6'] = address.address
                        if_data['netmask_v6'] = address.netmask
                        if_data['broadcast_v6'] = address.broadcast
                        if_data['ptp_v6'] = address.ptp
                if if_data: interfaces[interface] = if_data
        self._interfaces = interfaces
        return self._interfaces
    
    def get_dns_resolvers(self):
        if self._dns_resolvers:
            return self._dns_resolvers
        
        resolvers = []
        try:
            with open('/etc/resolv.conf', 'r') as file:
                for line in file:
                    if line.startswith('nameserver'):
                        resolvers.append(line.split()[1])
        except Exception as e:
            print (f'Could not fetch local DNS resolvers: {e}')
        self._dns_resolvers = resolvers
        return self._dns_resolvers
    
singleton = SysInfo()
