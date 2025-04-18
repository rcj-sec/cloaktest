import inspect
import ipaddress
import sys

import utils.pretty_print as print
import utils.file_reader as file_reader

from functools import wraps

def function_types(expected_types: dict):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            function_name = function.__name__
            signature = inspect.signature(function)

            try:
                parameters = signature.bind(*args, **kwargs)
                parameters.apply_defaults()
            except TypeError as e:
                print.error(f'[!] Error: {e}')
                sys.exit()

            for param_name, param_value in parameters.arguments.items():
                if param_name in expected_types:
                    expected = force_list(expected_types[param_name])
                    provided = type(param_value)
                    if provided not in expected:
                        types = _get_types_name(expected)
                        _print_wrong_parameter_msg(function_name, param_name, param_value, provided, types)
                        sys.exit()
            return function(*args, **kwargs)
        return wrapper
    return decorator

# Guaranteed: network_address = str, mask = none, int
def validate_ip_network(network_address, mask):
    if '/' not in network_address:
        if not mask:
            print.error(f'Error: no mask specified in for address {network_address}')
            sys.exit()
    else:
        network_address, mask = network_address.split('/')

    cidr_address = f'{network_address}/{mask}'

    try:
        network = ipaddress.ip_network(cidr_address, strict=True)
    except ValueError:
        print.error(f'Error: {cidr_address} is not a valid network address.')
        sys.exit()

    address_list = [str(address) for address in network.hosts()]

    return address_list, network_address, network.prefixlen

def validate_ip_addresses(address_list):

    if not address_list:
        print.error(f'Error: no address provided.')
        sys.exit()

    address_list = address_list if isinstance(address_list, list) else [address_list]

    if len(address_list) == 0:
        print.error(f'Error: no address provided.')
        sys.exit()

    for address in address_list:
        try:
            ipaddress.ip_address(address=address)
        except ValueError:
            print.error(f'Error: bad format for IP address {address}')
            sys.exit()
    
    return address_list

def validate_ports(ports):
    ports = ports if isinstance(ports, list) else [ports]

    for port in ports:
        if not isinstance(port, int) or not (0 <= port <= 65535):
            print.error(f'Error: port {port} is not an integer.')
            sys.exit()
    
    return ports

def force_list(item):
    return item if isinstance(item, list) else [item]

def _print_wrong_parameter_msg (function_name, param_name, param_value, provided, types):
    print.error(f"""Error: wrong parameter type for {param_name} in {function_name}().
            \n\t- Provided: {provided} ({param_value})
            \n\t+ Expected: {', '. join(types)}""")
    
def _get_types_name(types):
    return ['None' if t is None else t.__name__ for t in types]
