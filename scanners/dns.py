"""
Handles DNS related information gathering tasks.
"""
import dns.resolver
import dns.reversename

import utils.validation as validation

from core.sysinfo import singleton as sysinfo
from core.record import singleton as record

__resolve_ip_types = {
    'ip': str,
    'timeout': int,
}

@validation.function_types(__resolve_ip_types)
def resolve_ip(ip: str, timeout: int = 2) -> str | None:
    """Resolve hostname of given IP address.

    Args:
        ip (str): address to resolve
        timeout (int, optional): Seconds to wait for reply. Defaults to 2.

    Returns:
        str | None: Hostname if address was resolved. None if not.
    """
    try:
        reverse_lookup_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = sysinfo.get_dns_resolvers() + ['8.8.8.8', '1.1.1.1']
        answers = resolver.resolve(reverse_lookup_name, 'PTR')
        resolved_name = str(answers[0]).rstrip('.')
        record.add_host_spec(ip, 'Resolved hostname', resolved_name)
        return resolved_name
    except Exception as e:
        record.add_host_spec(ip, 'Resolved hostname', 'Unresolved')
        return None