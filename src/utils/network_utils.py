import socket
import struct
import ipaddress
import netifaces
from typing import Optional, List, Tuple, Union
import random


def ip_to_int(ip: str) -> int:
    """
    Convert IP address string to integer
    
    Args:
        ip: IP address string (e.g., "192.168.1.1")
        
    Returns:
        Integer representation
    """
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        raise ValueError(f"Invalid IP address: {ip}")


def int_to_ip(ip_int: int) -> str:
    """
    Convert integer to IP address string
    
    Args:
        ip_int: Integer representation
        
    Returns:
        IP address string
    """
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except Exception:
        raise ValueError(f"Invalid integer IP: {ip_int}")


def is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_port(port: int) -> bool:
    """
    Check if port number is valid
    
    Args:
        port: Port number
        
    Returns:
        True if valid
    """
    return isinstance(port, int) and 1 <= port <= 65535


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is in private range
    
    Args:
        ip: IP address
        
    Returns:
        True if private
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_in_subnet(ip: str, subnet: str) -> bool:
    """
    Check if IP is in subnet
    
    Args:
        ip: IP address
        subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        True if IP is in subnet
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(subnet, strict=False)
        return ip_obj in network
    except ValueError:
        return False


def get_default_interface() -> Optional[str]:
    """
    Get default network interface name
    
    Returns:
        Interface name or None
    """
    try:
        gateways = netifaces.gateways()
        default = gateways.get('default', {}).get(netifaces.AF_INET)
        if default:
            return default[1]
    except Exception:
        pass
    
    # Fallback to common interfaces
    for iface in ['eth0', 'en0', 'wlan0', 'ens33']:
        try:
            if iface in netifaces.interfaces():
                return iface
        except:
            pass
    
    return None


def get_interface_ip(interface: str) -> Optional[str]:
    """
    Get IP address of network interface
    
    Args:
        interface: Interface name
        
    Returns:
        IP address or None
    """
    try:
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            return addresses[netifaces.AF_INET][0]['addr']
    except Exception:
        pass
    
    return None


def mac_to_str(mac_bytes: bytes) -> str:
    """
    Convert MAC address bytes to string
    
    Args:
        mac_bytes: MAC address as bytes
        
    Returns:
        MAC address string (xx:xx:xx:xx:xx:xx)
    """
    if len(mac_bytes) == 6:
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    return ''


def str_to_mac(mac_str: str) -> Optional[bytes]:
    """
    Convert MAC address string to bytes
    
    Args:
        mac_str: MAC address string
        
    Returns:
        MAC address as bytes or None
    """
    try:
        # Remove common separators
        mac_str = mac_str.replace(':', '').replace('-', '').replace('.', '')
        if len(mac_str) == 12:
            return bytes.fromhex(mac_str)
    except Exception:
        pass
    
    return None


def calculate_checksum(data: bytes) -> int:
    """
    Calculate Internet checksum (RFC 1071)
    
    Args:
        data: Data bytes
        
    Returns:
        Checksum value
    """
    if len(data) % 2 == 1:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF


def tcp_checksum(src_ip: str, dst_ip: str, tcp_segment: bytes) -> int:
    """
    Calculate TCP checksum including pseudo-header
    
    Args:
        src_ip: Source IP
        dst_ip: Destination IP
        tcp_segment: TCP segment data
        
    Returns:
        TCP checksum
    """
    # Create pseudo-header
    pseudo_header = struct.pack(
        '!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,  # reserved
        6,  # protocol (TCP)
        len(tcp_segment)  # TCP length
    )
    
    return calculate_checksum(pseudo_header + tcp_segment)


def udp_checksum(src_ip: str, dst_ip: str, udp_datagram: bytes) -> int:
    """
    Calculate UDP checksum including pseudo-header
    
    Args:
        src_ip: Source IP
        dst_ip: Destination IP
        udp_datagram: UDP datagram
        
    Returns:
        UDP checksum
    """
    # Create pseudo-header
    pseudo_header = struct.pack(
        '!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,  # reserved
        17,  # protocol (UDP)
        len(udp_datagram)  # UDP length
    )
    
    return calculate_checksum(pseudo_header + udp_datagram)


def icmp_checksum(icmp_packet: bytes) -> int:
    """
    Calculate ICMP checksum
    
    Args:
        icmp_packet: ICMP packet
        
    Returns:
        ICMP checksum
    """
    return calculate_checksum(icmp_packet)


def get_random_ephemeral_port() -> int:
    """
    Get random ephemeral port number
    
    Returns:
        Port number between 49152 and 65535
    """
    return random.randint(49152, 65535)


def parse_ip_range(ip_range: str) -> List[str]:
    """
    Parse IP range string into list of IPs
    
    Args:
        ip_range: Range string (e.g., "192.168.1.1-192.168.1.10")
        
    Returns:
        List of IP addresses
    """
    if '-' in ip_range:
        start, end = ip_range.split('-')
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        
        result = []
        current = start_ip
        while current <= end_ip:
            result.append(str(current))
            current += 1
        return result
    else:
        # Single IP
        return [ip_range]


def parse_port_range(port_range: str) -> List[int]:
    """
    Parse port range string into list of ports
    
    Args:
        port_range: Range string (e.g., "80-90" or "80,443,8080")
        
    Returns:
        List of port numbers
    """
    if ',' in port_range:
        # Comma-separated list
        ports = []
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports
    
    elif '-' in port_range:
        # Range
        start, end = map(int, port_range.split('-'))
        return list(range(start, end + 1))
    
    else:
        # Single port
        return [int(port_range)]


def get_hostname(ip: str) -> Optional[str]:
    """
    Get hostname for IP address
    
    Args:
        ip: IP address
        
    Returns:
        Hostname or None
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if port is open
    
    Args:
        host: Host address
        port: Port number
        timeout: Connection timeout
        
    Returns:
        True if port is open
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def subnet_to_range(subnet: str) -> Tuple[str, str]:
    """
    Convert subnet CIDR to IP range
    
    Args:
        subnet: Subnet in CIDR notation
        
    Returns:
        Tuple of (first_ip, last_ip)
    """
    network = ipaddress.ip_network(subnet, strict=False)
    return (str(network.network_address), str(network.broadcast_address))


def cidr_to_netmask(cidr: int) -> str:
    """
    Convert CIDR prefix length to netmask
    
    Args:
        cidr: CIDR prefix length
        
    Returns:
        Netmask string
    """
    mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
    return int_to_ip(mask)


def netmask_to_cidr(netmask: str) -> int:
    """
    Convert netmask to CIDR prefix length
    
    Args:
        netmask: Netmask string
        
    Returns:
        CIDR prefix length
    """
    mask_int = ip_to_int(netmask)
    return bin(mask_int).count('1')
