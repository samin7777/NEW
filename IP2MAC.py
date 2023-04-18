import subprocess
import re
import socket
import platform

def get_mac_address(ip_address):
    # Check if the given IP address is the loopback address or the self IP address
    if ip_address == '127.0.0.1' or ip_address == socket.gethostbyname(socket.gethostname()):
        # Use the appropriate command on Windows or Linux to get the MAC address
        if platform.system() == 'Windows':
            if subprocess.call(['ipconfig', '/all']) == 0:
                ipconfig_output = subprocess.check_output(['ipconfig', '/all'])
                mac_address_match = re.search(r'([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})', ipconfig_output.decode())
                if mac_address_match:
                    return mac_address_match.group(0)
        else:
            if subprocess.call(['ifconfig']) == 0:
                ifconfig_output = subprocess.check_output(['ifconfig'])
                mac_address_match = re.search(r'ether (([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', ifconfig_output.decode())
                if mac_address_match:
                    return mac_address_match.group(1)
    else:
        # Run the appropriate command on Windows or Linux to get the MAC address for the given IP address
        if platform.system() == 'Windows':
            if subprocess.call(['arp', '-a', ip_address]) == 0:
                arp_output = subprocess.check_output(['arp', '-a', ip_address])
                # Parse the MAC address from the arp output using a regular expression
                mac_address_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_output.decode())
                if mac_address_match:
                    return mac_address_match.group(0)
        else:
            if subprocess.call(['arp', ip_address]) == 0:
                arp_output = subprocess.check_output(['arp', ip_address])
                # Parse the MAC address from the arp output using a regular expression
                mac_address_match = re.search(r'ether (([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', arp_output.decode())
                if mac_address_match:
                    return mac_address_match.group(1)
    return None

# Example usage:
ip_address = input('Enter an IP address: ')
mac_address = get_mac_address(ip_address)
if mac_address:
    print(f"MAC address of {ip_address} is {mac_address}")
else:
    print(f"Could not find MAC address for {ip_address}")
