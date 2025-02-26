#!/bin/python3

from scapy.all import IP, TCP, sr1
import sys
import socket
import time

TTL_OS = {
    32:"Windows 95/98/ME",
    64:"Linux, FreeBSD ou MAC OS X",
    128:"Windows XP, 7, 8, 2003, 2008",
    255:"Solaris"
}

def scan_ports(ip, start_port, end_port):
    print(f"Starting port scan of ip {ip} from ports {start_port} to {end_port}")
    print("="*70)

    try:
        for port in range(start_port, end_port+1):
            str_output = ''
            syn_packet = IP(dst = ip) / TCP(dport = port, flags = 'S')
            response = sr1(syn_packet, timeout = 1, verbose = 0)

            if response is None:
                try:
                    str_output += "OS: unknown "
                    str_output += f"| Port: {port} "
                    str_output += f"| Service: {socket.getservbyport(port, 'tcp')} "
                    str_output +=  "| State: Filtered "
                except:
                    str_output += "OS: unknown "
                    str_output += f"| Port: {port} "
                    str_output += f"| Service: unknown "
                    str_output +=  "| State: Filtered "

            else:

                if response.haslayer(TCP):
                    str_output += f"OS: {TTL_OS[response.ttl]} | "
                    str_output += f"Port: {port}/tcp "
                    try:
                        str_output += f"| Service: {socket.getservbyport(port, 'tcp')} "
                    except:
                        str_output += f"| Service: unknown "
                    
                    if response.getlayer(TCP).flags == 0x14: #RST/ACK flag
                        str_output += f"| State: Closed "
                    
                    elif response.getlayer(TCP).flags == 0x12: #SYN/ACK flag
                        str_output += f"| State: Open "
                    
                    else:
                        str_output += f"| State: Filtered "
                
            print(str_output) 

    except KeyboardInterrupt:
        print("Exiting the port scan")
        sys.exit()
    except Exception as e:
        print(e)

if __name__ == "__main__":
    if len(sys.argv) == 4:
        scan_ports(ip = socket.gethostbyname(sys.argv[1]), start_port = int(sys.argv[2]), end_port = int(sys.argv[3]))
    else:
        raise SyntaxException("Invalid syntax. The right one is: python3 port-scanner.py <ip> <start_port> <end_port>")