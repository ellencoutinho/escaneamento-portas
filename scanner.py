#!/bin/python3

from scapy.all import IP, IPv6, ICMPv6EchoRequest, TCP, ICMP, sr1, UDP
import ipaddress
import sys
import socket
import time

TTL_OS = {
    32:"Windows 95/98/ME",
    64:"Linux, FreeBSD ou MAC OS X",
    128:"Windows XP, 7, 8, 2003, 2008",
    255:"Solaris"
}

def scan_network(ip, start_port, end_port):
    print(f"Starting scan of network {ip}")
    print("="*130)

    try:
        network = ipaddress.ip_network(ip)
        for host in network.hosts():
            host = str(host)
            
            if network.version == 4:
                response = sr1(IP(dst=host) / ICMP(type=8), timeout=1, verbose=0)  # ICMP Echo Request
                if response is not None and response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:  # ICMP Echo Reply
                    scan_host(host, start_port, end_port)
            
            elif network.version == 6:
                response = sr1(IPv6(dst=host) / ICMPv6EchoRequest(), timeout=1, verbose=0)  # ICMPv6 Echo Request
                if response is not None and response.haslayer(ICMPv6EchoReply):  # ICMPv6 Echo Reply
                    scan_host(host, start_port, end_port)

    except ValueError:
        print("Invalid network address")
    except KeyboardInterrupt:
        print("Exiting the port scan")
        sys.exit()
    except Exception as e:
        print(e)


def scan_host(ip, start_port, end_port):
    print(f"Starting port scan of ip {ip} from ports {start_port} to {end_port}")
    print("="*130)

    try:
        is_ipv6 = ":" in ip

        for port in range(start_port, end_port+1):
            TCP_done = False
            UDP_done = False

            str_output = ''
            if is_ipv6:
                syn_packet = IPv6(dst=ip) / TCP(dport=port, flags='S')
            else:
                syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')
            udp_packet = IP(dst=ip)/UDP(dport=port)

            response_udp = sr1(udp_packet, timeout=1, verbose=0)
            response_tcp = sr1(syn_packet, timeout = 1, verbose = 0)

            if not TCP_done:
                if response_tcp is None:
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

                    if response_tcp.haslayer(TCP):
                        if is_ipv6:
                            str_output += f"Port: {port}/tcp | "
                        else:
                            str_output += f"OS: {TTL_OS[response_tcp.ttl]} "
                            str_output += f"| Port: {port}/tcp "
                        
                        try:
                            str_output += f"| Service: {socket.getservbyport(port, 'tcp')} "
                        except:
                            str_output += f"| Service: unknown "
                        
                        if response_tcp.getlayer(TCP).flags == 0x14: #RST/ACK flag
                            str_output += f"| State: Closed "
                        
                        elif response_tcp.getlayer(TCP).flags == 0x12: #SYN/ACK flag
                            str_output += f"| State: Open "
                        
                        else:
                            str_output += f"| State: Filtered "
                    
                print(str_output)
                TCP_done = True
                str_output = ''
            
            if not UDP_done:
                if response_udp is None:
                    str_output += "OS: unknown "
                    str_output += f"| Port: {port}/udp "
                    try:
                        str_output += f"| Service: {socket.getservbyport(port, 'udp')} "
                    except:
                        str_output += f"| Service: unknown "
                    str_output +=  "| State: Open|Filtered "

                else:
                    try:
                        str_output += f"OS: {TTL_OS[response_udp.ttl]} "
                    except:
                        str_output += "OS: unknown "
                    
                    str_output += f"| Port: {port}/udp "

                    try:
                        str_output += f"| Service: {socket.getservbyport(port, 'udp')} "
                    except:
                        str_output += f"| Service: unknown "
                    
                    str_output +=  "| State: Closed "
                    
                print(str_output)
                UDP_done = True
                str_output = ''


    except KeyboardInterrupt:
        print("Exiting the port scan")
        sys.exit()
    except Exception as e:
        print(e)

if __name__ == "__main__":
    scan_type = int(input("What is the scan type? [0 - Host | 1 - Network] "))
    ip_version = int(input("Which is the version of protocol to be scanned? [4 | 6]? "))

    if ip_version == 6:
        ipv6 = str(input("Insert the IPv6 {type} adress: ".format(type="host" if scan_type == 0 else "network")))
        start_port = int(input("Which port the scanner might start at? "))
        end_port = int(input("Which port the scanner might end at? "))

        if scan_type == 0:
            scan_host(ip = socket.getaddrinfo(ipv6, None, socket.AF_INET6)[0][4][0], 
                      start_port = start_port, end_port = end_port)
        elif scan_type == 1:
            scan_network(ip = ipv6, start_port = start_port, end_port = end_port)
    
    elif ip_version == 4:
        ipv4 = input("Insert the IPv4 {type} adress: ".format(type="host" if scan_type == 0 else "network"))
        start_port = int(input("Which port the scanner might start at? "))
        end_port = int(input("Which port the scanner might end at? "))

        if scan_type == 0:
            scan_host(ip = socket.gethostbyname(ipv4), start_port = start_port, end_port = end_port)
        elif scan_type == 1:
            scan_network(ip = ipv4, start_port = start_port, end_port = end_port)