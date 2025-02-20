#!/bin/python3

import sys
import socket
import time

def scan_ports(ip, start_port, end_port):
    first_found = False
    print(f"Starting port scan of ip {ip} from ports {start_port} to {end_port}")
    print("="*50)

    try:
        open_ports = []
        for port in range(start_port, end_port+1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))

                if result == 0: # Succesfull connection
                    if not first_found:
                        print("Open ports found:")
                        first_found = True
                    print(f"Port: {port} | Service: {socket.getservbyport(port)}")
                    open_ports.append(port)

        if not first_found:
            print("No open ports found")

    except KeyboardInterrupt:
        print("Exiting the port scan")
        sys.exit()
    except gai.error:
        print("Hostname ip could not be resolved")
        sys.exit()
    except socket.error:
        print("Could not connect to socket")
        sys.exit()

if __name__ == "__main__":
    if len(sys.argv) == 4:
        scan_ports(ip = socket.gethostbyname(sys.argv[1]), start_port = int(sys.argv[2]), end_port = int(sys.argv[3]))
    else:
        raise SyntaxException("Invalid syntax. The right one is: python3 port-scanner.py <ip> <start_port> <end_port>")