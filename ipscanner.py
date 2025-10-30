import nmap
import sys
import os
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_single_host(nm, ip, scan_ports=False):
    """
    Scan a single host for availability and optionally for open ports.
    
    Args:
        nm: nmap.PortScanner instance
        ip: IP address to scan
        scan_ports: Whether to scan for open ports
    Returns:
        dict: Host information including IP, hostname, state, and open ports
    """
    try:
        # Basic ping scan
        if scan_ports:
            # Scan common ports
            nm.scan(hosts=str(ip), arguments='-T4 --top-ports 20')
        else:
            nm.scan(hosts=str(ip), arguments='-sn -T4')
        
        if str(ip) in nm.all_hosts() and nm[str(ip)].state() == 'up':
            # Try to get hostname
            hostname = nm[str(ip)].hostname() if nm[str(ip)].hostname() else None
            
            if not hostname:
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0]
                except (socket.herror, socket.gaierror):
                    hostname = "Unknown"
            
            # Get open ports if scanning
            open_ports = []
            if scan_ports and 'tcp' in nm[str(ip)]:
                for port in nm[str(ip)]['tcp'].keys():
                    if nm[str(ip)]['tcp'][port]['state'] == 'open':
                        service = nm[str(ip)]['tcp'][port].get('name', 'unknown')
                        open_ports.append(f"{port}/{service}")
            
            return {
                'ip': str(ip),
                'hostname': hostname,
                'state': 'up',
                'ports': open_ports
            }
    except Exception as e:
        pass
    
    return None

def scan_network(network_range, max_threads=20, scan_ports=False):
    """
    Scans the given network range for active IP addresses using multithreading.

    Args:
        network_range (str): The network range to scan (e.g., '192.168.1.0/24').
        max_threads (int): Maximum number of concurrent threads.
        scan_ports (bool): Whether to scan for open ports on active hosts.
    Returns:
        list: A list of dictionaries with host information (IP, hostname, ports).
    """
    try:
        # Parse the network range
        network = ipaddress.ip_network(network_range, strict=False)
        
        # Specify the path to nmap.exe if it's not in PATH
        nmap_path = r'C:\Program Files (x86)\Nmap\nmap.exe'
        
        print(f"Scanning network: {network_range}")
        print(f"Total hosts to scan: {network.num_addresses - 2}")  # Exclude network and broadcast
        print(f"Threads: {max_threads}")
        print(f"Port scanning: {'Enabled' if scan_ports else 'Disabled'}")
        print("Please wait...\n")
        
        active_hosts = []
        completed = 0
        total_hosts = network.num_addresses - 2
        
        # Create ordered list of IPs to scan
        ips_to_scan = list(network.hosts())
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Create a separate nmap instance for each thread
            futures = {}
            for ip in ips_to_scan:
                if os.path.exists(nmap_path):
                    nm = nmap.PortScanner(nmap_search_path=(nmap_path,))
                else:
                    nm = nmap.PortScanner()
                future = executor.submit(scan_single_host, nm, ip, scan_ports)
                futures[future] = ip
            
            # Process results as they complete
            for future in as_completed(futures):
                completed += 1
                ip = futures[future]
                
                # Show progress
                print(f"Progress: [{completed}/{total_hosts}] Scanning {ip}...", end='\r')
                
                result = future.result()
                if result:
                    active_hosts.append(result)
                    ports_info = f" | Ports: {', '.join(result['ports'])}" if result['ports'] else ""
                    print(f"\n✓ Found: {result['ip']:15} - {result['hostname']}{ports_info}")
        
        # Sort results by IP address
        active_hosts.sort(key=lambda x: ipaddress.ip_address(x['ip']))
        
        print(f"\n")  # Clear progress line
        return active_hosts
    except nmap.PortScannerError as e:
        print(f"Error: Nmap not found or execution failed - {e}")
        print("\nMake sure:")
        print("1. Nmap is installed")
        print("2. Nmap is in your system PATH")
        print("3. You're running this script with administrator privileges")
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Parse command line arguments
    network = '192.168.1.0/24'  # Default
    scan_ports = False
    max_threads = 20
    
    # Simple argument parsing
    args = sys.argv[1:]
    for arg in args:
        if arg in ['-p', '--ports']:
            scan_ports = True
        elif arg.startswith('-t'):
            try:
                max_threads = int(arg.split('=')[1])
            except:
                print("Usage: -t=<number> for threads")
        elif '/' in arg or '.' in arg:
            network = arg
        elif arg in ['-h', '--help']:
            print("Usage: ipscanner.py [network_range] [options]")
            print("\nOptions:")
            print("  -p, --ports     Scan for open ports on active hosts")
            print("  -t=<number>     Number of threads (default: 20)")
            print("\nExamples:")
            print("  ipscanner.py 192.168.1.0/24")
            print("  ipscanner.py 10.0.0.0/24 -p")
            print("  ipscanner.py 192.168.1.0/24 -p -t=50")
            sys.exit(0)
    
    print("="*60)
    print("Network Scanner with Multithreading")
    print("="*60)
    active_hosts = scan_network(network, max_threads, scan_ports)
    print(f"{'='*60}")
    print(f"Scan complete! Found {len(active_hosts)} active host(s)")
    print("="*60)
    if not active_hosts:
        print("No active hosts found in the network range.")
    else:
        print("\nActive hosts (in order):")
        output_file = "active_hosts.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Network Scan Results for {network}\n")
            f.write(f"Port Scanning: {'Enabled' if scan_ports else 'Disabled'}\n")
            f.write("="*60 + "\n\n")
            for host in active_hosts:
                ip = host['ip']
                hostname = host['hostname']
                ports = host['ports']
                
                if ports:
                    port_str = f" | Ports: {', '.join(ports)}"
                    f.write(f"{ip:15} - {hostname}\n")
                    f.write(f"{'':15}   Open Ports: {', '.join(ports)}\n\n")
                    print(f"  • {ip:15} - {hostname}")
                    print(f"    Open Ports: {', '.join(ports)}")
                else:
                    f.write(f"{ip:15} - {hostname}\n")
                    print(f"  • {ip:15} - {hostname}")
        print(f"\nResults saved to {output_file}")

