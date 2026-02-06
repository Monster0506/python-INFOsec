import sys
import socket
import requests
import nmap
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import traceback
import os

# Comprehensive list of popular TLDs to check
COMMON_TLDS = [
    # Generic TLDs
    'com', 'net', 'org', 'info', 'biz', 'name', 'pro', 'mobi','gov', 'edu',
    # New generic TLDs
    'io', 'ai', 'dev', 'app', 'tech', 'online', 'site', 'website', 'store',
    'shop', 'blog', 'cloud', 'digital', 'email', 'network', 'solutions',
    'systems', 'today', 'world', 'xyz', 'club', 'life', 'link', 'live',
    'news', 'space', 'academy', 'agency', 'associates', 'center', 'company',
    'education', 'enterprises', 'expert', 'foundation', 'international',
    'management', 'media', 'partners', 'services', 'support', 'technology',
    'training', 'university', 'zone', 'tv', 'fm',
    # Country code TLDs
    'us', 'uk', 'ca', 'au', 'de', 'fr', 'it', 'es', 'nl', 'be', 'ch',
    'at', 'se', 'no', 'dk', 'fi', 'pl', 'cz', 'pt', 'gr', 'ie', 'nz',
    'jp', 'kr', 'cn', 'in', 'sg', 'hk', 'tw', 'my', 'th', 'id', 'ph',
    'br', 'mx', 'ar', 'cl', 'co', 'pe', 've', 'za', 'ru', 'il', 'ae',
    'ml', 'tk', 'cc'
]

class DomainScanner:
    """Scanner for checking domain registration, DNS, and open ports."""
    
    def __init__(self, domain_name, tlds=None, use_nmap=True, threads=10):
        self.domain_name = domain_name.lower().strip()
        self.tlds = tlds if tlds else COMMON_TLDS
        self.use_nmap = use_nmap
        self.threads = threads
        self.results = []
        self.nmap_path = self._find_nmap()
    
    def _find_nmap(self):
        """Find the Nmap executable path."""
        # Common Nmap installation paths
        if platform.system() == 'Windows':
            temp = r'C:\Program Files (x86)\Nmap\nmap.exe'
            #check if nmap exists at this path
            if not os.path.exists(temp):
                return r'C:\Program Files\Nmap\nmap.exe'
            return temp

        if platform.system() == 'Linux':
            return '/usr/bin/nmap'
        if platform.system() == 'Darwin':
            return '/usr/local/bin/nmap'
        
        return None
    

    
    def check_dns(self, domain):
        """Check if domain resolves to an IP address."""
        try:
            ip = socket.gethostbyname(domain)
            return {'resolves': True, 'ip': ip}
        except socket.gaierror:
            return {'resolves': False}
        except Exception as e:
            return {'resolves': False, 'error': str(e)}
    
    def scan_ports_nmap(self, ip):
        """Scan for open ports using Nmap."""
        if not self.nmap_path or not self.use_nmap:
            return []
        
        try:
            nm = nmap.PortScanner(nmap_search_path=(self.nmap_path,))
            # Quick scan of top 100 ports
            nm.scan(ip, arguments='-F -T4 --max-retries 1 --host-timeout 30s')
            
            open_ports = []
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    ports = nm[ip][proto].keys()
                    for port in ports:
                        if nm[ip][proto][port]['state'] == 'open':
                            service = nm[ip][proto][port]['name']
                            open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': service
                            })
            
            return open_ports
        except Exception as e:
            return [{'error': str(e)}]
    
    def check_http_https(self, domain):
        """Check if HTTP/HTTPS services are responding."""
        services = {}
        
        # Check HTTP
        try:
            requests.get(f'http://{domain}', timeout=5)
            services['http'] = True
        except requests.RequestException:
            services['http'] = False
        
        # Check HTTPS
        try:
            requests.get(f'https://{domain}', timeout=5)
            services['https'] = True
        except requests.RequestException:
            services['https'] = False
        
        return services
    
    def scan_domain(self, tld):
        """Perform complete scan on a single domain."""
        domain = f"{self.domain_name}.{tld}"
        
        result = {
            'domain': domain,
            'tld': tld,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Check DNS resolution (primary test)
        dns_info = self.check_dns(domain)
        result['dns'] = dns_info
        
        # If DNS resolves, perform additional checks
        if dns_info.get('resolves'):
            # Check HTTP/HTTPS
            result['web_services'] = self.check_http_https(domain)
            
            # Scan ports with Nmap
            if self.use_nmap and self.nmap_path:
                result['open_ports'] = self.scan_ports_nmap(dns_info['ip'])
            else:
                result['open_ports'] = []
        else:
            result['web_services'] = {'http': False, 'https': False}
            result['open_ports'] = []
        
        return result
    
    def scan_all(self):
        """Scan all TLD combinations using multithreading."""
        print(f"\nScanning domain: {self.domain_name}")
        print(f"Checking {len(self.tlds)} TLDs")
        print(f"Threads: {self.threads}")
        print(f"Nmap: {'Enabled' if self.use_nmap and self.nmap_path else 'Disabled'}")
        print("="*70)
        print()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_tld = {executor.submit(self.scan_domain, tld): tld for tld in self.tlds}
            
            completed = 0
            total = len(self.tlds)
            
            for future in as_completed(future_to_tld):
                tld = future_to_tld[future]
                completed += 1
                
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    # Show progress
                    status = "✓" if result['dns'].get('resolves') else "✗"
                    print(f"[{completed}/{total}] {status} {result['domain']}")
                    
                except Exception as e:
                    print(f"[{completed}/{total}] ✗ {self.domain_name}.{tld} - Error: {e}")
        
        print()
        return self.results
    
    def generate_report(self, output_file='domain_scan_results.txt'):
        """Generate a detailed report of all findings."""
        
        # Sort results: resolving domains first, then by domain name
        def sort_key(r):
            resolves = r['dns'].get('resolves', False)
            has_ports = len(r.get('open_ports', [])) > 0 and not any('error' in p for p in r.get('open_ports', []))
            
            if resolves and has_ports:
                return (0, r['domain'])  # Best: resolves with open ports
            elif resolves:
                return (1, r['domain'])  # Resolves
            else:
                return (2, r['domain'])  # Does not resolve
        
        sorted_results = sorted(self.results, key=sort_key)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("="*70 + "\n")
            f.write(f"Domain Scan Results: {self.domain_name}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total TLDs Checked: {len(self.results)}\n")
            f.write("="*70 + "\n\n")
            
            # Summary statistics
            resolving_count = sum(1 for r in self.results if r['dns'].get('resolves', False))
            http_count = sum(1 for r in self.results if r.get('web_services', {}).get('http', False))
            https_count = sum(1 for r in self.results if r.get('web_services', {}).get('https', False))
            ports_count = sum(1 for r in self.results if r.get('open_ports') and len(r['open_ports']) > 0)
            
            f.write("SUMMARY\n")
            f.write("-"*70 + "\n")
            non_resolving_count = len(self.results) - resolving_count
            f.write(f"Domains Resolving (DNS): {resolving_count}\n")
            f.write(f"Domains Not Resolving: {non_resolving_count}\n")
            f.write(f"HTTP Available: {http_count}\n")
            f.write(f"HTTPS Available: {https_count}\n")
            f.write(f"Domains with Open Ports: {ports_count}\n")
            f.write("\n")
            
            # Detailed results (only domains that resolve)
            f.write("DETAILED RESULTS\n")
            f.write("="*70 + "\n\n")
            
            for result in sorted_results:
                # Skip domains that don't resolve
                if not result['dns'].get('resolves'):
                    continue
                
                f.write(f"Domain: {result['domain']}\n")
                f.write("-"*70 + "\n")
                
                # DNS Information (primary check)
                dns_info = result['dns']
                f.write(f"DNS Resolves: Yes\n")
                f.write(f"  IP Address: {dns_info['ip']}\n")
                
                # Web Services
                web = result.get('web_services', {})
                if web.get('http') or web.get('https'):
                    f.write(f"Web Services:\n")
                    if web.get('http'):
                        f.write(f"  HTTP: Available\n")
                    if web.get('https'):
                        f.write(f"  HTTPS: Available\n")
                
                # Open Ports
                open_ports = result.get('open_ports', [])
                if open_ports and not any('error' in p for p in open_ports):
                    f.write(f"Open Ports: {len(open_ports)}\n")
                    for port_info in open_ports:
                        f.write(f"  {port_info['port']}/{port_info['protocol']} - {port_info['service']}\n")
                
                f.write("\n")

            # Non-resolving domains
            non_resolving = [r for r in sorted_results if not r['dns'].get('resolves')]
            if non_resolving:
                f.write("NON-RESOLVING DOMAINS\n")
                f.write("="*70 + "\n\n")
                for result in non_resolving:
                    f.write(f"  {result['domain']}\n")
                f.write("\n")

        print(f"✓ Report saved to {output_file}")
        return output_file


def main():
    """Main entry point for the domain scanner."""
    
    # Parse command line arguments
    if len(sys.argv) < 2 or '--help' in sys.argv or '-h' in sys.argv:
        print("="*70)
        print("Domain Scanner - Check domain availability and services")
        print("="*70)
        print("\nUsage: domainscanner.py <domain_name> [options]")
        print("\nArguments:")
        print("  domain_name         The second-level domain to check (e.g., 'austin')")
        print("\nOptions:")
        print("  -t=<number>         Number of threads (default: 10)")
        print("  --no-nmap           Disable Nmap port scanning")
        print("  --tlds=<list>       Comma-separated list of TLDs to check")
        print("                      (default: checks 80+ common TLDs)")
        print("  -o=<file>           Output file name (default: domain_scan_results.txt)")
        print("\nExamples:")
        print("  domainscanner.py yoyojesus")
        print("  domainscanner.py mycompany -t=20")
        print("  domainscanner.py example --tlds=com,net,org,io")
        print("  domainscanner.py mybrand --no-nmap -o=mybrand_results.txt")
        print("\nFeatures:")
        print("  - DNS resolution verification (primary check)")
        print("  - HTTP/HTTPS service detection")
        print("  - Nmap port scanning for resolved domains")
        print("  - Multithreaded scanning")
        print("  - Detailed text report generation")
        print()
        sys.exit(0)
    
    # Get domain name
    domain_name = sys.argv[1].strip()
    
    # Parse options
    threads = 10
    use_nmap = True
    tlds = None
    output_file = 'domain_scan_results.txt'
    
    for arg in sys.argv[2:]:
        if arg.startswith('-t='):
            try:
                threads = int(arg.split('=')[1])
            except ValueError:
                print("Error: Invalid thread count")
                sys.exit(1)
        elif arg == '--no-nmap':
            use_nmap = False
        elif arg.startswith('--tlds='):
            tld_list = arg.split('=')[1]
            tlds = [t.strip().lower() for t in tld_list.split(',')]
        elif arg.startswith('-o='):
            output_file = arg.split('=')[1]
    
    print("="*70)
    print("Domain Scanner")
    print("="*70)
    
    # Create scanner instance
    scanner = DomainScanner(domain_name, tlds=tlds, use_nmap=use_nmap, threads=threads)
    
    try:
        # Perform scan
        results = scanner.scan_all()
        
        # Generate report
        print("\nGenerating report...")
        scanner.generate_report(output_file)
        
        # Print summary
        print("\n" + "="*70)
        print("SCAN COMPLETE")
        print("="*70)
        
        resolving = sum(1 for r in results if r['dns'].get('resolves', False))
        has_ports = sum(1 for r in results if r.get('open_ports') and len(r['open_ports']) > 0)
        
        print(f"\nTotal domains checked: {len(results)}")
        print(f"DNS Resolving: {resolving}")
        print(f"With Open Ports: {has_ports}")
        print(f"\nDetailed report: {output_file}")
        print()
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
