import sys
import time
from datetime import datetime
import pywifi
from pywifi import const

def get_wifi_interface():
    """
    Get the first available WiFi interface.
    
    Returns:
        Interface object or None
    """
    wifi = pywifi.PyWiFi()
    interfaces = wifi.interfaces()
    
    if not interfaces:
        return None
    
    # Return the first interface
    return interfaces[0]

def scan_wifi_networks(interface, duration=5):
    """
    Scan for available WiFi networks.
    
    Args:
        interface: PyWiFi interface object
        duration: Time to wait for scan results (seconds)
    Returns:
        list: List of WiFi network information
    """
    print(f"Scanning for WiFi networks for {duration} seconds...")
    print(f"Interface: {interface.name()}")
    print("Please wait...\n")
    
    # Trigger scan
    interface.scan()
    
    # Wait for scan to complete
    time.sleep(duration)
    
    # Get scan results
    scan_results = interface.scan_results()
    
    return scan_results

def format_signal_quality(signal):
    """
    Convert signal strength to quality description.
    
    Args:
        signal: Signal strength in dBm
    Returns:
        str: Quality description
    """
    if signal >= -50:
        return "Excellent"
    elif signal >= -60:
        return "Good"
    elif signal >= -70:
        return "Fair"
    else:
        return "Weak"

def format_auth_type(auth):
    """
    Convert authentication type to readable string.
    
    Args:
        auth: Authentication algorithm constant
    Returns:
        str: Authentication type name
    """
    auth_types = {
        const.AKM_TYPE_NONE: "Open",
        const.AKM_TYPE_WPA: "WPA",
        const.AKM_TYPE_WPAPSK: "WPA-PSK",
        const.AKM_TYPE_WPA2: "WPA2",
        const.AKM_TYPE_WPA2PSK: "WPA2-PSK",
        const.AKM_TYPE_UNKNOWN: "Unknown"
    }
    return auth_types.get(auth, f"Unknown ({auth})")

def main():
    """Main function to run the WiFi scanner."""
    # Parse command line arguments
    duration = 5  # Default scan duration
    show_details = False
    
    args = sys.argv[1:]
    for arg in args:
        if arg in ['-d', '--details']:
            show_details = True
        elif arg.startswith('-t'):
            try:
                duration = int(arg.split('=')[1])
            except:
                print("Usage: -t=<seconds> for scan duration")
                sys.exit(1)
        elif arg in ['-h', '--help']:
            print("Usage: ssidscanner.py [options]")
            print("\nOptions:")
            print("  -d, --details   Show detailed information (MAC, channel, security)")
            print("  -t=<seconds>    Scan duration in seconds (default: 5)")
            print("\nExamples:")
            print("  ssidscanner.py")
            print("  ssidscanner.py -d")
            print("  ssidscanner.py -t=10 -d")
            sys.exit(0)
    
    print("="*70)
    print("WiFi Network Scanner")
    print("="*70)
    print(f"Scan Duration: {duration} seconds")
    print(f"Detailed Info: {'Enabled' if show_details else 'Disabled'}")
    print("="*70 + "\n")
    
    try:
        # Get WiFi interface
        interface = get_wifi_interface()
        
        if not interface:
            print("Error: No WiFi interface found.")
            print("\nTroubleshooting:")
            print("- Make sure WiFi adapter is enabled")
            print("- Check that WiFi drivers are installed")
            print("- Try running as administrator")
            sys.exit(1)
        
        # Scan for networks
        networks = scan_wifi_networks(interface, duration)
        
        if not networks:
            print("\nNo WiFi networks found.")
            print("\nTroubleshooting:")
            print("- Make sure WiFi is enabled")
            print("- Try increasing scan duration with -t=<seconds>")
            print("- Move closer to WiFi access points")
            return
        
        # Process and organize networks
        network_list = []
        seen_ssids = {}  # Track duplicate SSIDs (multiple APs with same name)
        
        for network in networks:
            ssid = network.ssid
            if not ssid:
                ssid = "<Hidden Network>"
            
            bssid = network.bssid
            signal = network.signal
            
            # Get authentication type
            auth_type = "Unknown"
            if network.akm and len(network.akm) > 0:
                auth_type = format_auth_type(network.akm[0])
            
            network_info = {
                'ssid': ssid,
                'bssid': bssid,
                'signal': signal,
                'quality': format_signal_quality(signal),
                'auth': auth_type,
                'freq': network.freq
            }
            
            # Track duplicate SSIDs
            if ssid in seen_ssids:
                seen_ssids[ssid] += 1
            else:
                seen_ssids[ssid] = 1
            
            network_list.append(network_info)
        
        # Sort by signal strength (strongest first)
        network_list.sort(key=lambda x: x['signal'], reverse=True)
        
        print(f"\n{'='*70}")
        print(f"Scan complete! Found {len(network_list)} WiFi network(s)")
        unique_ssids = len(seen_ssids)
        print(f"Unique SSIDs: {unique_ssids}")
        print("="*70)
        
        # Display results
        print("\nDiscovered WiFi Networks (sorted by signal strength):\n")
        for i, net in enumerate(network_list, 1):
            signal_bar = "█" * int((100 + net['signal']) / 10) if net['signal'] > -100 else ""
            print(f"{i}. {net['ssid']:32} [{net['quality']}]")
            print(f"   Signal: {net['signal']} dBm {signal_bar}")
            
            if show_details:
                print(f"   MAC (BSSID): {net['bssid']}")
                print(f"   Security: {net['auth']}")
                print(f"   Frequency: {net['freq']} MHz")
            
            print()
        
        # Save to file
        output_file = "active_ssids.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"WiFi Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {duration} seconds\n")
            f.write(f"Detailed Info: {'Enabled' if show_details else 'Disabled'}\n")
            f.write(f"Total Networks: {len(network_list)} | Unique SSIDs: {unique_ssids}\n")
            f.write("="*70 + "\n\n")
            
            for i, net in enumerate(network_list, 1):
                f.write(f"{i}. {net['ssid']} [{net['quality']}]\n")
                f.write(f"   Signal: {net['signal']} dBm\n")
                
                if show_details:
                    f.write(f"   MAC (BSSID): {net['bssid']}\n")
                    f.write(f"   Security: {net['auth']}\n")
                    f.write(f"   Frequency: {net['freq']} MHz\n")
                
                f.write("\n")
        
        print(f"Results saved to {output_file}")
        
    except Exception as e:
        print(f"\nError during WiFi scan: {e}")
        print("\nPossible issues:")
        print("- WiFi adapter not found or not enabled")
        print("- Insufficient permissions (try running as administrator)")
        print("- WiFi drivers not properly installed")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
