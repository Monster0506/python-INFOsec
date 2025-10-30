import asyncio
import sys
from bleak import BleakScanner
from datetime import datetime

async def scan_bluetooth(duration=10, show_details=False):
    """
    Scans for Bluetooth Low Energy (BLE) devices.
    
    Args:
        duration (int): Scan duration in seconds
        show_details (bool): Show detailed information (RSSI, manufacturer data, etc.)
    Returns:
        list or dict: List of BLEDevice objects or dict with advertisement data
    """
    print(f"Scanning for BLE devices for {duration} seconds...")
    print("Please wait...\n")
    
    if show_details:
        # Returns dict: {address: (BLEDevice, AdvertisementData)}
        devices = await BleakScanner.discover(timeout=duration, return_adv=True)
    else:
        # Returns list of BLEDevice objects
        devices = await BleakScanner.discover(timeout=duration, return_adv=False)
    
    return devices

async def main():
    """Main function to run the Bluetooth scanner."""
    # Parse command line arguments
    duration = 10  # Default scan duration
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
            print("Usage: btscanner.py [options]")
            print("\nOptions:")
            print("  -d, --details   Show detailed information (RSSI, manufacturer, services)")
            print("  -t=<seconds>    Scan duration in seconds (default: 10)")
            print("\nExamples:")
            print("  btscanner.py")
            print("  btscanner.py -d")
            print("  btscanner.py -t=20 -d")
            sys.exit(0)
    
    print("="*70)
    print("Bluetooth Device Scanner")
    print("="*70)
    print(f"Scan Duration: {duration} seconds")
    print(f"Detailed Info: {'Enabled' if show_details else 'Disabled'}")
    print("="*70 + "\n")
    
    try:
        all_devices = []
        
        # Scan for BLE devices
        ble_devices = await scan_bluetooth(duration, show_details)
        
        # Process BLE devices
        if show_details:
            # ble_devices is a dict: {address: (BLEDevice, AdvertisementData)}
            for address, (ble_device, adv_data) in ble_devices.items():
                device_info = {
                    'address': ble_device.address,
                    'name': ble_device.name or 'Unknown',
                    'rssi': adv_data.rssi,
                    'manufacturer': adv_data.manufacturer_data,
                    'services': list(adv_data.service_uuids)
                }
                all_devices.append(device_info)
        else:
            # ble_devices is a list of BLEDevice objects
            for device in ble_devices:
                device_info = {
                    'address': device.address,
                    'name': device.name or 'Unknown',
                    'rssi': None,
                    'manufacturer': None,
                    'services': []
                }
                all_devices.append(device_info)
        
        if not all_devices:
            print("\nNo Bluetooth devices found.")
            print("\nTroubleshooting:")
            print("- Make sure Bluetooth is enabled on your computer")
            print("- Ensure nearby Bluetooth devices are discoverable")
            print("- Try increasing scan duration with -t=<seconds>")
            return
        
        # Sort by name, then address
        all_devices.sort(key=lambda x: (x['name'], x['address']))
        
        print(f"\n{'='*70}")
        print(f"Scan complete! Found {len(all_devices)} Bluetooth device(s)")
        print("="*70)
        
        # Display results
        print("\nDiscovered Bluetooth Devices:\n")
        for i, dev in enumerate(all_devices, 1):
            print(f"{i}. {dev['name']}")
            print(f"   Address: {dev['address']}")
            
            if show_details:
                if dev['rssi'] is not None:
                    print(f"   Signal Strength (RSSI): {dev['rssi']} dBm")
                
                if dev['manufacturer']:
                    print(f"   Manufacturer Data: {dev['manufacturer']}")
                
                if dev['services']:
                    print(f"   Services: {', '.join(dev['services'][:3])}" + 
                          (f" (+{len(dev['services'])-3} more)" if len(dev['services']) > 3 else ""))
            
            print()
        
        # Save to file
        output_file = "active_bt.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Bluetooth Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {duration} seconds\n")
            f.write(f"Detailed Info: {'Enabled' if show_details else 'Disabled'}\n")
            f.write("="*70 + "\n\n")
            
            for i, dev in enumerate(all_devices, 1):
                f.write(f"{i}. {dev['name']}\n")
                f.write(f"   Address: {dev['address']}\n")
                
                if show_details:
                    if dev['rssi'] is not None:
                        f.write(f"   Signal Strength (RSSI): {dev['rssi']} dBm\n")
                    
                    if dev['manufacturer']:
                        f.write(f"   Manufacturer Data: {dev['manufacturer']}\n")
                    
                    if dev['services']:
                        f.write(f"   Services: {', '.join(dev['services'])}\n")
                
                f.write("\n")
        
        print(f"Results saved to {output_file}")
        
    except Exception as e:
        print(f"\nError during Bluetooth scan: {e}")
        print("\nPossible issues:")
        print("- Bluetooth adapter not found or not enabled")
        print("- Insufficient permissions (try running as administrator)")
        print("- Bluetooth drivers not properly installed")
        sys.exit(1)

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
