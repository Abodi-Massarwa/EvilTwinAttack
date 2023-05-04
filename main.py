""""" IMPORTS """
import subprocess

import scapy.layers.dot11
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

"""" global variables  """

victim_ls = []
ap_list = []

""""" Functions """


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

    # capture packets with Scapy


def sniff_packets(pkt: scapy.packet):
    """
    speaking of capturing frames ...
    1) probe request is type 0 subtype 4
    2) probe response is type 0 subtype 5
    3) beacon is type 0 subtype 8
    all under the management frame category
    addr1 : dst
    addr2 : src
    addr3 : AP
    """

    if pkt.haslayer(Dot11): # means 802.11 packet

        if pkt.type == 0 and pkt.subtype == 8: # beacon
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


if __name__ == '__main__':
    # 1
    switch_to_monitor_mode()
    print("switched to MONITOR MODE")
    # 2 Sniffing packets in order to spoof the MAC addresses in order to send the FAKE de-authentication frame
    our_wlan = get_wireless_interface()
    print("our NIC is " + our_wlan)
    sniff(iface=our_wlan, prn=sniff_packets, timeout=10)
    print(victim_ls)
