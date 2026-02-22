import os
import random
try:
    import scapy 
    import pychromecast 
    import typer
    import rich
    import pylaunch
except:
    print("Installing your dependancies.")
    os.popen("sudo pip install scapy pychromecast flask pylaunch rich typer  --break-system-packages")
    print("Finished installing all the requirments.")
os.popen("sudo apt install qrencode ")
### Starting the pwnapple hotspot ###
while True:
    choice = input("Would you like to enable the pwnapple hotspot?\nY or N?\n")
    if choice.upper() == "Y" or choice.upper() == "YES":
        print("Setting up pwnapple hotspot\n")
        ssid = input("Please input the ssid/name of the network:\n")
        characters = ['a','b', 'c', 'd', 'e','f','d','e','f','g','h','i','j','k','l','m','n','p','q','r','s','t','u','v','w','x','y','z',
                    '1','2','3','4','5','6','7','8','9','0']
        password = ""
        print("Creating password...")
        for x in range(0,8):
            password += random.choice(characters)
        print(f"Your password is: {password}\n")
        device = input("Please input your wifi card for the creation of the hotspot:\n(type 0 for wlan0)\n")
        if device == "0":
            os.popen(f"sudo nmcli device wifi hotspot ssid {ssid} password {password} ifname wlan0")
            print("Here's a qr code for a easy connection :)")
            os.popen(f"nmcli wlan0 wifi show-password")
        else:
             os.popen(f"sudo nmcli device wifi hotspot ssid {ssid} password {password} ifname {device}")
             print("Here's a qr code for a easy connection :)")
             os.popen(f"nmcli {device} wifi show-password")
    elif choice.upper() == "N" or choice.upper() == "NO":
        print("Ok,Skipping the hotspot setup")
        break
    else:
        print("Not a vaild option\n")

print("Thank you for setting up pwnapple, hope you enjoy!")
