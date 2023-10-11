from scapy.all import *
direccionIpDst = "www.utdt.com"
packet = IP(dst= "www.utdt.com", ttl = 64)/ICMP(type=8, code=0)
resp = sr1(packet, timeout = 10)
