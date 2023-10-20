from scapy.layers.inet import IP, ICMP, sr1
import sys
import socket
import time

def traceroute(host: str):
    i = 1

    while i < 64:
        packet = IP(dst = host, ttl = i) / ICMP(type = 8, code = 0)
        start_time = time.time()
        resp = sr1(packet, timeout = 1, verbose=0)
        end_time = time.time()

        if resp is not None:
            response_ip = resp.getlayer(IP).src
            rtt = (end_time - start_time) * 1000  # Calculamos el RTT en milisegundos

            if response_ip == socket.gethostbyname(host):
                print('IP del host remoto: {} (RTT: {:.2f} ms)'.format(response_ip, rtt))
                return
            else:
                print('Hop {}: {} (RTT: {:.2f} ms)'.format(i, response_ip, rtt))
        else:
            pass

        i += 1

    print('traceroute finished')

def main():
    host = sys.argv[1]
    traceroute(host)

if __name__ == "__main__":
    main()