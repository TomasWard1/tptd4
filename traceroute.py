from scapy.layers.inet import IP,ICMP,sr1
import sys
import socket

def traceroute(host:str):
    '''
    Recibe: IP del host destino
    '''
    i:int = 1
    destination_ip = socket.gethostbyname(host)
    
    while(i < 64): 
        packet = IP(dst= host, ttl = i)/ICMP(type=8, code=0)
        resp = sr1(packet, timeout = 2,verbose=0)
        if resp is not None:
            response_ip = resp.getlayer(IP).src
           
            if (response_ip == destination_ip):
                print('The host\'s IP is {}'.format(response_ip))
                return
            else:
                print('Hop {}: {}'.format(i,response_ip))
        else:
            pass
        i+=1
    print(i)
    print('traceroute finished')

def main():
  # Obtenemos el host destino del argumento de la línea de comandos.
  host = sys.argv[1]

  # Ejecutamos el traceroute.
  traceroute(host)

if __name__ == "__main__":
  main()