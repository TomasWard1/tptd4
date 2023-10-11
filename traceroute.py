from scapy.layers.inet import IP,ICMP,sr1,sr
import sys
import socket

def traceroute(host:str):
    '''
    Recibe: IP del host destino
    '''
    i:int = 1
    
    while(i < 64): 
        packet = IP(dst= host, ttl = i)/ICMP(type=8, code=0)
        resp = sr1(packet, timeout = 10,verbose=0)
        if resp is not None:
            response_ip = resp.getlayer(IP).src
           
            if (response_ip == socket.gethostbyname(host)):
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