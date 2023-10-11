from scapy.layers.inet import IP,ICMP,sr1,sr
import sys
import socket

def traceroute(host:str):
    '''
    Recibe: IP del host destino
    '''
    i:int = 1
    
    while(i < 100): 
        packet = IP(dst= host, ttl = i)/ICMP(type=8, code=0)
        resp = sr1(packet, timeout = 10,verbose=0)
        if resp is not None:
            response_ip = resp.getlayer(IP).src
            print(response_ip)

            if (socket.gethostbyaddr(response_ip.psrc)[0] == host):
               
                print('The host is: {}'.format(response_ip))
                return
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