from scapy.layers.inet import IP,ICMP,sr1,sr
import sys

def traceroute(host:str):
    '''
    Recibe: IP del host destino
    '''
    i:int = 1
    
    while(i < 100): 
        packet = IP(dst= host, ttl = i)/ICMP(type=8, code=0)
        resp = sr(packet, timeout = 10)
        if resp is not None:
            response_ip = resp.getlayer(IP).src
            print(response_ip)
            if (response_ip == host):
                break
        else:
            pass
        
      
        i+=1

    print('termino el ciclo')
       


def main():
  # Obtenemos el host destino del argumento de la línea de comandos.
  host = sys.argv[1]

  # Ejecutamos el traceroute.
  traceroute(host)

if __name__ == "__main__":
  main()