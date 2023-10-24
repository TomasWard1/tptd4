from scapy.layers.inet import IP,ICMP,sr1, sr
import sys
import socket
import time

def traceroute(host:str):
    '''
    Recibe: IP del host destino
    '''
    i:int = 1
    TTL_expirados = 0  # Contador para mensajes TTL expired durante el tránsito
    
    while(i < 64): 
        packet = IP(dst= host, ttl = i)/ICMP(type=8, code=0)
        resp = sr1(packet, timeout = 2,verbose=0)
        if resp is not None:
            response_ip = resp.getlayer(IP).src
           
            if (response_ip == socket.gethostbyname(host)):
                print('The host\'s IP is {}'.format(response_ip))
                break
            else:
                print('Hop {}: {}'.format(i,response_ip))


                # VERIFICAR SI EL MENSAJE ICMP ES: "TTL expired during transit"
                if resp.getlayer(ICMP).type == 11 and resp.getlayer(ICMP).code == 0: #type = 11 -> el mensaje ICMP es de tipo 11 -> TTL expired during transit,  se verifica que el codigo del mensaje sea 0, -> el tiempo de vida del TTL se agotó en un router
                    TTL_expirados += 1
                    print("TTL expirado")


                    # CALCULAR LA DIFERENCIA DEL RTT
                    if i > 1:
                        prev_time = time_sent  # prev_time almacena el tiempo de la iteración anterior
                        current_time = time.time()
                        RTT = (current_time - prev_time) * 1000  # Convierte a milisegundos
                        print('RTT (ms) para el hop actual: ' + str(RTT))
            
                    # Establecemos el nuevo tiempo de envío para la próxima iteración
                    time_sent = time.time()

        else:
            print("NADA")
            pass
        
        i+=1
    
    print('traceroute finished')
    if i > 1:
        porcentajeTTLzero = (TTL_expirados / (i - 1)) * 100  # Calculo el porcentaje
        print('Porcentaje de hosts intermedios con TTL expired durante el tránsito: ' + str(porcentajeTTLzero))
      
      

       


def main():
  # Obtenemos el host destino del argumento de la línea de comandos.
  host = sys.argv[1]

  # Ejecutamos el traceroute.
  traceroute(host)

if __name__ == "__main__":
  main()




