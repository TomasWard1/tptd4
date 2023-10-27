from scapy.layers.inet import IP, ICMP, sr1
import sys
import socket
import time


def traceroute(host: str):
    ttl = 1
    ttl_expirados = 0
    hop_ips = []

    while ttl < 30:
        # Construimos un paquete IP con un TTL que incrementa
        packet = IP(dst=host, ttl=ttl) / ICMP(type=8, code=0)

        start_time = time.time()
        resp = sr1(packet, timeout=1, verbose=0) #CAMBIAR A 2
        end_time = time.time()

        if resp is not None:
            response_ip = resp.getlayer(IP).src
            # Calculamos el RTT en milisegundos
            rtt = (end_time - start_time) * 1000

            hop_ips.append(response_ip) #Incluimos el destino como una IP del camino 

            if resp.type == 0:  # ICMP Echo Reply, llego a destino
                print('IP del host remoto: {} (RTT: {:.2f} ms)'.format(
                    response_ip, rtt))
                break
            else:
                # Verificar si el mensaje ICMP es: "TTL expired during transit"
                # type = 11 -> el mensaje ICMP es de tipo 11 -> TTL expired during transit,  se verifica que el codigo del mensaje sea 0, -> el tiempo de vida del TTL se agotó en un router
                if resp.getlayer(ICMP).type == 11 and resp.getlayer(ICMP).code == 0:
                    ttl_expirados += 1
                    print(
                        'Hop {}: {} - TTL expirado (RTT: {:.2f} ms)'.format(ttl, response_ip, rtt))
                else:
                    print('Hop {}: {} (RTT: {:.2f} ms)'.format(
                        ttl, response_ip, rtt))
        else:
            print('*Hop {}: Sin respuesta'.format(ttl))

        ttl += 1
    
    porcentajeTTLzero = (ttl_expirados / ttl) * 100  # Calculo el porcentaje
    print('Porcentaje de hosts intermedios con TTL expirado: {:.2f}'.format(porcentajeTTLzero))
    return hop_ips

    


if __name__ == "__main__":
    # Obtenemos el host destino del argumento de la línea de comandos.
    host = sys.argv[1]

    # Ejecutamos el traceroute.
    traceroute(host)
