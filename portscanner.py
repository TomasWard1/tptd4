from scapy.layers.inet import IP, ICMP, sr1, TCP
import sys
from scapy.all import Raw

def port_scanner(ip_address,mode):
    open_ports = []
    filtered_ports = []
    total_ports = 1000
    output_file = "results_f.txt"

    for dest_port in range(1, total_ports + 1):
        try:
            packet = IP(dst=ip_address) / TCP(flags="S", dport=dest_port)
            resp = sr1(packet, timeout=0.25, verbose=0)

            if resp is not None and resp.haslayer(TCP) and resp['TCP'].flags == 'SA':
                if (mode == '-h'):
                    #Criterio 2.1: Puerto esta abierto
                    open_ports.append(dest_port)

                elif (mode == '-f'):
                    #Criterio 2.2: Hay que establecer conexion TCP para confirmar estado abierto
                    #Mandamos un paquete con ACK + Payload
                    packet_with_payload = IP(dst=ip_address) / TCP(flags="A", dport=dest_port) / Raw(load='Payload')
                    resp_with_payload = sr1(packet_with_payload, timeout=1, verbose=1)
                    print(resp_with_payload)
                    if resp_with_payload is not None and resp_with_payload.haslayer(TCP) and resp['TCP'].flags == 'A':
                        print('Analyzing port {}, status OPEN'.format(dest_port))
                        open_ports.append(dest_port)
                    
                    elif resp_with_payload is None:
                        # No se recibio respuesta, esta filtrado
                        print('Analyzing port {}, status FILTERED'.format(dest_port))
                        filtered_ports.append(dest_port)
                    else:
                        print('Analyzing port {}, status OTHER'.format(dest_port))
            
            elif resp is None:
                # No se recibio respuesta, esta filtrado
                print('Analyzing port {}, status FILTERED'.format(dest_port))
                filtered_ports.append(dest_port)
            else:
                print('Analyzing port {}, status OTHER'.format(dest_port))
        except ConnectionRefusedError as e:
            #Puerto cerrado
            print(f"Connection refused: {e}")

    #Procesamos al txt
    with open(output_file, "w") as f:
        f.write("Open Ports:\n")
        for port in open_ports:
            f.write(str(port) + "\n")

        f.write("\nFiltered Ports:\n")
        for port in filtered_ports:
            f.write(str(port) + "\n")

    open_port_percentage = len(open_ports) / total_ports * 100
    filtered_port_percentage = len(filtered_ports) / total_ports * 100

    print(f"Open Ports: {open_port_percentage}%")
    print(f"Filtered Ports: {filtered_port_percentage}%")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python portscanner.py <IP> <-h/-f>")
        sys.exit(1)

    target_ip = sys.argv[1]
    mode_char = sys.argv[2]

    port_scanner(target_ip,mode_char)
