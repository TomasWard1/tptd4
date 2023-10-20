from scapy.layers.inet import IP, ICMP, sr1, TCP
import sys


def port_scanner(ip_address):
    open_ports = []
    filtered_ports = []
    total_ports = 1000  # You can adjust this based on your needs
    output_file = "port_scan_results.txt"

    for dest_port in range(1, total_ports + 1):
        packet = IP(dst=ip_address) / TCP(flags="S", dport=dest_port)
        resp = sr1(packet, timeout=1, verbose=1)

        # 0x12 == SYN-ACK
        if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            # Puerto esta abierto
            open_ports.append(dest_port)
        elif resp is None:
            # No se recibio respuesta, esta filtrado
            filtered_ports.append(dest_port)

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
    if len(sys.argv) != 2:
        print("Uso: python portscanner.py <IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_scanner(target_ip)
