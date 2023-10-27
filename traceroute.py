from scapy.layers.inet import IP, ICMP, sr1
import sys
import time
import requests
import folium

def traceroute(host: str):
    ttl = 1
    ttl_expirados = 0
    hop_ips = []

    while ttl < 30:
        # Construimos un paquete IP con un TTL que incrementa
        packet = IP(dst=host, ttl=ttl) / ICMP(type=8, code=0)

        start_time = time.time()
        resp = sr1(packet, timeout=2, verbose=0)
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
                # ICMP type 11 = TTL expired during transit
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

    

websites = {
    "Africa": [
        "www.unisa.ac.za",
        "www.wits.ac.za",
        "www.ug.edu.gh",
        "www.unilorin.edu.ng",
        "www.uonbi.ac.ke",

    ],
    "North America": [
        "www.carleton.edu",
        "www.pomona.edu",
        "www.middlebury.edu",
        "www.macalester.edu",
        "www.grinnell.edu"
    ],
    "Europe": [
        "www.aalto.fi",
        "www.ceu.edu",
        "www.epfl.ch",
        "www.tu-dresden.de",
        "www.uib.no"
    ],
    "Asia": [
        "www.iiit.ac.in",
        "www.ku.edu.np",
        "www.ajou.ac.kr",
        "www.hku.hk",
        "www.ait.ac.th"
    ],

    "Oceania": [
        "www.swinburne.edu.au",
        "www.uwa.edu.au",
        "www.qut.edu.au",
        "www.aut.ac.nz",
        "www.curtin.edu.au"
    ]
}


colors = ['blue', 'green', 'red', 'pink', 'purple']


def map_request():

    # Creamos un mapa folium
    traceroute_map = folium.Map(location=[0, 0], zoom_start=2)

    for index, entry in enumerate(websites.items()):
        website_list = entry[1]
        color = colors[index]

        for i in range(0, len(website_list)):
            website = website_list[i]
            print(website)

            hops = traceroute(website)

            locations = []

            for hop in hops:
                # Hacemos llamadas a una API externa para obtener la ubicacion a partir de la direccion IP
                response = requests.get(f"http://ip-api.com/json/{hop}")
                data = response.json()
                lat = data.get("lat", "Unknown")
                lon = data.get("lon", "Unknown")

                if lat != "Unknown" and lon != "Unknown":

                    locations.append([lat, lon])
                    folium.Marker(
                        location=[lat, lon],
                        icon=folium.Icon(color=color),
                        popup=folium.Popup(f"{website}", max_width=300),
                    ).add_to(traceroute_map)

            folium.PolyLine(locations, color=color).add_to(traceroute_map)

    traceroute_map.save("traceroute_map.html")


if __name__ == "__main__":
    # Obtenemos el argumento de la línea de comandos.
    arg = sys.argv[1]
    
    if (arg == '-map'):
        map_request()
    else:
        traceroute(arg)
