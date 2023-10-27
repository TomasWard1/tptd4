from traceroute import traceroute
import folium
import requests
import sys

# Lists of websites hosted in each continent
websites = {
    "Africa": [
        "www.unisa.ac.za",  # University of Tunis El Manar, Tunisia
        "www.wits.ac.za",  # University of the Witwatersrand, South Africa
        "www.ug.edu.gh",   # University of Ghana
        "www.unilorin.edu.ng",  # University of Ilorin, Nigeria
        "www.uonbi.ac.ke",  # University of Nairobi, Kenya

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

    # Create a Folium map
    traceroute_map = folium.Map(location=[0, 0], zoom_start=2)

    for index, entry in enumerate(websites.items()):
        website_list = entry[1]
        color = colors[index]

        for i in range(0, len(website_list)):
            website = website_list[i]
            print(website)

            hops = traceroute(website)

            locations = []  # To store locations for drawing lines

            for hop in hops:
                # Check if the IP address is not a private IP

                # Use an IP geolocation service (ip-api.com in this example) to map IPs to locations
                response = requests.get(f"http://ip-api.com/json/{hop}")
                data = response.json()
                city = data.get("city", "Unknown")
                country = data.get("country", "Unknown")
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

    # Save the map as an HTML file
    traceroute_map.save("traceroute_map.html")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        print("Usage: python map.py")
        sys.exit(1)

    map_request()
