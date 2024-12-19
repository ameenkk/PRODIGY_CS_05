from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import flet as ft
import csv
from collections import Counter
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import threading

# Global variable to control packet sniffing
stop_sniffing = False


# Function to process each packet
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = bytes(packet[IP].payload).hex()[:50]
        return {
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Payload (Hex)": payload,
        }
    return None


# Function to filter packets by protocol
def filter_packet_by_protocol(packet, selected_protocol):
    if selected_protocol != "All":
        if selected_protocol == "TCP" and not packet.haslayer(TCP):
            return False
        if selected_protocol == "UDP" and not packet.haslayer(UDP):
            return False
        if selected_protocol == "ICMP" and not packet.haslayer(ICMP):
            return False
    return True


# Function to generate protocol usage chart
def generate_chart(protocol_counts):
    plt.figure(figsize=(6, 4))
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())
    plt.bar(protocols, counts, color="skyblue")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.title("Protocol Usage Distribution")
    plt.tight_layout()

    # Save chart to a buffer
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    base64_image = base64.b64encode(buf.read()).decode("utf-8")
    buf.close()
    plt.close()
    return base64_image


# Flet UI function
def main(page: ft.Page):
    page.title = "Packet Sniffer Tool"
    page.window_width = 1000
    page.window_height = 800

    # UI Components
    protocol_search = ft.TextField(label="Search Protocol", hint_text="Enter Protocol (TCP/UDP/ICMP)")

    packet_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Source IP")),
            ft.DataColumn(ft.Text("Destination IP")),
            ft.DataColumn(ft.Text("Protocol")),
            ft.DataColumn(ft.Text("Payload (Hex)")),
        ],
        rows=[],
    )

    protocol_chart = ft.Image(src="", fit="contain", width=600, height=400)
    captured_packets = []
    protocol_counts = Counter()

    def update_chart():
        if protocol_counts:
            chart_image = generate_chart(protocol_counts)
            protocol_chart.src_base64 = chart_image
            page.update()

    def start_sniffing(e):
        global stop_sniffing
        stop_sniffing = False
        packet_table.rows.clear()
        captured_packets.clear()
        protocol_counts.clear()
        page.update()

        def capture_packets(packet):
            global stop_sniffing
            if stop_sniffing:
                return False  # Stops sniffing if flag is set
            # Only capture packets that match the selected protocol
            if filter_packet_by_protocol(packet, protocol_search.value.strip()):
                data = process_packet(packet)
                if data:
                    captured_packets.append(data)
                    protocol_counts[data["Protocol"]] += 1
                    packet_table.rows.append(
                        ft.DataRow(
                            cells=[
                                ft.DataCell(ft.Text(data["Source IP"])),
                                ft.DataCell(ft.Text(data["Destination IP"])),
                                ft.DataCell(ft.Text(str(data["Protocol"]))),
                                ft.DataCell(ft.Text(data["Payload (Hex)"])),
                            ]
                        )
                    )
                    page.update()
                    update_chart()

        # Run sniffing in a separate thread to avoid blocking the UI
        threading.Thread(target=lambda: sniff(prn=capture_packets)).start()

    def stop_sniffing_packets(e):
        global stop_sniffing
        stop_sniffing = True
        page.snackbar = ft.Snackbar(ft.Text("Sniffing stopped"))
        page.update()

    def save_to_csv(e):
        if captured_packets:
            filename = "captured_packets.csv"
            with open(filename, "w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=captured_packets[0].keys())
                writer.writeheader()
                writer.writerows(captured_packets)
            page.snackbar = ft.Snackbar(ft.Text(f"Packets saved to {filename}"))
            page.update()

    # Buttons
    start_button = ft.ElevatedButton(text="Start Sniffing", on_click=start_sniffing)
    stop_button = ft.ElevatedButton(text="Stop Sniffing", on_click=stop_sniffing_packets)
    save_button = ft.ElevatedButton(text="Save to CSV", on_click=save_to_csv)

    # Layout
    page.add(
        ft.Column(
            [
                ft.Text("Packet Sniffer Tool", size=24, weight="bold"),
                protocol_search,
                ft.Row([start_button, stop_button, save_button]),
                protocol_chart,
                packet_table,
            ],
            scroll="always",  # Ensure scrollability
        )
    )


# Run the Flet app
if __name__ == "__main__":
    ft.app(target=main)
