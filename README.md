Packet Sniffer Tool
Overview
The Packet Sniffer Tool is an advanced network packet capture and analysis tool built using Python. This tool captures network packets in real-time and analyzes relevant packet details such as source and destination IP addresses, protocols, and payload data. Users can filter the captured packets by protocol (TCP, UDP, ICMP) and visualize the distribution of protocols in a chart. The captured packet data can also be exported to a CSV file for further analysis.

This tool uses Scapy for packet sniffing, Matplotlib for visualizing protocol distribution, and Flet for building a user-friendly graphical interface.

Features
Real-time packet sniffing: Capture live network packets using Scapy.
Protocol Filtering: Filter packets based on the selected protocol (TCP, UDP, ICMP).
Data Visualization: View the distribution of packet protocols in a bar chart.
Export to CSV: Save captured packet data to a CSV file for further analysis.
Simple and intuitive UI: Built with Flet for easy interaction.
Requirements
To run this tool, you need to have the following Python packages installed:

Scapy: For packet sniffing and analysis.
Flet: For building the graphical user interface (GUI).
Matplotlib: For visualizing the distribution of protocols.
Install Required Packages
You can install the required dependencies using pip:

bash
Copy code
pip install scapy flet matplotlib
How to Use
Start the tool:

Run the Python script to start the packet sniffer tool.
bash
Copy code
python packet_sniffer.py
Sniff Packets:

Click the "Start Sniffing" button to start capturing packets.
You can filter packets by entering the desired protocol (e.g., TCP, UDP, or ICMP) in the search box.
Stop Sniffing:

Click the "Stop Sniffing" button to stop capturing packets.
Save Captured Packets:

Click the "Save to CSV" button to save the captured packet data to a CSV file.
View Protocol Distribution:

The protocol distribution is displayed as a bar chart, showing the frequency of each protocol type.
UI Elements
Search Protocol: A search box to filter packets based on protocol. You can enter TCP, UDP, or ICMP.
Start Sniffing Button: Begins the packet sniffing process.
Stop Sniffing Button: Stops the packet sniffing process.
Save to CSV Button: Saves the captured packets to a CSV file for further analysis.
Protocol Distribution Chart: A real-time bar chart that displays the distribution of packet protocols.
Packet Data Columns
Source IP: The IP address of the packet's source.
Destination IP: The IP address of the packet's destination.
Protocol: The protocol of the packet (TCP, UDP, ICMP).
Payload (Hex): The first 50 characters of the packet's payload in hexadecimal format.
Example Output
The captured packet data is displayed in a table with the following columns:

Source IP	Destination IP	Protocol	Payload (Hex)
192.168.1.1	192.168.1.2	TCP	450000284000400040068c11...
192.168.1.3	192.168.1.4	UDP	4500001c000040000002f0c9...
The protocol distribution is displayed as a bar chart, showing the number of occurrences of each protocol.

Known Issues
Performance: The tool may not perform well with a high volume of network traffic, as it captures and processes each packet individually in real-time.
Permissions: On some systems, running the script may require administrative privileges to capture network packets.
Contributing
Feel free to contribute to the development of this tool by forking the repository and submitting pull requests. Contributions can include bug fixes, feature enhancements, or improvements in performance.

Steps to Contribute:
Fork the repository.
Clone your forked repository.
Make changes and test them locally.
Create a pull request with a clear description of the changes.
