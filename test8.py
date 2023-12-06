import tkinter as tk
from tkinter import ttk, messagebox
import threading
from scapy.sendrecv import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.all import Ether, IPv6, TCP, UDP, Raw
import time
import logging
import nmap
import binascii
import re
import ipaddress

def remove_non_numeric_chars(payload):
    """Removes all non-numeric characters from the given payload."""
    regex = re.compile(r'[^\d]')
    return regex.sub('', payload)

class PacketHandler:
    def __init__(self, gui_instance):
        self.gui_instance = gui_instance
        self.last_packet_data = None
        self.packet_data = []
        self.packet_count = 0

    def packet_callback(self, packet):
        if not self.gui_instance.stop_sniffing_event.is_set():
            packet_number = self.packet_count + 1
            packet_time = time.strftime("%Y-%m-%d %H:%M:%S")
            src_ip = "N/A"
            dst_ip = "N/A"
            summary = packet.summary()

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

            # Log the captured packet
            logging.info(f"Packet {packet_number}: Time={packet_time}, SrcIP={src_ip}, DstIP={dst_ip}, Summary={summary}")

            packet_data = {
                "packet_number": packet_number,
                "packet_time": packet_time,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "summary": summary,
            }
            self.last_packet_data = packet_data
            self.packet_data.append(packet_data)
            self.packet_count += 1

            # Apply protocol filter
            protocol_filter = self.gui_instance.protocol_filter_var.get()
            if protocol_filter != "All":
                if (TCP in packet and protocol_filter != "TCP") or \
                   (UDP in packet and protocol_filter != "UDP") or \
                   (packet.haslayer(ICMP) and protocol_filter != "ICMP"):
                    return

            # Highlight packets with specific source or destination IP addresses
            highlighted_ips = ["192.168.0.1", "10.0.0.1"]
            item_id = f"packet_{packet_number}"
            self.gui_instance.packet_tree.insert("", "end", iid=item_id, values=(packet_number, packet_time, src_ip, dst_ip, summary))

            if src_ip in highlighted_ips or dst_ip in highlighted_ips:
                self.gui_instance.packet_tree.tag_configure('filtered', background='green')
                self.gui_instance.packet_tree.item(item_id, tags=('filtered',))

            # Check packet count limit
            packet_limit = int(self.gui_instance.packet_limit_var.get())
            if packet_limit > 0 and packet_number > packet_limit:
                self.gui_instance.stop_sniffing_event.set()

    def get_last_packet_data(self):
        return self.last_packet_data

    def sniff_packets(self):
        try:
            sniff(iface=self.gui_instance.interface_entry.get(), prn=self.packet_callback, stop_filter=self.is_stopped, promisc=True)
        except Exception as e:
            if not self.gui_instance.stop_sniffing_event.is_set():
                # Show an error message to the user in addition to printing to the console
                self.gui_instance.show_error_message(f"An error occurred: {e}")
                print("Error:", e)

    def is_stopped(self, packet):
        return self.gui_instance.stop_sniffing_event.is_set()

class GUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Packet Sniffer")
        self.window.geometry("800x600")
        self.window.configure(bg="black")  # Set the background color

        # Interface input field
        interface_label = ttk.Label(self.window, text="Interface:")
        interface_label.pack()
        self.interface_entry = ttk.Entry(self.window)
        self.interface_entry.pack()

        # Start button
        start_button = ttk.Button(self.window, text="Start Sniffing", command=self.start_sniffing, style='Colorful.TButton')
        start_button.pack()
        start_button_tooltip = ttk.Label(self.window, text="Click to start sniffing packets.")
        start_button_tooltip.pack()

        # Stop button
        stop_button = ttk.Button(self.window, text="Stop Sniffing", command=self.stop_sniffing, style='Colorful.TButton')
        stop_button.pack()
        stop_button_tooltip = ttk.Label(self.window, text="Click to stop sniffing packets.")
        stop_button_tooltip.pack()

        # Scan button
        scan_button = ttk.Button(self.window, text="Port Scan", command=self.port_scan, style='Colorful.TButton')
        scan_button.pack()
        scan_button_tooltip = ttk.Label(self.window, text="Click to perform a port scan on the target host.")
        scan_button_tooltip.pack()

        # Analyze button
        analyze_button = ttk.Button(self.window, text="Analyze Packet", command=self.analyze_packet, style='Colorful.TButton')
        analyze_button.pack()
        analyze_button_tooltip = ttk.Label(self.window, text="Click to analyze the selected packet.")
        analyze_button_tooltip.pack()

        save_button = ttk.Button(self.window, text="Save Packets", command=self.save_packets, style='Colorful.TButton')
        save_button.pack()
        save_button_tooltip = ttk.Label(self.window, text="Click to save captured packets.")
        save_button_tooltip.pack()

        # Filter by Protocol Combobox
        self.protocol_filter_var = tk.StringVar()
        self.protocol_filter_var.set("All")
        protocol_filter_label = ttk.Label(self.window, text="Filter by Protocol:")
        protocol_filter_label.pack()
        self.protocol_filter_combobox = ttk.Combobox(self.window, values=["All", "TCP", "UDP", "ICMP"], textvariable=self.protocol_filter_var)
        self.protocol_filter_combobox.pack()

        # Packet Count Limit Entry
        self.packet_limit_var = tk.StringVar()
        self.packet_limit_var.set("100")
        packet_limit_label = ttk.Label(self.window, text="Packet Limit:")
        packet_limit_label.pack()
        self.packet_limit_entry = ttk.Entry(self.window, textvariable=self.packet_limit_var)
        self.packet_limit_entry.pack()

        # Create a Treeview widget with columns
        self.packet_tree = ttk.Treeview(self.window, columns=("Number", "Time", "Source IP", "Destination IP", "Summary"), show="headings")
        self.packet_tree.heading("Number", text="Number")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source IP", text="Source IP")
        self.packet_tree.heading("Destination IP", text="Destination IP")
        self.packet_tree.heading("Summary", text="Summary")

        # Set column widths
        self.packet_tree.column("#1", width=50)
        self.packet_tree.column("#2", width=150)
        self.packet_tree.column("#3", width=150)
        self.packet_tree.column("#4", width=150)
        self.packet_tree.column("#5", width=300)
        self.packet_tree.pack()

        # Set tag configuration for the color scheme
        self.packet_tree.tag_configure('filtered', background='green')

        # Initialize thread and event
        self.sniffing_thread = None
        self.stop_sniffing_event = threading.Event()

        # Configure logging
        logging.basicConfig(filename="packet_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

        # Define a style for colorful buttons
        self.style = ttk.Style()
        self.style.configure("Colorful.TButton", foreground="white", background="#4CAF50", padding=5)

        # Define a style for Treeview
        self.style.configure("Colorful.Treeview", background="white", fieldbackground="white")

    def run(self):
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.window.mainloop()

    def start_sniffing(self):
        iface = self.interface_entry.get()

        if not iface:
            self.show_error_message("Please enter an interface name")
            return

        self.packet_handler = PacketHandler(self)
        self.stop_sniffing_event.clear()
        self.sniffing_thread = threading.Thread(target=self.packet_handler.sniff_packets)
        self.sniffing_thread.start()
        print("Packet sniffing started")

    def stop_sniffing(self):
        self.stop_sniffing_event.set()

    def on_closing(self):
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.stop_sniffing()
            self.sniffing_thread.join()
            print("Packet sniffing stopped")
        self.window.destroy()

    def analyze_packet(self):
        last_packet_data = self.packet_handler.get_last_packet_data()
        if last_packet_data:
            packet_number = last_packet_data["packet_number"] - 1
            src_ip = last_packet_data["src_ip"]
            dst_ip = last_packet_data["dst_ip"]
            summary = last_packet_data["summary"]
            selected_item = self.packet_tree.selection()
        else:
            messagebox.showinfo("No Packet", "No packet data available for analysis.")
        if selected_item:
            packet_number_str = self.packet_tree.item(selected_item, 'values')[0]
            try:
                packet_number = int(packet_number_str) - 1  # Adjust for 0-based indexing
                if 0 <= packet_number < len(self.packet_handler.packet_data):
                    selected_packet = self.packet_handler.packet_data[packet_number]

                    # Extract relevant details from the selected packet
                    src_ip = selected_packet["src_ip"]
                    dst_ip = selected_packet["dst_ip"]
                    summary = selected_packet["summary"]

                    # Analyze the selected packet using scapy
                    analysis_result = f"Source IP: {src_ip}\nDestination IP: {dst_ip}\nSummary: {summary}"

                    try:
                        # Construct the packet
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / Raw(load=binascii.unhexlify(remove_non_numeric_chars(summary)))

                        # Extract information from the packet
                        if IP in packet:
                            analysis_result += f"\nProtocol: IPv4"

                            if TCP in packet:
                                analysis_result += f"\nSource Port: {packet[TCP].sport}\nDestination Port: {packet[TCP].dport}"
                                if packet[TCP].dport == 80:
                                    analysis_result += "\nHTTP Traffic Detected"
                                elif packet[TCP].dport == 443:
                                    analysis_result += "\nHTTPS Traffic Detected"

                        # Extract and handle payload content
                        payload = packet[Raw].load
                        payload_str = payload.decode("utf-8", "replace")
                        analysis_result += f"\nPayload: {payload_str}"

                    except Exception as e:
                        analysis_result += f"\nError analyzing packet: {e}\nRaw Payload: {selected_packet.get('raw_payload', 'N/A')}"

                        messagebox.showinfo("Packet Analysis", analysis_result)
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid packet number: {e}")

    def port_scan(self):
        target_host = self.interface_entry.get()  # Use the input field for the target host
        if not target_host:
            self.show_error_message("Please enter a target host to scan")
            return
        # Add IP address validation before proceeding
        try:
            ipaddress.IPv4Address(target_host)
        except ipaddress.AddressValueError:
            self.show_error_message("Invalid target host IP address")
            return

        nm = nmap.PortScanner()
        try:
            nm.scan(target_host, arguments='-p 1-65535')  # Scan all ports

            open_ports = nm[target_host]['tcp'].keys()

            if open_ports:
                result = f"Open ports on {target_host}: {', '.join(map(str, open_ports))}"
                messagebox.showinfo("Port Scan Result", result)
            else:
                messagebox.showinfo("Port Scan Result", f"No open ports found on {target_host}")

        except nmap.PortScannerError as e:
            self.show_error_message(f"An error occurred during port scan: {e}")
        except Exception as e:
            self.show_error_message(f"An error occurred: {e}")

    def save_packets(self):
        file_path = "captured_packets.pcap"  # Change the filename as needed
        captured_packets = []

        for item in self.packet_tree.get_children():
            packet_values = self.packet_tree.item(item, 'values')
            src_ip = packet_values[2]
            dst_ip = packet_values[3]
            summary = packet_values[4]

            # Skip packets with "N/A" source or destination IP addresses
            if src_ip == "N/A" or dst_ip == "N/A":
                continue

            # Validate source and destination IP addresses
            try:
                ipaddress.IPv4Address(src_ip)
                ipaddress.IPv4Address(dst_ip)
            except ipaddress.AddressValueError as e:
                self.show_error_message(f"Invalid source or destination IP address: {e}")
                return

            # Remove the non-numeric characters from the raw payload
            raw_payload = remove_non_numeric_chars(summary)

            # Construct the captured packet
            captured_packet = IP(src=src_ip, dst=dst_ip) / Raw(load=raw_payload)
            captured_packets.append(captured_packet)

        try:
            if captured_packets:
                wrpcap(file_path, captured_packets)
                messagebox.showinfo("Packets Saved", f"Packets saved to {file_path}")
            else:
                messagebox.showinfo("Packets Saved", "No packets to save.")
        except Exception as e:
            self.show_error_message(f"An error occurred while saving packets: {e}")

if __name__ == "__main__":
    app = GUI()
    app.run()
