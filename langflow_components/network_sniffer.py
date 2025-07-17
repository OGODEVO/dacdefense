
from langflow.custom import Component
from langflow.io import Handle, Output
from langflow.schema import Data
import scapy.all as scapy
import threading
import time

class NetworkSniffer(Component):
    display_name = "Network Sniffer"
    description = "Sniffs network packets and extracts relevant data."
    icon = "wifi"

    outputs = [
        Output(display_name="Packet Data", name="packet_data", method="get_packet_data")
    ]

    def __init__(self):
        super().__init__()
        self.packets = []
        self.stop_sniffing = threading.Event()

    def start_sniffing(self):
        scapy.sniff(prn=self.process_packet, stop_filter=self.should_stop)

    def process_packet(self, packet):
        if packet.haslayer(scapy.IP):
            self.packets.append(str(packet.summary()))

    def should_stop(self, packet):
        return self.stop_sniffing.is_set()

    def get_packet_data(self) -> Data:
        self.stop_sniffing.clear()
        sniffer_thread = threading.Thread(target=self.start_sniffing)
        sniffer_thread.start()
        time.sleep(10)  # Sniff for 10 seconds
        self.stop_sniffing.set()
        sniffer_thread.join()
        return Data(data={"packets": self.packets})
