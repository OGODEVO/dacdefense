from scapy.all import sniff, wrpcap
import threading

stop_sniffing = threading.Event()

def packet_callback(packet):
    """Callback function to process each captured packet."""
    print(packet.summary())
    wrpcap("network_log.pcap", packet, append=True)

def start_sniffer(interface=None):
    """Starts the network sniffer on a separate thread."""
    stop_sniffing.clear()
    sniffer_thread = threading.Thread(target=sniff, kwargs={
        'prn': packet_callback,
        'store': 0,
        'iface': interface,
        'stop_filter': lambda p: stop_sniffing.is_set()
    })
    sniffer_thread.start()
    print("Sniffer started...")

def stop_sniffer():
    """Stops the network sniffer."""
    stop_sniffing.set()
    print("Sniffer stopped.")
