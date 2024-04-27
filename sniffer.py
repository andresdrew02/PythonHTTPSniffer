import psutil
import inquirer
import signal
from scapy.all import *
import argparse
from scapy.layers.inet import IP,TCP
from colorama import just_fix_windows_console, init, Fore, Back, Style

just_fix_windows_console()
interfaces  = psutil.net_if_addrs()

#CTRL-C
def signal_handler(sig, frame):
    print(Fore.CYAN + "[i] Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def filter_http_packet(packet: Packet):
    if not TCP in packet or not IP in packet:
        return False
    if packet[IP].dport != 80:
        return False
    if packet[TCP].payload is None:
        return False
    return True    

def capture_http_packets(interface=None, verbose=False, output="./captured_http_packets.txt"):
    captured_http_packets = []
    if interface is None:
        # Salir del programa
        sys.exit(1)
    
    # Capturar los paquetes
    while True:
        http_packets_sniffer = AsyncSniffer(iface=interface)
        http_packets_sniffer.start()
        if not hasattr(http_packets_sniffer, 'stop_cb'):
            time.sleep(0.1)
        results = http_packets_sniffer.stop()
        for packet in results:
            if filter_http_packet(packet) is False:
                if verbose == True: print(Fore.RED + packet.summary() + Style.RESET_ALL)
            else:
                try:
                    payload = str(bytes(packet[TCP].payload).decode("utf-8"))
                except:
                    payload = ""

                # Custom Packet Object
                custom_packet = {
                        "src_ip": packet[IP].src,
                        "dst_ip": packet[IP].dst,
                        "src_port": packet[TCP].sport,
                        "dst_port": packet[TCP].dport,
                        "timestamp": packet.time,
                        "payload": payload
                    }
                captured_http_packets.append(custom_packet)
                print(Back.GREEN + "[+] Got a Hit! ->" + Style.RESET_ALL + " " + packet.summary())
                print(payload)
                # Save to file
                with open(output, "a") as f:
                    f.write(str(custom_packet) + "\n")


def main():
    # Configuraciones
    parser = argparse.ArgumentParser(
        description="Sniff HTTP requests and filter out packets that don't contain HTTP requests."
    )
    parser.add_argument(
        '-i', '--iface', help="Interface to use for sniffing, if not set you will be prompted to use one"
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', help="Verbose mode to see all the packets captured"
    )
    parser.add_argument(
        '-o', '--output', help="Output file to save the captured HTTP packets", default="./captured_http_packets.txt"
    )

    # Interfaz a usar
    selected_interface = None
    args = parser.parse_args()
    if args.iface:
        if args.iface not in interfaces:
            print(f"{Fore.RED} [-] Interface {args.iface} not found")
            sys.exit(1)
        selected_interface = args.iface
    else:
        interface_question = inquirer.List(
            "interface",
            message="Select an interface;",
            choices=interfaces.keys()
        )
        selected_interface = inquirer.prompt([interface_question]).get("interface")
    print(f"[+] Output file will be saved to: {Fore.CYAN + args.output + Style.RESET_ALL}")
    print(f"[+] Selected interface: {Fore.CYAN + selected_interface + Style.RESET_ALL}, sniffing packets and filtering by HTTP requests...")
    # Check output file format
    if (args.output[-4:] != ".txt"):
        print(f"{Fore.RED} [-] Output file must be a .txt file")
        sys.exit(1)
    capture_http_packets(interface=selected_interface, verbose=args.verbose, output=args.output)


if __name__ == "__main__":
    main()