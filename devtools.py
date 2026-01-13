import shutil
import cmd
from scapy.all import sniff, Raw



print(r" _____    _                               _____      _       ______           _              _      ")
print(r"|_   _|  (_)                             |  ___|    (_)      |  _  \         | |            | |     ")
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

    def __init__(self):
        super().__init__()

    def do_speak(self, message):
        """Create a new text file in the current directory."""
        if message:
            print(message)
        else:
            print("Use it like: say hello world \nit will print what you type its a test run to check if this works")
    
    def do_exit(self, arg):
        return True

    def do_sniff(self, arg):
        if arg:
            sniff(count = int(arg), prn=lambda packet: print(packet[Raw].load) if packet.haslayer(Raw) else None)
        else:
            print("enter the amount of packets you wanna sniff on THIS computer")

    def do_sniffing(self, arg):
        sniff(prn=lambda packet: print(packet[Raw].load) if packet.haslayer(Raw) else None)


if __name__ == '__main__':
    Devtools().cmdloop()