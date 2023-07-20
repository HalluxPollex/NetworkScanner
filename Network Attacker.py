from scapy.all import *

#Target = input("Enter the target value: ")
Target = "192.168.1.1"
Registered_Ports = range(1, 1024)
open_ports = []

def scanport(port):

    src_port = RandShort()
    syn_pkt = sr1(IP(dst=Target) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5, verbose=0)

    try:

        if syn_pkt is not None:

            try:
                if syn_pkt.haslayer(TCP):

                    try:
                        if syn_pkt[TCP].flags == 0x12:
                            open_ports.append(port)
                            sr(IP(dst=Target) / TCP(sport=src_port, dport=port, flags="R"), timeout = 2)
                            print(open_ports)
                            return True

                    except Exception as e_inner:
                        print(f"Seems like port is closed: {e_inner}")
                        return False

            except Exception as e_middle:
                print(f"Seems like syn_pkt has no TCP layer: {e_middle}")
                return False

    except Exception as e_outer:
        print(f"Seems like Synchronization Packet does not exists: {e_outer}")
        return False

for port in Registered_Ports:
    #print("syn scan on, %s with ports %s" % (Target, port))
    scanport(port)