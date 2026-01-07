from packet import Packet
from firewall import check_packet, log_packet

def menu():
    print("\n === Firewall CLI ===")
    print("1. Simulate Packet")
    print("2. Exit")

while True:
    menu()
    choice = input("Choice: ")

    if choice == "1":
        src_ip = input("Source IP: ")
        dst_ip = input("Destination IP: ")
        dst_port = int(input("Destination Port: "))
        protocol = input("Protocol: ")

        packet = Packet(
            src_ip,
            dst_ip,
            12345,          # src_port
            dst_port,
            protocol
        )
        decision = check_packet(packet)
        log_packet(packet,decision)

        print("Decision:",decision)

    elif choice == "2":
        break
        