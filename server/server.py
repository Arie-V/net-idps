import socket # For socket programming
import json # For JSON
import threading # For threading
import random # For generating random strings
import string # For generating random strings
import subprocess # For executing system commands
from database_manager import DatabaseManager  # Import DatabaseManager
import re # For regular expressions
import atexit # For cleanup
import time # For sleep
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf # For ARP
import paramiko # For SSH, Also shows warning a future feature will be removed, No concern for now.

# For localhost
host = 'localhost' # localhost by default
port = 8080 # Default port
db_file = 'scanner_db.db'
connected_users = {}  # Store (IP - localhost, port, connection, CLIENT/SCANNER, MAC, IP) and signature
connected_scanners = {}  # Store multiple scanners as {(IP, port): connection}
lock = threading.Lock()  # Lock for thread safety
scanner_process = None # Scanner process

# For windows SSH Server
IS_VM_MODE = False
WINDOWS_HOST = None
WINDOWS_USERNAME = None
WINDOWS_PASSWORD = None

# Initialize SSH Client
ssh_client = paramiko.SSHClient()  # More specific name
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Keep track of blocked IP's/MAC's
blocked_ips = set()
blocked_macs = set()

# Function to send ARP messages that update the ARP cache of connected clients to avoid ARP cache poisoning
def send_arp_messages():
    while True:
        with lock:
            for user_address, user_data in connected_users.items():
                if user_data['type'] == "CLIENT":
                    client_ip = user_data.get('ip', '')
                    client_mac = user_data.get('mac', '')
                    
                    if not client_ip or not client_mac:
                        print(f"Skipping ARP send for {user_address} due to missing IP or MAC")
                        continue

                    # Get server MAC address dynamically
                    server_mac = get_if_hwaddr(conf.iface)

                    # Create Ethernet frame + ARP packet
                    arp_packet = Ether(src=server_mac, dst=client_mac) / \
                                ARP(op=2,  # ARP Reply
                                    hwsrc=server_mac,  # Sender MAC
                                    psrc=client_ip,    # Sender IP
                                    hwdst=client_mac,  # Target MAC
                                    pdst=client_ip)    # Target IP

                    # Send the packet at Layer 2
                    sendp(arp_packet, verbose=False, iface=conf.iface)
                    print(f"Sent ARP message: {client_ip} is at {server_mac}")
                    
        time.sleep(10)  # Wait for 10 seconds before sending the next round

# Function to start the ARP thread
def start_arp_thread():
    arp_thread = threading.Thread(target=send_arp_messages)
    arp_thread.daemon = True  # Daemonize thread to exit when the main program exits
    arp_thread.start()

# Function to get the IP of this machine
def get_ip_address():
    return socket.gethostbyname(socket.gethostname())

# Function to generate a random string
def generate_random_string(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Get the MAC address for a given IP using the ARP table
def get_mac_address(ip_address):
    try:
        arp_output = subprocess.check_output(['ip', 'neigh', 'show', ip_address]).decode('utf-8')
        match = re.search(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", arp_output)
        return match.group(0) if match else None
    except Exception as e:
        print(f"Error retrieving MAC address for {ip_address}: {e}")
        return None

# Store the user's signature and connection
def store_user_signature(client_address, signature, conn, conn_type, client_mac, client_ip):
    with lock:
        connected_users[client_address] = {'signature': signature, 'conn': conn, 'type': conn_type, 'mac': client_mac, 'ip' : client_ip}

# Verify the signature of a client
def verify_signature(client_address, signature):
    with lock:
        return connected_users.get(client_address, {}).get('signature') == signature

# Block an IP address
def block_ip(ip_address):
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
    blocked_ips.add(ip_address)

# Block a MAC address
def block_mac(mac_address):
    subprocess.run(['sudo', 'ebtables', '-A', 'INPUT', '-s', mac_address, '-j', 'DROP'])
    blocked_macs.add(mac_address)

# Unblock a blocked IP address
def unblock_ip(ip_address):
    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'])

# Unblock a blocked MAC address
def unblock_mac(mac_address):
    subprocess.run(['sudo', 'ebtables', '-D', 'INPUT', '-s', mac_address, '-j', 'DROP'])

# Unblock all blocked IP's and MAC's
def unblock_all():
    for ip in blocked_ips:
        unblock_ip(ip)
    for mac in blocked_macs:
        unblock_mac(mac)

# Register the unblock_all function to be called on program exit
atexit.register(unblock_all)

# Function to get the VM name by MAC address
def get_vm_name_by_mac(TARGET_MAC):
    """Retrieve VM name using the MAC address."""
    list_vms_command = '"C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe" list vms'
    # Command to get the MAC address of a VM
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the Windows server
    try:
        print(f"Connecting to {WINDOWS_HOST}...")
        ssh_client.connect(WINDOWS_HOST, username=WINDOWS_USERNAME, password=WINDOWS_PASSWORD)
        
        # Execute the command to list all VMs
        print(f"Fetching VM list...")
        stdin, stdout, stderr = ssh_client.exec_command(list_vms_command)

        # Read the output and error
        vms_output = stdout.read().decode()
        error = stderr.read().decode()

        # Print the output and error
        if error:
            print(f"Error:\n{error}")
            return None

        # Extract VM names
        vm_names = re.findall(r'"([^"]+)"', vms_output)
        
        # Check each VM for the MAC address
        for vm_name in vm_names:
            print(f"Checking VM: {vm_name}")

            # Command to get the MAC address of a VM
            mac_command = f'"C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe" showvminfo "{vm_name}" --machinereadable | findstr macaddress1'
            stdin, stdout, stderr = ssh_client.exec_command(mac_command)

            # Read the output
            mac_output = stdout.read().decode()
            mac_match = re.search(r'macaddress1="([A-F0-9]+)"', mac_output, re.IGNORECASE)

            # Check if the MAC address matches the target MAC
            if mac_match:
                mac = mac_match.group(1).strip().upper()
                print(f"Found MAC: {mac} for VM: {vm_name}")
                if mac == TARGET_MAC:
                    print(f"Match found: {vm_name} (MAC: {TARGET_MAC})")
                    return vm_name

        print("No VM found with the given MAC address.")
        return None

    except Exception as e:
        print(f"Connection Error: {e}")
        return None

    finally:
        ssh_client.close()
        print("SSH connection closed.")

# Function to execute a command on the Windows server
def execute_command(vm_name, action):
    """Control the VM's network adapter using VBoxManage."""
    KICK_COMMAND = f'"C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe" controlvm "{vm_name}" setlinkstate1 off'
    UNKICK_COMMAND = f'"C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe" controlvm "{vm_name}" setlinkstate1 on'
    
    # Determine the command based on the action
    command = KICK_COMMAND if action == "off" else UNKICK_COMMAND

    # Connect to the Windows server
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the Windows server
    try:
        print(f"Connecting to {WINDOWS_HOST}...")
        ssh_client.connect(WINDOWS_HOST, username=WINDOWS_USERNAME, password=WINDOWS_PASSWORD)

        # Execute the command
        print(f"Executing command: {command}")
        stdin, stdout, stderr = ssh_client.exec_command(command)

        # Read the output and error
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        # Print the output and error
        if output:
            print(f"Output:\n{output}")
        if error:
            print(f"Error:\n{error}")

        print(f"Command executed successfully: {command}")

    except Exception as e:
        print(f"Connection Error: {e}")

    finally:
        ssh_client.close()
        print("SSH connection closed.")

# Disables ICMP redirect messages for all interfaces on a Linux system.
def disable_icmp_redirects():
    try:
        # Disable ICMP redirects for all interfaces
        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"],
            check=True,
        )
        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.conf.default.accept_redirects=0"],
            check=True,
        )
        print("ICMP redirect messages have been disabled.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to disable ICMP redirects: {e}")

# Checks if a value is an IP address
def is_ip_address(value):
    # Regular expression pattern for an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(ip_pattern, value) is not None

# Checks if a value is a MAC address
def is_mac_address(value):
    # Regular expression pattern for a MAC address
    mac_pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    return re.match(mac_pattern, value) is not None

# Function to send a message to a client
def send_message(client_socket, message):
    try:
        # Send the message to the client
        client_socket.send(message.encode('utf-8'))
    except Exception as e:
        print(f"Failed to send message: {e}")

# Function to handle client connections
def handle_client(conn, addr, db_manager):
    print(f"Connection from {addr}")
    client_address = addr  # addr is a tuple (IP, port)

    # Generate a random signature for the client
    current_signature = generate_random_string()
    store_user_signature(client_address, current_signature, conn, "", "", "")  # Store (IP, port, connection, CLIENT/SCANNER, MAC) and initial signature

    try:
        while True:
            # Receive data from the client
            data = conn.recv(1024) # Buffer size up to 10,000 bytes
            if not data:
                break

            client_msg = json.loads(data.decode('utf-8'))
            print(f"Received from client {addr}: {client_msg}")

            # Handle CONNECT message
            if client_msg['type'] == 'CONNECT':
                # Get client's MAC address
                client_mac  = client_msg['mac']
                client_ip = client_msg['ip']

                # Generate a new signature and update the client's signature
                new_signature = generate_random_string()
                store_user_signature(client_address, new_signature, conn, "CLIENT", client_mac, client_ip)  # Update with new signature and connection
                connect_response = {'type': 'CONNECT', 'status': '1', 'signature': new_signature}

                send_message(conn, json.dumps(connect_response))
                print(f"Sent to client {addr}: {connect_response}")
                continue  # No need to verify signature for CONNECT message

            # Handle SCANNER_CONNECT message (Allow multiple scanners)
            if client_msg['type'] == 'SCANNER_CONNECT':
                with lock:
                    connected_scanners[client_address] = conn  # Store scanner connection
                
                # Generate a new signature and update the scanner's signature
                new_signature = generate_random_string()
                store_user_signature(client_address, new_signature, conn, "SCANNER", "", "")  # Update with new signature
                connect_response = {'type': 'SCANNER_CONNECT', 'status': '1', 'signature': new_signature}
                
                # Send a response to the scanner
                send_message(conn, json.dumps(connect_response))
                print(f"Scanner {addr} connected.")
                continue  

            # Verify signature for all other messages
            if not verify_signature(client_address, client_msg.get('signature', '')):
                error_response = {'type': 'ERROR', 'status': 'invalid_signature'}

                # Send an error response
                send_message(conn, json.dumps(error_response))
                print(f"Sent to client {addr}: {error_response}")
                continue

            # Handle LOGIN message
            if client_msg['type'] == 'LOGIN':
                # Get the username and password from the client message
                username = client_msg['username']
                password = client_msg['password']

                # Generate a new signature and update the client's signature
                new_signature = generate_random_string()
                client_mac = connected_users.get(client_address, {}).get('mac', '')
                client_ip = connected_users.get(client_address, {}).get('ip', '')
                store_user_signature(client_address, new_signature, conn, "CLIENT", client_mac, client_ip)  # Update with new signature
                
                # Validate the login credentials
                if db_manager.validate_login(username, password):
                    login_response = {'type': 'LOGIN', 'status': '1', 'signature': new_signature}
                    print("Login successful.")
                else:
                    login_response = {'type': 'LOGIN', 'status': '0', 'signature': new_signature}
                    print("Login unsuccessful.")
                
                # Send the login response
                send_message(conn, json.dumps(login_response))
                print(f"Sent to client {addr}: {login_response}")

            # Handle SIGNUP message
            elif client_msg['type'] == 'SIGNUP':
                # Get the username and password from the client message
                username = client_msg['username']
                password = client_msg['password']
                
                # Generate a new signature and update the client's signature
                new_signature = generate_random_string()
                client_mac = connected_users.get(client_address, {}).get('mac', '')
                client_ip = connected_users.get(client_address, {}).get('ip', '')
                store_user_signature(client_address, new_signature, conn, "CLIENT", client_mac, client_ip)  # Update with new signature

                # Check if the username already exists
                if db_manager.user_exists(username):
                    signup_response = {'type': 'SIGNUP', 'status': '0', 'message': 'Username already exists.', 'signature': new_signature}
                    print("Signup failed: username already exists.")
                else:
                    db_manager.add_user(username, password)
                    signup_response = {'type': 'SIGNUP', 'status': '1', 'signature': new_signature}
                    print("Signup successful.")
                
                # Send the signup response
                send_message(conn, json.dumps(signup_response))
                print(f"Sent to client {addr}: {signup_response}")

            elif client_msg['type'] == 'REPORT':
                # Generate a new signature and update the scanner's signature
                new_signature = generate_random_string()
                store_user_signature(client_address, new_signature, conn, "SCANNER", "", "")  # Update with new signature

                # Get the attack details
                attack_details = client_msg.get('attack_details', '')

                # Log the received attack details and check if it's a string
                if isinstance(attack_details, str) and ',' in attack_details:
                    attack_type, suspected_value = attack_details.split(',')
                    print(f"Attack type: {attack_type}, Suspected value: {suspected_value}")
                else:
                    # Send an error response if the attack details are invalid
                    error_response = {'type': 'ERROR', 'status': 'invalid_attack_details_format'}
                    send_message(conn, json.dumps(error_response))
                    print(f"Sent to client {client_address}: {error_response}")
                    continue
                
                # Declare attacker values and determine if the value is an IP or MAC address
                suspected_ip = None
                suspected_mac = None

                # Check if the suspected value is an IP or MAC address
                if is_ip_address(suspected_value):
                    suspected_ip = suspected_value
                elif is_mac_address(suspected_value):
                    suspected_mac = suspected_value

                # Report the attack to the database
                db_manager.report_attack(attack_type, suspected_ip, suspected_mac)

                # If the attack is ICMP redirect, disable ICMP redirects
                if "ICMP_REDIRECT" in attack_type:
                    disable_icmp_redirects()
                
                # Respond to scanner with report acknowledge message
                report_response = {'type': 'REPORT', 'status': '1', 'signature': new_signature}
                send_message(conn, json.dumps(report_response))
                print(f"Sent to client {client_address}: {report_response}")

                # Broadcast the report details to all connected users and update their signatures
                for user_address, user_data in connected_users.items():
                    if user_data['type'] == "CLIENT" and user_data['conn'] != conn:  # Skip the original sender
                        # Generate a new signature for the user
                        user_signature = generate_random_string()
                        client_mac = connected_users.get(client_address, {}).get('mac', '')
                        client_ip = connected_users.get(client_address, {}).get('ip', '')

                        # Check if the user's IP or MAC matches the suspected value
                        print(f"Checking user {user_address[0]} with MAC {user_data['mac']}")
                        print("Suspected_value: ", suspected_value)
                        if suspected_value.strip() == user_data['ip'].strip() or suspected_value.strip().lower() == user_data['mac'].strip().lower():
                            # Block the user's IP and MAC
                            kick_message = {'type': 'KICK', 'status': '1', 'signature': user_signature}
                            print(f"Sending kick message to {user_address}: {kick_message}")
                            send_message(user_data['conn'], json.dumps(kick_message))
                            
                            # Block the user's IP and MAC
                            block_ip(user_data['ip'])
                            block_mac(user_data['mac'])
                            
                            # This command kicks the attacker from the network
                            if IS_VM_MODE:
                                # Get the VM name by MAC address
                                vm_name = get_vm_name_by_mac(user_data['mac'])
                                # Execute the command to kick the attacker
                                execute_command(vm_name, "off")
                                print(f"Kicked attacker with MAC {user_data['mac']} from the virtual network.")

                        # Update the user's signature
                        store_user_signature(user_address, user_signature, user_data['conn'], "CLIENT", client_mac, client_ip)  # Update with new signature
                        broadcast_message = {
                            'type': 'REPORT',
                            'status': '1',
                            'attack_details': attack_details,
                            'signature': user_signature
                        }
                        user_conn = user_data['conn']  # Assuming you store the connection object
                        try:
                            # Send the report to the user
                            send_message(user_conn, json.dumps(broadcast_message))
                            print(f"Broadcasted report to {user_address}: {broadcast_message}")
                        except Exception as e:
                            print(f"Error broadcasting to {user_address}: {e}")

                
            elif client_msg['type'] == 'GET_LOGS':
                # Generate a new signature and send the logs
                new_signature = generate_random_string()
                client_mac = connected_users.get(client_address, {}).get('mac', '')
                client_ip = connected_users.get(client_address, {}).get('ip', '')
                store_user_signature(client_address, new_signature, conn, "CLIENT", client_mac, client_ip)  # Update signature

                # Get logs from the database
                logs_json = db_manager.get_logs_as_json()
                logs_data = json.loads(logs_json)  # Convert logs string back to JSON

                # Check if logs are available
                if logs_data["logs"]:
                    response = {
                        'type': 'GET_LOGS',
                        'status': '1',
                        'logs': logs_data["logs"],  # Send logs as a JSON array
                        'signature': new_signature
                    }
                else:
                    response = {
                        'type': 'GET_LOGS',
                        'status': '0',  # Indicate no logs are available
                        'logs': [],
                        'signature': new_signature
                    }

                send_message(conn, json.dumps(response))
                print(f"Sent to client {addr}: {response}")

            # Handle DISCONNECT message
            elif client_msg['type'] == 'DISCONNECT':
                print(f"Client {addr} disconnected.")
                break

            # Handle invalid requests
            else:
                # Generate a new signature and send an error response
                new_signature = generate_random_string()
                client_mac = connected_users.get(client_address, {}).get('mac', '')
                client_ip = connected_users.get(client_address, {}).get('ip', '')
                store_user_signature(client_address, new_signature, conn, "", client_mac, client_ip)  # Update with new signature
                error_response = {'type': 'ERROR', 'status': 'invalid_request', 'signature': new_signature}
                # Send the error response
                send_message(conn, json.dumps(error_response))
                print(f"Sent to client {addr}: {error_response}")

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    
    finally:
        # Close the connection
        conn.close()
        with lock:
            # Remove the client from the connected users list
            if client_address in connected_users:
                del connected_users[client_address]
            if client_address in connected_scanners:
                print(f"Scanner {client_address} disconnected.")
                del connected_scanners[client_address]

# Function to start the scanner
def start_scan():
    global scanner_process

    # Check if scanner is already running
    if scanner_process is not None:
        print("Scanner is already running.")
        return

    # Start the scanner process
    try:
        scanner_process = subprocess.Popen(
            ["sudo", "./packet_scanner"],  # Command to start the scanner
            stdout=subprocess.PIPE,       # Capture stdout
            stderr=subprocess.PIPE,       # Capture stderr
            text=True                     # Enable text mode for output
        )
    except Exception as e:
        print(f"Failed to start scanner: {e}")

# Function to stop the scanner
def stop_scan():
    global scanner_process

    if scanner_process is None:
        print("Scanner is not running.")
        return

    try:
        # Send termination signal
        scanner_process.terminate()
        scanner_process.wait()  # Wait for the process to terminate
        scanner_process = None
    except Exception as e:
        print(f"Failed to stop scanner: {e}")

# Function to start the server and listen for incoming connections
def start_server():
    db_manager = DatabaseManager(db_file)  # Initialize the database manager

    # Build server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}...")

    # Start the scanner on server side
    start_scan()

    # Start the ARP thread
    start_arp_thread()

    while True:
        # Start accepting users
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr, db_manager))
        client_thread.start()

# This function will be used in the final version, it will select the mode of the server
def select_mode():
    try:
        # Global variables to be used in the server
        global WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD, host
        # Ask the user to select the mode
        print("\n\nWelcome to the server, please select a mode:")
        print("1. VM Mode - Sits in a virtual network, must include outside SSH Windows server (Full working kicker)")
        print("2. Regular Mode - Sits on the real network, can be used in all networks (No kicker but still blocks the attacks)")
        print("Select mode:")
        mode = input()
        if mode == "1":
            # Ask for the Windows server IP, username and password if in VM mode
            WINDOWS_HOST = input("Enter the Windows server IP: ")
            WINDOWS_USERNAME = input("Enter the Windows username: ")
            WINDOWS_PASSWORD = input("Enter the Windows password: ")
            IS_VM_MODE = True
        elif mode == "2":
            print("Regular mode selected, pick the server IP:")
            print("1. Localhost")
            print("2. This machine's IP")
            ip_choice = input()
            if ip_choice == "1":
                host = "localhost"
            elif ip_choice == "2":
                host = get_ip_address()
        else:
            print("Invalid mode selected.")
            return select_mode()
    except Exception as e:
        print(f"Error selecting mode: {e}")
        return select_mode()

if __name__ == "__main__":
    # Selects the mode
    select_mode()

    # Start the server
    start_server()
