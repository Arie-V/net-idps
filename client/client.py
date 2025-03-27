import socket # Library to create sockets
import json # Library to work with JSON data
import scapy.all as scapy # Library to sniff network from the client
import threading # Library to create threads
import time # Library to use time functions
import subprocess # Library to execute command lines in code
import os # for the operating system
import atexit # Library to register functions to be called on program exit
import tkinter as tk # Library to create GUI
import uuid # Library to get the MAC address of the device

# Global flag to indicate if logged in
flag_isloggedin = False
current_signature = ""  # Store signature globally
scanner_process = None  # Process flag and indicator if the scanner is running

# Keep track of blocked IP's/MAC's
blocked_ips = set()
blocked_macs = set()

# Functions for blocking and unblocking IP's and MAC's
def block_ip(ip_address):
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
    blocked_ips.add(ip_address)

# Function to block a MAC address
def block_mac(mac_address):
    subprocess.run(['sudo', 'ebtables', '-A', 'INPUT', '-s', mac_address, '-j', 'DROP'])
    blocked_macs.add(mac_address)

# Function to unblock an IP address
def unblock_ip(ip_address):
    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'])

# Function to unblock a MAC address
def unblock_mac(mac_address):
    subprocess.run(['sudo', 'ebtables', '-D', 'INPUT', '-s', mac_address, '-j', 'DROP'])

# Function to unblock all IP's and MAC's on program exit
def unblock_all():
    for ip in blocked_ips:
        unblock_ip(ip)
    for mac in blocked_macs:
        unblock_mac(mac)

# Register the unblock_all function to be called on program exit
atexit.register(unblock_all)

# Function to get current MAC address
def get_mac_address():
    # Get the MAC address of the device using the uuid library
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xFF) for i in range(0, 48, 8)][::-1])
    return mac

# Function to get current IP address
def get_ip_address():
    # Get the IP address of the device using the scapy library
    return scapy.get_if_addr('wlan0')

def disconnect_wifi(interface="wlan0"):
    """This function uses a command line tool that manages the network manager, it will disconnect the client if suspicious activity is detected and will be installed if not found on this device"""
    try:
        # Use nmcli to disconnect the interface
        subprocess.run(["nmcli", "device", "disconnect", interface], check=True)
        print("Suspicious activity detected, disconnecting from the network.")
    except FileNotFoundError:
        print("nmcli not found. Installing...")
        try:
            # Install the network manager tool
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y", "network-manager"], check=True)
            disconnect_wifi()
        except subprocess.CalledProcessError:
            print("Failed to install nmcli. Please install it manually.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to disconnect {interface} using nmcli: {e}")

def disable_icmp_redirects():
    """
    Disables ICMP redirect messages for all interfaces on a Linux system.
    """
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

def send_message(client_socket, message):
    try:
        # Send the message to the server
        client_socket.send(message.encode('utf-8'))
    except Exception as e:
        print(f"Failed to send message: {e}")

def login(client_socket, username, password):
    global flag_isloggedin, current_signature

    # Create JSON message for LOGIN
    login_message = {'type': 'LOGIN', 'username': username, 'password': password, 'signature': current_signature}

    send_message(client_socket, json.dumps(login_message))

def signup(client_socket, username, password):
    global current_signature

    # Create JSON message for SIGNUP
    signup_message = {'type': 'SIGNUP', 'username': username, 'password': password, 'signature': current_signature}

    send_message(client_socket, json.dumps(signup_message))

def get_logs(client_socket):
    global current_signature
    # Send the GET_LOGS request
    get_logs_message = {'type': 'GET_LOGS', 'signature': current_signature}
    send_message(client_socket, json.dumps(get_logs_message))

def send_disconnect_message(client_socket):
    global current_signature
    stop_scan()
    # Send the DISCONNECT message
    disconnect_message = {'type': 'DISCONNECT', 'signature': current_signature}
    send_message(client_socket, json.dumps(disconnect_message))

def display_logs(logs):
    # Create a new window to display the logs
    log_window = tk.Tk()
    log_window.title("Logs")

    # Create a text widget to display the logs
    log_text = tk.Text(log_window)
    log_text.pack(fill="both", expand=True)

    # Insert each log entry into the text widget
    for log in logs:
        log_text.insert(tk.END, f"ID: {log['id']}, Type: {log['attack_type']}, "
                                f"IP: {log['suspected_ip']}, MAC: {log['suspected_mac']}, Time: {log['time']}\n")

    # Start the main loop for the window
    log_window.mainloop()

# Listens to the server, if the server sends us REPORT and the attacker's info, we block him. if we get KICK, we disconnect from the network
def listen_to_server(client_socket):
    try:
        # Use the global variables
        global current_signature, flag_isloggedin

        while True:
            # Receive data from the server
            data = client_socket.recv(10000).decode('utf-8')
            if data:
                try:
                    # Parse the JSON data
                    response = json.loads(data)
                    current_signature = response.get('signature', current_signature)
                    
                    # Check the type of message
                    if response['type'] == 'SIGNUP':
                        print("Signup successful!" if response['status'] == '1' 
                              else f"Signup unsuccessful. Reason: {response.get('message', 'Unknown error')}")

                    elif response['type'] == 'LOGIN':
                        if response['status'] == '1':
                            flag_isloggedin = True
                            print("Login successful!")
                        else:
                            print("Login unsuccessful.")

                    elif response.get('type') == 'KICK':
                        print("Suspicious activity detected from this device, disconnecting from LAN...")
                        disconnect_wifi()

                    elif response.get('type') == 'GET_LOGS':
                        if response.get('status') == '1':
                            display_logs(response['logs'])
                        else:
                            print(f"Failed to get logs. Reason: {response.get('message', 'Unknown error')}")
                    
                    elif response.get('type') == 'REPORT' and response.get('status') == '1':
                        attack_details = response.get('attack_details', '')
                        if ',' in attack_details:
                            attack_type, suspected_value = attack_details.split(',')
                            if flag_isloggedin:
                                print(f"Attack type: {attack_type}, Suspected value: {suspected_value}")

                except json.JSONDecodeError:
                    print(f"Received non-JSON data: {data}")
    except Exception as e:
        print(f"Error in server listener thread: {e}")

def start_scan():
    global scanner_process

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

def stop_scan():
    global scanner_process

    # Stop the scanner process
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

def menu(client_socket):
    # Start the listener thread
    thread = threading.Thread(target=listen_to_server, args=(client_socket,))
    thread.daemon = True
    thread.start()
    
    while True:
        # Wait a moment for any pending server responses
        time.sleep(0.1)
        
        if not flag_isloggedin:
            option = input("1. Login \n2. Signup\n3. Disconnect\nEnter option: ")

            if option == '1':
                username = input("Enter username: ")
                password = input("Enter password: ")
                login(client_socket, username, password)
            elif option == '2':
                username = input("Enter username: ")
                password = input("Enter password: ")
                signup(client_socket, username, password)
            elif option == '3':
                send_disconnect_message(client_socket)
                print("Disconnecting from server.")
                break
            else:
                print("Invalid option.")
        else:
            option = input("1. View logs\n2. Disconnect\nEnter option: ")
            
            if option == '1':
                get_logs(client_socket)
            elif option == '2':
                send_disconnect_message(client_socket)
                print("Disconnecting from server.")
                break
            else:
                print("Invalid option.")

def connect_to_server(host, port):
    """This function loops until it connects to the server"""
    while True:
        try:
            # Attempt to connect to the server
            print(f"Attempting to connect to server at {host}:{port}...")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            print("Connected to the server!")
            return client_socket
        except (ConnectionRefusedError, socket.timeout):
            print("Connection failed. Retrying in 5 seconds...")
            time.sleep(5)

def select_server():
    # Display the server selection menu
    print("Welcome to the client program!")
    print("Please select the server:")
    print("1. Localhost")
    print("2. Custom server")
    option = input("Enter option: ")

    # Select the server based on the user's choice
    if option == '1':
        return 'localhost', 8080
    elif option == '2':
        host = input("Enter the server IP: ")
        return host, 8080
    else:
        print("Invalid option.")
        return select_server()

if __name__ == "__main__":
    # Continuously attempt to connect to the server
    server_host = 'localhost'
    server_port = 8080

    # Select the server
    server_host, server_port = select_server()

    client_socket = connect_to_server(server_host, server_port)

    # Send CONNECT message
    connect_message = {'type': 'CONNECT', 'mac' : get_mac_address(), 'ip' : get_ip_address()}
    send_message(client_socket, json.dumps(connect_message))

    # Receive response from server
    data = client_socket.recv(1024).decode('utf-8')
    response = json.loads(data)

    # Check if the connection was successful
    if response['type'] == 'CONNECT' and response['status'] == '1':
        current_signature = response['signature']  # Store the initial signature

        # Start the scanner on client side
        start_scan()

        print("\nWelcome, Any following reports will be popped up and any suspicious activity will be detected and blocked\n")

        # Start the menu
        menu(client_socket)
    else:
        print("Failed to connect to server.")

    client_socket.close()
