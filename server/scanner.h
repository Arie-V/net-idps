#ifndef SCANNER_H
#define SCANNER_H

#include <iostream> // For input/output
#include <pcap.h> // For packet capture
#include <unordered_map> // For storing ARP table
#include <unordered_set> // For storing unique ports
#include <cstring> // For string manipulation
#include <netinet/ip.h> // For IP header
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <netinet/if_ether.h> // For Ethernet header
#include <arpa/inet.h> // For inet_ntop
#include <resolv.h> // For DNS query
#include <thread> // For multithreading
#include <chrono> // For time functions
#include <mutex> // For synchronization
#include <vector> // For storing public DNS servers
#include <string> // For string manipulation
#include <ldns/ldns.h> // For DNS parsing
#include <map> // For storing port scan connections
#include <iomanip>  // For std::setw and std::setfill
#include <sstream>  // For std::stringstream
#include <functional> // For callback functions
#include <set> // For storing unique ports
#include <stdexcept> // For exceptions
#include <netinet/in.h> // For sockaddr_in
#include <sys/ioctl.h> // For ioctl
#include <net/if.h> // For ifreq
#include <unistd.h> // For close

#define FC_TYPE_MANAGEMENT 0x00 // Management frame
#define FC_SUBTYPE_BEACON 0x08 // Beacon frame
#define SYN_THRESHOLD 300 // Threshold for SYN flood detection
#define ICMP_THRESHOLD 300 // Threshold for ICMP flood detection
#define SMURF_TIME_WINDOW 10 // Time window for smurf attack detection
#define SMURF_THRESHOLD 50 // Threshold for smurf attack detection
#define BROADCAST_IP "255.255.255.255" // Broadcast IP address
#define PORT_SCAN_THRESHOLD 10 // Threshold for port scan detection
#define PORT_SCAN_TIME_WINDOW 60 // Time window for port scan detection

// DNS header structure
struct dnshdr {
    uint16_t id;       // Identification
    uint16_t flags;    // Flags
    uint16_t qdcount;  // Number of questions
    uint16_t ancount;  // Number of answers
    uint16_t nscount;  // Number of authority records
    uint16_t arcount;  // Number of additional records
};

// DHCP header structure
struct dhcphdr {
    uint8_t op;          // Message type: 1 = request, 2 = reply
    uint8_t htype;       // Hardware address type: 1 = Ethernet
    uint8_t hlen;        // Hardware address length: 6 for Ethernet
    uint8_t hops;        // Number of hops
    uint32_t xid;        // Transaction ID
    uint16_t secs;       // Seconds elapsed since client began address acquisition
    uint16_t flags;      // Flags
    uint32_t ciaddr;     // Client IP address (if already bound)
    uint32_t yiaddr;     // Your IP address (assigned by server)
    uint32_t siaddr;     // Next server IP address
    uint32_t giaddr;     // Relay agent IP address
    uint8_t chaddr[16];  // Client hardware address
    uint8_t sname[64];   // Server host name (optional)
    uint8_t file[128];   // Boot file name (optional)
    uint8_t options[0];  // Options (variable length)
};

// Port scan connection tracker structure
struct ConnectionTracker {
    std::set<uint16_t> ports; // Unique destination ports
    std::chrono::time_point<std::chrono::steady_clock> firstSeen;
};

typedef std::function<void(const std::string&)> AttackCallback; // Callback function for attack detection

class Scanner {
public:
    // Construtor
    Scanner();
    // Set update callback for attack detection
    void set_attack_callback(AttackCallback cb);
    // Sniffer function
    void start_sniffing();
    void stop_sniffing();
    
private:
    bool running; // A flag to stop/start the packet sniffing process

    AttackCallback attack_callback;  // Callback to notify scanner_client
    // Function to check for any malicious activity
    void check_for_attacks();

    // Scanner functions
    std::string get_current_dhcp_server(); // Get the current DHCP server
    void check_dhcp_spoofing(const std::string& dhcp_server_ip, const std::string& srcIp); // Check for DHCP spoofing
    void check_port_scan(const std::string &srcIp); // Check for port scanning
    void check_smurf_attack(const std::string &srcIp, const std::string &dstIp); // Check for smurf attack
    void check_syn_flood(); // Check for SYN flood
    void update_arp_table(const struct ether_header* eth_hdr, const struct ether_arp* arp_hdr); // Update ARP table
    std::unordered_set<std::string> query_dns_servers(const std::string& domain_name); // Query public DNS servers
    void check_dns_spoofing(const u_char* packet, struct ip* ip_hdr, struct udphdr* udp_hdr, struct dnshdr* dns_hdr); // Check for DNS spoofing
    void handle_packet(const u_char* packet, const struct pcap_pkthdr* header); // Handle incoming packets
    void check_evil_twin(); // Check for evil twin attacks
    std::string extract_ssid(const u_char* packet, int len); // Extract SSID from beacon frame
    void check_icmp_flood(); // Check for ICMP flood
    void check_for_ip_mac_spoofing(const u_char* packet, const struct ip* ip_hdr, const struct ether_header* eth_hdr, const std::string& original_ip, const std::string& original_mac); // Check for IP/MAC spoofing
    bool is_trusted_router(const std::string& ip); // Check if the IP address is a trusted router
    void check_icmp_redirect(const u_char* packet, const struct ip* ip_hdr, const struct icmphdr* icmp_hdr); // Check for ICMP redirect

    // Global variables to store relevant info
    std::unordered_set<std::string> dhcp_servers; // Set of DHCP servers
    std::string device_interface = "wlan0"; // Default interface
    std::unordered_map<std::string, ConnectionTracker> port_scanTracker; // Port scan tracker
    std::unordered_map<std::string, int> syn_counts; // SYN packet counter
    std::unordered_map<std::string, std::unordered_set<std::string>> arp_table; // ARP table
    std::mutex mtx; // Mutex for synchronization
    std::vector<std::string> public_dns_servers; // List of public DNS servers
    std::unordered_map<std::string, int> icmp_counts; // ICMP packet counter
    std::unordered_map<std::string, int> smurf_icmpTracker; // Smurf attack tracker
    std::unordered_set<std::string> trusted_routers = {"192.168.1.1", "10.0.0.1"}; // Set of trusted routers
};

#endif // SCANNER_H
