#include "scanner.h"

// Public DNS servers for checking DNS spoofing + set running flag to false
Scanner::Scanner() : public_dns_servers({
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "8.26.56.26", "8.20.247.20", "209.244.0.3", "209.244.0.4",
    "64.6.64.6", "64.6.65.6", "84.200.69.80", "84.200.70.40",
    "185.228.168.168", "185.228.168.10", "77.88.8.8", "77.88.8.88"
}), running(false) {}

void Scanner::set_attack_callback(AttackCallback cb) {
    attack_callback = cb;
}

void Scanner::check_for_attacks() {
    while (running) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            check_syn_flood();
            check_icmp_flood();
        }        
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

// Function to get the trusted DHCP server using `nmcli`
std::string Scanner::get_current_dhcp_server() {
    const char *command = "nmcli -f DHCP4.OPTION device show wlan0 | grep 'dhcp_server_identifier' | awk -F' = ' '{print $2}'";
    char buffer[128];
    std::string result;

    // Open a pipe to execute the command
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        std::cerr << "Failed to run command\n";
        return "";
    }

    // Read the command output
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    pclose(pipe);

    // Remove newline characters
    result.erase(result.find_last_not_of("\n\r") + 1);
    return result;
}

// Function to detect DHCP spoofing
void Scanner::check_dhcp_spoofing(const std::string& dhcp_server_ip, const std::string& srcIp) {
    // Retrieve the trusted DHCP server
    std::string trusted_dhcp_server = get_current_dhcp_server();

    // Compare the packet's DHCP server with the trusted server
    if (dhcp_server_ip != trusted_dhcp_server) {
        std::cout << ("DHCP spoofing detected from IP: " + srcIp + ", Spoofed DHCP Server: " + dhcp_server_ip) << std::endl;

        std::string alert = "DHCP_SPOOF," + srcIp;
        std::cout << alert << std::endl;
        if (attack_callback) {
            attack_callback(alert);  // Notify scanner_client
        }
    }
}


// This function detects incoming SYN requests for different ports, if the requests check for a suspicious amount of ports within a small amount of time, send an alert
void Scanner::check_port_scan(const std::string &srcIp) {
    auto now = std::chrono::steady_clock::now();
    auto &tracker = this->port_scanTracker[srcIp];

    // Remove outdated entries
    if (std::chrono::duration_cast<std::chrono::seconds>(now - tracker.firstSeen).count() > PORT_SCAN_TIME_WINDOW) {
        tracker.ports.clear();
        tracker.firstSeen = now;
    }

    if (tracker.ports.size() >= PORT_SCAN_THRESHOLD) {
        std::cout << "ALERT: Potential Port Scan Detected from IP: " << srcIp << "\n";

        std::string alert = "PORT_SCAN," + srcIp;
        std::cout << alert << std::endl;
        if (attack_callback) {
            attack_callback(alert);  // Notify scanner_client
        }

        tracker.ports.clear(); // Reset tracking after detection
    }
}

// This function will go over each ICMP packet and check for the destination IP, if there are too many of them aimed at a certain user, send an alert
void Scanner::check_smurf_attack(const std::string &srcIp, const std::string &dstIp) {
    // Check if destination is a broadcast address
    if (dstIp == BROADCAST_IP) {
        auto now = std::chrono::steady_clock::now();
        static auto lastCheck = now;

        // Increment ICMP request count for the source IP
        smurf_icmpTracker[srcIp]++;

        // Periodically check for Smurf attack
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastCheck).count() > SMURF_TIME_WINDOW) {
            lastCheck = now;

            for (const auto &[ip, count] : smurf_icmpTracker) {
                if (count > SMURF_THRESHOLD) {
                    std::cout << "Possible Smurf Attack Detected from Source IP: " << ip << "\n";

                    std::string alert = "SMURF_ATTACK," + ip;
                    std::cout << alert << std::endl;
                    
                    if (attack_callback) {
                        attack_callback(alert);  // Notify scanner_client
                    }
                }
            }
            // Reset the tracker
            smurf_icmpTracker.clear();
        }
    }
}

// This function checks for ICMP echo requests and notifies the user whenever there's a suspected ICMP ping flood
void Scanner::check_icmp_flood() {
    // Go over all of the IP's and their counts
    for (auto& [ip, count] : icmp_counts) {
        // If the IP appears more than the threshold, alert the user
        if (count > ICMP_THRESHOLD) {
            std::cout << "\nALERT: ICMP flood detected from " << ip << " with " << count << " ICMP Echo Requests!\n";
            std::string alert = "ICMP_FLOOD," + ip;
            std::cout << alert << std::endl;
            if (attack_callback) {
                attack_callback(alert);  // Notify scanner_client
            }
            icmp_counts[ip] = 0;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// This function checks ICMP redirect by comparing given IP to trusted IP (Our router)
void Scanner::check_icmp_redirect(const u_char* packet, const struct ip* ip_hdr, const struct icmphdr* icmp_hdr){
    if (icmp_hdr->type == 5) { // ICMP Redirect Message
        std::string src_ip = inet_ntoa(ip_hdr->ip_src); // Source IP of the packet
        std::string gateway_ip = inet_ntoa(*(struct in_addr*)((u_char*)icmp_hdr + 8)); // New gateway IP in the redirect message

        if (!this->is_trusted_router(src_ip)) {
            std::cerr << "[ALERT] Untrusted source IP in ICMP Redirect: " << src_ip << "\n";
            std::string alert = "ICMP_REDIRECT," + src_ip + "," + gateway_ip;
            if (attack_callback) {
                attack_callback(alert); // Notify the scanner client
            }
        }
    }
}

// Compares given IP to our router's IP
bool Scanner::is_trusted_router(const std::string& ip){
    return trusted_routers.find(ip) != trusted_routers.end();
}

// This function checks for a syn flood whenever a SYN message is received
void Scanner::check_syn_flood() {
    // Go over all of the IP's and their counts
    for (auto& [ip, count] : syn_counts) {
        // If the IP appears more than 100 times, alert the user
        if (count > SYN_THRESHOLD) {
            std::cout << "\nALERT: SYN flood detected from " << ip << " with " << count << " SYN packets!\n";
            std::string alert = "SYN_FLOOD," + ip;
            std::cout << alert << std::endl;
            if (attack_callback) {
                attack_callback(alert);  // Notify scanner_client
            }
            syn_counts[ip] = 0;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// Function to convert MAC address to a human-readable string
std::string mac_to_string(const u_char* mac) {
    std::stringstream ss;
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        if (i != 0) {
            ss << ":";
        }
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    return ss.str();
}

// This function updates the ARP table whenever an ARP message is captured
void Scanner::update_arp_table(const struct ether_header* eth_hdr, const struct ether_arp* arp_hdr) {
    // Get source IP of the received ARP message and convert it to a string
    std::string src_ip = inet_ntoa(*(struct in_addr*)&arp_hdr->arp_spa); // Access the sender protocol address (IP) through the ARP header
    
    // Get the MAC address and convert it to a human-readable string
    std::string src_mac = mac_to_string(arp_hdr->arp_sha); // Access the sender hardware address (MAC) through the ARP header

    // Only proceed if the IP is not 0.0.0.0
    if (src_ip != "0.0.0.0") {
        // Locks mutex for secure info storing inside the ARP table
        std::lock_guard<std::mutex> lock(mtx);
        arp_table[src_mac].insert(src_ip);

        // If more than one IP has the same MAC, alert the user
        if (arp_table[src_mac].size() > 1) {
            std::cout << "\nALERT: ARP Spoofing detected, MAC address " << src_mac << " has multiple IPs: ";
            for (const auto& ip : arp_table[src_mac]) {
                std::cout << ip << " ";
            }
            std::cout << "\n";

            std::string alert = "ARP_SPOOF," + src_mac;
            std::cout << alert << std::endl;
            if (attack_callback) {
                attack_callback(alert);  // Notify scanner_client
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

std::unordered_set<std::string> Scanner::query_dns_servers(const std::string& domain_name) {
    // Initialize DNS query variables
    std::unordered_set<std::string> ips;
    ldns_resolver *resolver;
    ldns_rdf *domain;
    ldns_pkt *packet;
    ldns_rr_list *rr_list;
    ldns_rr *rr;
    ldns_status status;

    status = ldns_resolver_new_frm_file(&resolver, NULL);
    if (status != LDNS_STATUS_OK) {
        std::cerr << "Failed to create resolver\n";
        return ips;
    }

    domain = ldns_dname_new_frm_str(domain_name.c_str());
    if (!domain) {
        std::cerr << "Failed to create domain\n";
        ldns_resolver_deep_free(resolver);
        return ips;
    }

    packet = ldns_resolver_query(resolver, domain, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    if (!packet) {
        std::cerr << "Failed to query DNS\n";
        ldns_rdf_deep_free(domain);
        ldns_resolver_deep_free(resolver);
        return ips;
    }

    rr_list = ldns_pkt_rr_list_by_type(packet, LDNS_RR_TYPE_A, LDNS_SECTION_ANSWER);
    if (!rr_list) {
        std::cerr << "No A records found\n";
        ldns_pkt_free(packet);
        ldns_rdf_deep_free(domain);
        ldns_resolver_deep_free(resolver);
        return ips;
    }

    for (size_t i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
        rr = ldns_rr_list_rr(rr_list, i);
        ldns_rdf *rdata = ldns_rr_rdf(rr, 0);
        char *ip = ldns_rdf2str(rdata);
        ips.insert(std::string(ip));
        free(ip);
    }

    ldns_rr_list_deep_free(rr_list);
    ldns_pkt_free(packet);
    ldns_rdf_deep_free(domain);
    ldns_resolver_deep_free(resolver);

    // Return a list of IP's from the DNS servers
    return ips;
}

// This function checks for DNS spoofing by querying an existing DNS server and comparing both responses when a DNS packet is captured
void Scanner::check_dns_spoofing(const u_char* packet, struct ip* ip_hdr, struct udphdr* udp_hdr, struct dnshdr* dns_hdr) {
    if (ntohs(dns_hdr->flags) & 0x8000) {  // Check for DNS response
        std::string domain_name;
        std::unordered_set<std::string> ips;
        // Calculate the pointer to a specific location insde the packet
        const unsigned char* ptr = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr);

        // Parse the DNS packet using the 'ldns' library
        ldns_pkt* dns_pkt;
        // This function parses the raw DNS packet into a manageable structure for later use
        ldns_status status = ldns_wire2pkt(&dns_pkt, ptr, sizeof(dnshdr));

        if (status != LDNS_STATUS_OK) {
            return;
        }

        ldns_rr_list* answer_list = ldns_pkt_answer(dns_pkt);
        for (size_t i = 0; i < ldns_rr_list_rr_count(answer_list); ++i) {
            ldns_rr* rr = ldns_rr_list_rr(answer_list, i);
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
                ldns_rdf* rdata = ldns_rr_rdf(rr, 0);
                char* ip = ldns_rdf2str(rdata);
                ips.insert(std::string(ip));
                free(ip);
            }
        }

        if (domain_name.empty() || ips.empty()) {
            ldns_pkt_free(dns_pkt);
            return;
        }

        std::unordered_set<std::string> expected_ips = query_dns_servers(domain_name);
        if (expected_ips.empty()) {
            ldns_pkt_free(dns_pkt);
            return;
        }

        bool spoofed = true;
        for (const auto& ip : ips) {
            if (expected_ips.find(ip) != expected_ips.end()) {
                spoofed = false;
                break;
            }
        }

        if (spoofed) {
            std::cout << "\nALERT: Potential DNS spoofing detected for " << domain_name << "\n";
            std::string alert = "DNS_SPOOF";
            std::cout << alert << std::endl;
            if (attack_callback) {
                attack_callback(alert);  // Notify scanner_client
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        ldns_pkt_free(dns_pkt);
    }
}

std::string get_interface_mac(const std::string& interface = "wlan0") {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(sockfd);
        throw std::runtime_error("Failed to get MAC address");
    }

    close(sockfd);

    unsigned char* mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return std::string(mac_str);
}

std::string get_interface_ip(const std::string& interface = "wlan0") {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        close(sockfd);
        throw std::runtime_error("Failed to get IP address");
    }

    close(sockfd);

    struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    return std::string(inet_ntoa(ipaddr->sin_addr));
}

void Scanner::check_for_ip_mac_spoofing(const u_char* packet, const struct ip* ip_hdr, const struct ether_header* eth_hdr, 
                              const std::string& original_ip, const std::string& original_mac) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);

    // Convert source MAC address to string
    char src_mac[18];
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
             eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

    // Check for IP spoofing (our MAC, but different IP)
    if (original_mac == src_mac && original_ip != src_ip) {
        std::cout << "\n[!] IP Spoofing Detected! Source MAC: " << src_mac << ", Spoofed IP: " << src_ip << std::endl;
        
        std::string alert = "IP_SPOOF," + original_ip;
        std::cout << alert << std::endl;
        if (attack_callback) {
            attack_callback(alert);  // Notify scanner_client
        }
        // TODO: Add logic to disconnect or take action against this client
    }

    // Check for MAC spoofing (our IP, but different MAC)
    if (original_ip == src_ip && original_mac != src_mac) {
        std::cout << "\n[!] MAC Spoofing Detected! Source IP: " << src_ip << ", Spoofed MAC: " << src_mac << std::endl;

        std::string alert = "MAC_SPOOF," + original_mac;
        std::cout << alert << std::endl;
        if (attack_callback) {
            attack_callback(alert);  // Notify scanner_client
        }

        // TODO: Add logic to disconnect or take action against this client
    }
}

// This function handles each packet by filtering the source/destination IP by constructing specific headers and filtering the packet by its type
void Scanner::handle_packet(const u_char* packet, const struct pcap_pkthdr* header) {
    // Ensure the packet is large enough for an Ethernet header
    if (header->len < sizeof(struct ether_header)) {
        return; // Packet too small
    }
    
    // Extract the Ethernet header from the packet
    struct ether_header* eth_hdr = (struct ether_header*)packet;

    // Check if the packet is an IP packet
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        // Extract the IP header from the packet
        struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
        
        // Declare buffers to store the source and destination IP addresses as strings
        char srcIp[INET_ADDRSTRLEN];
        char dstIp[INET_ADDRSTRLEN];

        // Convert the source and destination IP addresses from binary to text
        inet_ntop(AF_INET, &(ip_hdr->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dstIp, INET_ADDRSTRLEN);

        // Retrieve the interface's IP and MAC addresses (with inetfaces to verify)
        std::string original_ip = get_interface_ip(this->device_interface);
        std::string original_mac = get_interface_mac(this->device_interface);

        // Perform spoofing detection
        check_for_ip_mac_spoofing(packet, ip_hdr, eth_hdr, original_ip, original_mac);

        // Check if the packet is a TCP packet
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            // Ensure the packet is large enough for a TCP header
            size_t tcp_offset = sizeof(struct ether_header) + (ip_hdr->ip_hl * 4);
            if (header->len < tcp_offset + sizeof(struct tcphdr)) {
                return; // Packet too small for TCP header
            }

            // Extract the TCP header from the packet
            struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + tcp_offset);

            // Check if the SYN flag is set
            if (tcp_hdr->th_flags & TH_SYN) {
                syn_counts[srcIp]++; // Increment SYN packet count for the source IP
            }

            // Check if it's a SYN packet without ACK
            if ((tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK)) {
                uint16_t dstPort = ntohs(tcp_hdr->th_dport);

                // Track ports for the source IP
                auto &tracker = this->port_scanTracker[srcIp];
                tracker.ports.insert(dstPort);
                if (tracker.ports.size() == 1) {
                    tracker.firstSeen = std::chrono::steady_clock::now(); // Record the first occurrence
                }

                // Check for potential port scanning
                check_port_scan(srcIp);
            }

        // Check if the packet is an ICMP packet
        } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
            // Ensure the packet is large enough for an ICMP header
            if (header->len < sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct icmphdr)) {
                return; // Packet too small for ICMP header
            }

            // Extract the ICMP header from the packet
            struct icmphdr* icmp_hdr = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            // Check if the ICMP type is 8 (Echo request)
            if (icmp_hdr->type == ICMP_ECHO) {
                check_smurf_attack(srcIp, dstIp); // Checks for smurf attacks
                icmp_counts[srcIp]++; // Increments the counter for ICMP ping flood
            }

            // Check if the ICMP type is 5 (Redirect)
            check_icmp_redirect(packet, ip_hdr, icmp_hdr);

        // Check if the packet is a UDP packet
        } else if (ip_hdr->ip_p == IPPROTO_UDP) {
            // Ensure the packet is large enough for a UDP header
            if (header->len < sizeof(struct ether_header) + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr)) {
                return; // Packet too small for UDP header
            }

            // Extract the UDP header from the packet
            struct udphdr* udp_hdr = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            // Extract the DNS header from the packet
            struct dnshdr* dns_hdr = (struct dnshdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

            // Check for potential DNS spoofing attacks
            check_dns_spoofing(packet, ip_hdr, udp_hdr, dns_hdr);
            
            size_t udp_offset = sizeof(struct ether_header) + (ip_hdr->ip_hl * 4);
            if (header->len < udp_offset + sizeof(struct udphdr)) return;

            uint16_t srcPort = ntohs(udp_hdr->uh_sport);
            uint16_t dstPort = ntohs(udp_hdr->uh_dport);

            // Check if the packet is a DHCP packet (ports 67 or 68)
            if ((srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67)) {
                size_t dhcp_offset = udp_offset + sizeof(struct udphdr);
                if (header->len < dhcp_offset + sizeof(struct dhcphdr)) return;

                struct dhcphdr* dhcp_hdr = (struct dhcphdr*)(packet + dhcp_offset);

                // Extract DHCP server identifier from options
                const uint8_t* options = (uint8_t*)(packet + dhcp_offset + sizeof(struct dhcphdr));
                uint32_t dhcp_server_identifier = 0;

                // Search for the DHCP Server Identifier option (option code 54)
                for (size_t i = 0; i < header->len - dhcp_offset - sizeof(struct dhcphdr);) {
                    uint8_t option_code = options[i];
                    if (option_code == 54) {
                        // Option 54 found, extract the server identifier (4 bytes)
                        memcpy(&dhcp_server_identifier, &options[i + 2], 4);
                        break;
                    }
                    i += 2 + options[i + 1]; // Move to the next option
                }

                // Convert the server identifier to a human-readable IP
                char server_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &dhcp_server_identifier, server_ip, INET_ADDRSTRLEN);

                // Check for DHCP spoofing
                check_dhcp_spoofing(server_ip, srcIp);
            }

        }

    // Check if the packet is an ARP packet
    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        // Ensure the packet is large enough for an ARP header
        if (header->len < sizeof(struct ether_header) + sizeof(struct ether_arp)) {
            return; // Packet too small for ARP header
        }

        // Extract the ARP header from the packet 
        struct ether_arp* arp_hdr = (struct ether_arp*)(packet + sizeof(struct ether_header));

        // Update the ARP table with the source MAC and IP addresses
        update_arp_table(eth_hdr, arp_hdr);
        
    }
}

void Scanner::start_sniffing() {
    running = true; // Set running flag to true
    
    auto packet_sniffer = [this]() {
        char errbuf[PCAP_ERRBUF_SIZE];
        
        // Promiscuous mode is enabled by passing 1 as the third argument of pcap_open_live()
        pcap_t* handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf); // Third argument is '1' for promiscuous mode
        if (handle == nullptr) {
            std::cerr << "Could not open device: " << errbuf << std::endl;
            return;
        }

        const u_char* packet;
        struct pcap_pkthdr header;

        // Sniff packets in an infinite loop
        while (running) {
            packet = pcap_next(handle, &header);
            if (packet == nullptr) continue;

            // Print the packet using pcap's print function
            //std::cout << "Captured Packet..." << std::endl;
            //pcap_dump((u_char*)stdout, &header, packet); // Print the packet to stdout

            // Process the packet
            handle_packet(packet, &header);
        }

        pcap_close(handle);
    };

    // Start the packet sniffer thread
    std::thread sniffer_thread(packet_sniffer);
    sniffer_thread.detach();

    // Start the attack check thread
    std::thread attack_checker(&Scanner::check_for_attacks, this);
    attack_checker.detach();
}

// Function to stop sniffing by setting the running flag to false
void Scanner::stop_sniffing() {
    running = false;
    std::cout << "Sniffing stopped.\n";
}