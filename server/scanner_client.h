#ifndef SCANNER_CLIENT_H
#define SCANNER_CLIENT_H

#include <iostream> // For input/output
#include <cstring> // For string manipulation
#include <string> // For string
#include <cstdlib> // For exit
#include <unistd.h> // For close
#include <arpa/inet.h> // For inet_ntoa
#include <jsoncpp/json/json.h> // For JSON parsing
#include <thread> // For threading
#include <mutex> // For mutex
#include "scanner.h" // Include the scanner header file
#include <cstdlib> // For exit 
#include <set> // For set

class ScannerClient {
public:
    ScannerClient(); // Constructor
    ~ScannerClient(); // Destructor
    void connectToServer(); // Method to connect to the server
    void sendReportMessage(const std::string& attack_type); // Method to send a report message to the server
    void startReceivingMessages(); // New method to start the receiver thread
    void updateSignature(const std::string& signature); // Method to update the signature
    void handle_attack(const std::string& attack_details); // Method to handle attack notifications

private:
    Scanner scanner; // A scanner instance for sniffing/detecting packages
    int socket_fd; // Socket file descriptor
    const int PORT = 8080; // Port number
    const char* SERVER_IP = "127.0.0.1"; // Server IP address
    std::string current_signature; // Current signature
    std::thread receive_thread; // Thread for receiving messages
    std::mutex mtx; // Mutex for thread safety
    std::set<std::string> reported_attacks;  // Set to keep track of reported attacks
};

#endif // SCANNER_CLIENT_H
