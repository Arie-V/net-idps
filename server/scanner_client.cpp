#include "scanner_client.h"

// Constructor
ScannerClient::ScannerClient() {
    // Initialize socket_fd to -1
    socket_fd = -1;
}

// Destructor
ScannerClient::~ScannerClient() {
    if (socket_fd != -1) {
        close(socket_fd);
    }
    // Join the receive thread
    if (receive_thread.joinable()) {
        receive_thread.join(); // Wait for the thread to finish
    }
}

// Method to connect to the server
void ScannerClient::connectToServer() {
    // Create a socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        // Error creating socket
        std::cerr << "Socket creation failed." << std::endl;
        return;
    }
    
    // Create a sockaddr_in struct for the server
    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_address.sin_addr);

    // Connect to the server
    if (connect(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        // Error connecting to server
        std::cerr << "Connection to server failed." << std::endl;
        close(socket_fd);
        socket_fd = -1; // Reset the socket_fd
        return;
    }

    std::cout << "Connected to server." << std::endl;

    // Send a SCANNER_CONNECT message to the server
    Json::Value connect_msg;
    connect_msg["type"] = "SCANNER_CONNECT"; // Updated message type

    // Convert the JSON to a string and send it
    Json::StreamWriterBuilder writer;
    std::string message = Json::writeString(writer, connect_msg);
    send(socket_fd, message.c_str(), message.size(), 0);
    
    // Wait for the server to send the initial signature
    char buffer[1024] = {0};
    int bytes_received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);

    // Handle the response
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer
        std::string response(buffer);
        
        // Parse the response JSON
        Json::Value jsonResponse;
        Json::CharReaderBuilder reader;
        std::string errors;
        std::istringstream s(response);
        
        // Parse the JSON response
        if (Json::parseFromStream(reader, s, &jsonResponse, &errors)) {
            // Check if the response contains a signature
            if (jsonResponse.isMember("signature")) {
                // Update the current signature
                std::string signature = jsonResponse["signature"].asString();
                updateSignature(signature);
                std::cout << "received signature: " + signature << std::endl;
            }
        }
    }
    
    std::cout << "Starting network scan in a new thread..." << std::endl;
    // Create a thread for the Scanner to start sniffing
    std::thread scanThread([&]() {
        // Capture 'this' and use a lambda to match the callback signature
        scanner.set_attack_callback([this](const std::string& attack_details) {
            this->handle_attack(attack_details);  // Pass 'this' and attack details
        });
        scanner.start_sniffing();
    });
    
    // Detach the thread so it runs independently
    scanThread.detach();
}

void ScannerClient::handle_attack(const std::string& attack_details) {
    std::cout << "Received attack notification in the scanner client: " << attack_details << std::endl;
    
    // Check if the attack details have already been reported
    if (reported_attacks.find(attack_details) == reported_attacks.end()) {
        // If not reported, send the report and add to the set
        sendReportMessage(attack_details);
        reported_attacks.insert(attack_details);
    } else {
        std::cout << "Attack details already reported: " << attack_details << std::endl;
    }
}

void ScannerClient::sendReportMessage(const std::string& attack_type) {
    // Create a report message and send it to the server
    Json::Value report_msg;
    report_msg["type"] = "REPORT";
    report_msg["attack_details"] = attack_type;
    report_msg["signature"] = current_signature;
    
    // Convert the JSON to a string and send it
    Json::StreamWriterBuilder writer;
    std::string message = Json::writeString(writer, report_msg);
    
    // Send the message to the server
    send(this->socket_fd, message.c_str(), message.size(), 0);

    // Wait for the server to send the initial signature
    char buffer[1024] = {0};
    int bytes_received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer
        std::string response(buffer);
        
        // Parse the response JSON
        Json::Value jsonResponse;
        Json::CharReaderBuilder reader;
        std::string errors;
        std::istringstream s(response);

        // Parse the JSON response
        if (Json::parseFromStream(reader, s, &jsonResponse, &errors)) {
            // Check if the response contains a signature
            if (jsonResponse.isMember("signature")) {
                std::string signature = jsonResponse["signature"].asString();
                updateSignature(signature);
                std::cout << "received signature: " + signature << std::endl;
            }
        }
    }
}

void ScannerClient::updateSignature(const std::string& signature) {
    // Update the current signature
    current_signature = signature;
    //std::cout << "Updated signature: " << current_signature << std::endl;
}
