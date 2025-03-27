#include "scanner.h"
#include "scanner_client.h"

int main() {
    
    ScannerClient scannerClient;
    scannerClient.connectToServer();

    //Scanner scanner;
    //scanner.start_sniffing();

    // Infinite loop so the main function won't end
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
