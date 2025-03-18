#include "libkrf.h"
#include <pcap.h>
#include <iostream>
#include <csignal>
#include <cstring>
#include <atomic>

std::atomic<bool> stop_signal(false);

void signal_handler(int signum) {
    stop_signal = true;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }

    const std::string iface = argv[1];  // Interface name
    libkrf::WiFiRFAnalyzer analyzer(iface);  // ✅ Pass interface to constructor

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!handle) {
        std::cerr << "❌ Failed to open interface " << iface << ": " << errbuf << std::endl;
        return 1;
    }

    std::cout << "✅ Capturing packets on " << iface << "..." << std::endl;
    signal(SIGINT, signal_handler); // Handle Ctrl+C

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (!stop_signal) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 1) { // Packet captured
            int rssi;
            analyzer.parse_radiotap_header(packet, header->len, rssi);
            std::string mac_addr = analyzer.extract_mac_address(packet);
            std::cout << "Captured MAC: " << mac_addr << std::endl;
        } else if (res == 0) {
            continue; // Timeout
        } else {
            std::cerr << "❌ Error capturing packet!" << std::endl;
            break;
        }
    }

    pcap_close(handle);
    std::cout << "✅ Capture stopped." << std::endl;
    return 0;
}
