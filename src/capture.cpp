#include "libkrf.h"
#include <pcap.h>
#include <iostream>
#include <stdexcept>
#include <cstdio> // Include for BUFSIZ
#include <atomic>

extern std::atomic<bool> stop_signal;

namespace libkrf {

const std::string RED = "\033[1;31m";
const std::string GREEN = "\033[1;32m";
const std::string YELLOW = "\033[1;33m";
const std::string BLUE = "\033[1;34m";
const std::string MAGENTA = "\033[1;35m";
const std::string CYAN = "\033[1;36m";
const std::string RESET = "\033[0m";  // Reset to default color

WiFiRFAnalyzer::WiFiRFAnalyzer(const std::string& iface) 
    : interface(iface), pcap_handle(nullptr), is_capturing(false) {}

WiFiRFAnalyzer::~WiFiRFAnalyzer() {
    stop_capture();
}

bool WiFiRFAnalyzer::start_capture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << RED << "❌ Error opening interface: " << errbuf << RESET << std::endl;
        return false;  // Return false on failure
    }

    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (stop_signal) break;  // Stop when signal is set

        if (res == 0) continue;  // Timeout, no packet received

        int rssi = 0;
        int radiotap_len = parse_radiotap_header(packet, header->len, rssi);

        if (radiotap_len > 0) {
            std::cout << GREEN << "✅ Parsed Radiotap Header - Length: " << radiotap_len << RESET << 
                    BLUE  << " | RSSI: " << rssi << " dBm"<< RESET << std::endl;
        }
    }

    pcap_close(handle);
    return true;  // Return true on successful execution
}


void WiFiRFAnalyzer::stop_capture() {
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
    is_capturing = false;
}

std::vector<uint8_t> WiFiRFAnalyzer::capture_packets(int packet_count) {
    std::vector<uint8_t> packets;
    struct pcap_pkthdr* header;
    const u_char* packet;

    for (int i = 0; i < packet_count; ++i) {
        int res = pcap_next_ex(pcap_handle, &header, &packet);
        if (res == 1) {
            packets.insert(packets.end(), packet, packet + header->len);
        } else if (res == 0) {
            std::cerr << RED << "Timeout reached." << RESET << std::endl;
        } else {
            throw std::runtime_error("❌Error capturing packet: " + std::string(pcap_geterr(pcap_handle)));
        }
    }
    return packets;
}

} // namespace libkrf