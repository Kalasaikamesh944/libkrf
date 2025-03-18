#include "libkrf.h"
#include <pcap.h>
#include <iostream>
#include <stdexcept>
#include <cstdio> // Include for BUFSIZ
#include <atomic>

extern std::atomic<bool> stop_signal;

namespace libkrf {

WiFiRFAnalyzer::WiFiRFAnalyzer(const std::string& iface) 
    : interface(iface), pcap_handle(nullptr), is_capturing(false) {}

WiFiRFAnalyzer::~WiFiRFAnalyzer() {
    stop_capture();
}

bool WiFiRFAnalyzer::start_capture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "❌ Error opening interface: " << errbuf << std::endl;
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
            std::cout << "✅ Parsed Radiotap Header - Length: " << radiotap_len
                      << " | RSSI: " << rssi << " dBm" << std::endl;
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
            std::cerr << "Timeout reached." << std::endl;
        } else {
            throw std::runtime_error("❌Error capturing packet: " + std::string(pcap_geterr(pcap_handle)));
        }
    }
    return packets;
}

} // namespace libkrf