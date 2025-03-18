#include "libkrf.h"
#include <pcap.h>
#include <iostream>
#include <cstring> // For memcpy
#include <atomic>
#include <cstdint>
#include <cstring>

#pragma pack(push, 1)  // Ensure no padding
struct radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};
#pragma pack(pop)  // Restore default alignment

extern std::atomic<bool> stop_signal;

namespace libkrf {

const std::string RED = "\033[1;31m";
const std::string GREEN = "\033[1;32m";
const std::string YELLOW = "\033[1;33m";
const std::string BLUE = "\033[1;34m";
const std::string MAGENTA = "\033[1;35m";
const std::string CYAN = "\033[1;36m";
const std::string RESET = "\033[0m";  // Reset to default color


// Function to print MAC address
void print_mac_address(const char* label, const uint8_t* mac) {
    printf("✅ %s MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

std::string WiFiRFAnalyzer::extract_mac_address(const uint8_t* packet_data) {
    if (!packet_data) return "Invalid Packet";

    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             packet_data[10], packet_data[11], packet_data[12],
             packet_data[13], packet_data[14], packet_data[15]);

    return std::string(mac);
}


// Parse Radiotap Header
int WiFiRFAnalyzer::parse_radiotap_header(const uint8_t* packet, uint32_t len, int& rssi) {
    if (len < 8) {
        std::cerr << RED << "❌ Packet too small for Radiotap header. Length: " << len << RESET  << std::endl;
        return -1;
    }

    std::cout << MAGENTA << "----------------------------------------------------------------" << RESET << std::endl;
    
    std::cout << BLUE << "Packet Hex Dump (" << len << " bytes):"<< RESET << std::endl;

    for (size_t i = 0; i < len; i++) {
       printf("%02X ", packet[i]);

    // Print newline every 16 bytes for better readability
       if ((i + 1) % 16 == 0) {
        printf("\n");
       }
    }

    // Ensure the last line is printed properly
    if (len % 16 != 0) {
       printf("\n");
    }


    struct {
        uint8_t it_version;
        uint8_t it_pad;
        uint16_t it_len;
        uint32_t it_present;
    } __attribute__((packed)) rt_header;

    std::memcpy(&rt_header, packet, sizeof(rt_header));

    uint16_t radiotap_len = le16toh(rt_header.it_len);  
    uint32_t present_flags = le32toh(rt_header.it_present);

    if (radiotap_len > len || radiotap_len < 8 || radiotap_len > 128) {
        std::cerr << RED <<  "❌ Invalid Radiotap header length! Header length: " << radiotap_len 
                  << ", Packet length: " << len << RESET << std::endl;
        return -1;
    }

    uint32_t offset = 8;
    while (present_flags & 0x80000000) {  
        if (offset + 4 > len) {
            std::cerr << RED << "❌ Malformed Radiotap header: `it_present` overflow!" << RESET <<  std::endl;
            return -1;
        }
        std::memcpy(&present_flags, packet + offset, 4);
        present_flags = le32toh(present_flags);
        offset += 4;
    }

    if (present_flags & (1 << 5)) {  
        if (offset + 8 > len) {
            std::cerr << RED << "❌ Packet too short for RSSI field."<< RESET << std::endl;
            return -1;
        }
        rssi = static_cast<int8_t>(*(packet + offset + 8));
        std::cout << GREEN << "✅ RSSI: " << rssi << " dBm" << RESET << std::endl;
    } else {
        std::cerr << RED << "⚠️ RSSI field not found in Radiotap header."<< RESET << std::endl;
        return -1;
    }

    // ✅ Extract MAC Address from IEEE 802.11 header
    uint32_t ieee_offset = radiotap_len;
    if (ieee_offset + 10 > len) {
        std::cerr << RED <<  "❌ Packet too small for IEEE 802.11 header!" << RESET << std::endl;
        return -1;
    }

    uint8_t frame_control = packet[ieee_offset];  // Frame Control Field
    uint8_t type = (frame_control >> 2) & 0x03;  // Extract type (2 bits)
    uint8_t subtype = (frame_control >> 4) & 0x0F;  // Extract subtype (4 bits)

    uint8_t mac_addr[6];
    if (type == 0) {  // Management Frame
        std::memcpy(mac_addr, packet + ieee_offset + 10, 6);  // Extract BSSID
        print_mac_address("📡 BSSID", mac_addr);
    } else if (type == 1) {  // Control Frame (No MAC usually)
        std::cout << BLUE << "⚠️ Control frame detected, skipping MAC extraction.\n" << RESET;
    } else if (type == 2) {  // Data Frame
        std::memcpy(mac_addr, packet + ieee_offset + 4, 6);  // Extract Source MAC
        print_mac_address("📶 Source", mac_addr);
    }

    return radiotap_len;
}

// Capture and Extract Signal Strength
int WiFiRFAnalyzer::get_signal_strength() {
    if (!pcap_handle) {
        throw std::runtime_error("❌Capture not started. Call start_capture() first.");
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    int res = pcap_next_ex(pcap_handle, &header, &packet);
    if (res == 1) {
        int rssi = 0;
        int radiotap_len = parse_radiotap_header(packet, header->len, rssi);
        
        if (radiotap_len > 0) {
            return rssi;
        } else {
            throw std::runtime_error("❌Failed to extract RSSI.");
        }
    } else if (res == 0) {
        throw std::runtime_error("❌Timeout while capturing packet.");
    } else {
        throw std::runtime_error("❌Error capturing packet: " + std::string(pcap_geterr(pcap_handle)));
    }
}

void WiFiRFAnalyzer::scan_networks() {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (is_capturing && !stop_signal) {  // Check stop_signal
        int res = pcap_next_ex(pcap_handle, &header, &packet);
        if (res == 1) {
            process_packet(packet, header->len);
        } else if (res == 0) {
            continue; // Timeout
        } else {
            std::cerr << RED << "❌Error capturing packet: " << pcap_geterr(pcap_handle) << RESET << std::endl;
            break; // Exit on error
        }
    }
}

std::string extract_mac_address(const uint8_t* packet_data) {
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             packet_data[10], packet_data[11], packet_data[12],
             packet_data[13], packet_data[14], packet_data[15]);
    return std::string(mac);
}

void WiFiRFAnalyzer::process_packet(const uint8_t* packet, uint32_t len) {
    if (!packet) {
        std::cerr << RED << "❌Packet pointer is null." << RESET <<std::endl;
        return;
    }

    if (len < sizeof(radiotap_header)) {
        std::cerr << RED <<  "❌Packet too small to contain Radiotap header. Packet length: "<< RESET << len << std::endl;
        return;
    }

    const radiotap_header* rt_header = reinterpret_cast<const radiotap_header*>(packet);

    // Ensure the radiotap header length is valid
    if (rt_header->it_len < sizeof(radiotap_header) || rt_header->it_len > len) {
        std::cerr << RED << "❌ Invalid Radiotap header length! Header length: " << rt_header->it_len
                  << ", Packet length: " << len << RESET << std::endl;          
        return;
    }

    std::cout << "Radiotap header length: " << rt_header->it_len << ", Packet length: " << len << std::endl;
    

}

} // namespace libkrf
