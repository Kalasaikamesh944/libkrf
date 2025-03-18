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


void WiFiRFAnalyzer::hexDump(const uint8_t* data, size_t len, const std::string& title) {
    std::cout << CYAN << "Hex Dump: " << title << " (" << len << " bytes)" << RESET << std::endl;

    for (size_t i = 0; i < len; i += 16) {
        // Print offset
        printf("%04zx: ", i);

        // Print hex values
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   "); // Pad if less than 16 bytes
            }
        }

        // Print ASCII representation
        printf(" ");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char c = data[i + j];
                if (isprint(c)) {
                    printf("%c", c);
                } else {
                    printf("."); // Replace non-printable characters
                }
            } else {
                printf(" "); // Pad if less than 16 bytes
            }
        }

        printf("\n");
    }
}

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

// Add this function to detect HTTP passwords
void WiFiRFAnalyzer::detectHttpPasswords(const uint8_t* packet, uint32_t len) {
    // Check if the packet is large enough to contain HTTP data
    if (len < 54) { // Minimum Ethernet + IP + TCP header size
        return;
    }

    // Extract TCP payload (assuming Ethernet + IPv4 + TCP headers)
    const uint8_t* tcp_payload = packet + 54; // Skip Ethernet (14) + IP (20) + TCP (20) headers
    uint32_t tcp_payload_len = len - 54;

    // Check if the payload contains HTTP data
    if (tcp_payload_len < 7) { // Minimum HTTP header size
        return;
    }

    // Look for HTTP POST or GET requests
    if (std::memcmp(tcp_payload, "POST ", 5) != 0 && std::memcmp(tcp_payload, "GET ", 4) != 0) {
        return;
    }

    // Convert TCP payload to a string for easier searching
    std::string http_payload(reinterpret_cast<const char*>(tcp_payload), tcp_payload_len);

    // Look for common password field names
    std::vector<std::string> password_fields = {"password", "pass", "pwd", "passwd"};
    for (const auto& field : password_fields) {
        size_t pos = http_payload.find(field + "=");
        if (pos != std::string::npos) {
            // Extract the password value
            size_t start = pos + field.length() + 1; // Skip "field="
            size_t end = http_payload.find('&', start); // Find the next parameter delimiter
            if (end == std::string::npos) {
                end = http_payload.length(); // If no delimiter, use the end of the payload
            }

            std::string password_value = http_payload.substr(start, end - start);
            std::cout << RED << "⚠️ Potential Password Detected in HTTP Traffic!" << RESET << std::endl;
            std::cout << "Field: " << field << std::endl;
            std::cout << "Value: " << password_value << std::endl;
            std::cout << MAGENTA << "----------------------------------------------------------------" << RESET << std::endl;
        }
    }
}

// Parse Radiotap Header
int WiFiRFAnalyzer::parse_radiotap_header(const uint8_t* packet, uint32_t len, int& rssi) {
    if (len < 8) {
        std::cerr << RED << "❌ Packet too small for Radiotap header. Length: " << len << RESET  << std::endl;
        return -1;
    }

    std::cout << MAGENTA << "----------------------------------------------------------------" << RESET << std::endl;
    // Print hex dump for testing
    hexDump(packet, len, "Raw Packet Data");

    std::cout << BLUE << "Packet Hex Dump (" << len << " bytes):" << RESET << std::endl;

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

    // Parse Radiotap Header
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
            std::cerr << RED << "❌ Packet too short for RSSI field." << RESET << std::endl;
            return -1;
        }
        rssi = static_cast<int8_t>(*(packet + offset + 8));
        std::cout << GREEN << "✅ RSSI: " << rssi << " dBm" << RESET << std::endl;
    } else {
        std::cerr << RED << "⚠️ RSSI field not found in Radiotap header." << RESET << std::endl;
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

    // Decode the hexdump data
    std::cout << CYAN << "Decoding Hexdump Data:" << RESET << std::endl;
    std::cout << "Frame Control Field: " << std::hex << static_cast<int>(frame_control) << std::dec << std::endl;
    std::cout << "Type: " << static_cast<int>(type) << " (";
    switch (type) {
        case 0: std::cout << "Management"; break;
        case 1: std::cout << "Control"; break;
        case 2: std::cout << "Data"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << ")" << std::endl;

    std::cout << "Subtype: " << static_cast<int>(subtype) << " (";
    switch (type) {
        case 0: // Management Frame Subtypes
            switch (subtype) {
                case 0: std::cout << "Association Request"; break;
                case 1: std::cout << "Association Response"; break;
                case 2: std::cout << "Reassociation Request"; break;
                case 3: std::cout << "Reassociation Response"; break;
                case 4: std::cout << "Probe Request"; break;
                case 5: std::cout << "Probe Response"; break;
                case 8: std::cout << "Beacon"; break;
                case 9: std::cout << "ATIM"; break;
                case 10: std::cout << "Disassociation"; break;
                case 11: std::cout << "Authentication"; break;
                case 12: std::cout << "Deauthentication"; break;
                default: std::cout << "Unknown"; break;
            }
            break;
        case 1: // Control Frame Subtypes
            switch (subtype) {
                case 11: std::cout << "RTS"; break;
                case 12: std::cout << "CTS"; break;
                case 13: std::cout << "ACK"; break;
                case 14: std::cout << "CF-End"; break;
                case 15: std::cout << "CF-End + CF-Ack"; break;
                default: std::cout << "Unknown"; break;
            }
            break;
        case 2: // Data Frame Subtypes
            switch (subtype) {
                case 0: std::cout << "Data"; break;
                case 1: std::cout << "Data + CF-Ack"; break;
                case 2: std::cout << "Data + CF-Poll"; break;
                case 3: std::cout << "Data + CF-Ack + CF-Poll"; break;
                case 4: std::cout << "Null"; break;
                case 5: std::cout << "CF-Ack"; break;
                case 6: std::cout << "CF-Poll"; break;
                case 7: std::cout << "CF-Ack + CF-Poll"; break;
                default: std::cout << "Unknown"; break;
            }
            break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << ")" << std::endl;

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
    
    detectHttpPasswords(packet, len);
}


} // namespace libkrf
