#ifndef LIBKRF_H
#define LIBKRF_H

#include <string>
#include <vector>
#include <cstdint>
#include <pcap.h>
#include <unordered_map>

namespace libkrf {

struct AccessPoint {
    std::string bssid;
    std::string ssid;
    int channel;
    int rssi;
};

struct Client {
    std::string mac;
    std::string bssid;
    int rssi;
};

class WiFiRFAnalyzer {
public:
    WiFiRFAnalyzer(const std::string& interface);
    ~WiFiRFAnalyzer();

    bool start_capture();
    void stop_capture();
    void set_monitor_mode();
    void set_channel(int channel);
    void channel_hop();
    std::vector<uint8_t> capture_packets(int packet_count);
    int get_signal_strength();
    void scan_networks();
    int parse_radiotap_header(const uint8_t* packet, uint32_t len, int& rssi);
    std::string extract_mac_address(const uint8_t* packet_data);
    void hexDump(const uint8_t* data, size_t len, const std::string& title);
    void detectHttpPasswords(const uint8_t* packet, uint32_t len);
    

private:
    std::string interface;
    pcap_t* pcap_handle;
    bool is_capturing;
    std::unordered_map<std::string, AccessPoint> access_points;
    std::unordered_map<std::string, Client> clients;

    void process_packet(const uint8_t* packet, uint32_t len);
};

} // namespace libkrf

#endif // LIBKRF_H