#include "libkrf.h"
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <net/if.h> // Add this line for if_nametoindex
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <thread>

namespace libkrf {

const std::string RED = "\033[1;31m";
const std::string GREEN = "\033[1;32m";
const std::string YELLOW = "\033[1;33m";
const std::string BLUE = "\033[1;34m";
const std::string MAGENTA = "\033[1;35m";
const std::string CYAN = "\033[1;36m";
const std::string RESET = "\033[0m";  // Reset to default color


void WiFiRFAnalyzer::set_monitor_mode() {
    struct nl_sock* socket = nl_socket_alloc();
    if (!socket) {
        throw std::runtime_error("❌Failed to allocate netlink socket.");
    }

    if (genl_connect(socket)) {
        nl_socket_free(socket);
        throw std::runtime_error("❌Failed to connect to netlink.");
    }

    int driver_id = genl_ctrl_resolve(socket, "nl80211");
    if (driver_id < 0) {
        nl_socket_free(socket);
        throw std::runtime_error("❌nl80211 not found.");
    }

    // Create a message to set monitor mode
    struct nl_msg* msg = nlmsg_alloc();
    if (!msg) {
        nl_socket_free(socket);
        throw std::runtime_error("❌Failed to allocate netlink message.");
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, driver_id, 0, 0, NL80211_CMD_SET_INTERFACE, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(interface.c_str()));
    nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    if (nl_send_auto(socket, msg) < 0) {
        nlmsg_free(msg);
        nl_socket_free(socket);
        throw std::runtime_error("❌Failed to send netlink message.");
    }

    nlmsg_free(msg);
    nl_socket_free(socket);
    std::cout << "Monitor mode set for interface " << interface << std::endl;
}

void WiFiRFAnalyzer::channel_hop() {
    int channels[] = {1, 6, 11}; // Common Wi-Fi channels
    while (is_capturing) {
        for (int channel : channels) {
            set_channel(channel);
            std::this_thread::sleep_for(std::chrono::seconds(1)); // Stay on each channel for 1 second
        }
    }
}

void WiFiRFAnalyzer::set_channel(int channel) {
    // Use `iwconfig` or `iw` to set the channel
    std::string command = "iwconfig " + interface + " channel " + std::to_string(channel);
    int result = system(command.c_str());
    if (result != 0) {
        throw std::runtime_error("❌Failed to set channel: " + std::to_string(channel));
    }
    std::cout << "Channel set to " << channel << " on interface " << interface << std::endl;
}

} // namespace libkrf
