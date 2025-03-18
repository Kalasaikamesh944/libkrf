# libkrf

**libkrf** is a powerful wireless network analysis tool designed for extracting radiotap headers, RSSI values, and MAC addresses from live network traffic. It provides advanced packet capture and real-time analysis using `libpcap`.

## Features

- 📡 **Radiotap Header Parsing** – Extracts detailed metadata from 802.11 packets.
- 📶 **Signal Strength Detection** – Captures RSSI values from WiFi frames.
- 🕵️ **MAC Address Extraction** – Identifies and displays source and destination MAC addresses.
- 🛠 **Full Packet Hex Dump** – Prints raw packet data for debugging and deep analysis.
- ⚡ **Efficient & Lightweight** – Built using C++ and optimized for performance.

---

## Installation

### 📥 Clone the Repository
```sh
 git clone https://github.com/yourusername/libkrf.git
 cd libkrf
```

### 🔧 Build the Project
Ensure you have CMake and necessary dependencies installed:

```sh
./build.sh
```

Alternatively, manually build with:
```sh
mkdir build && cd build
cmake ..
make
```

### ✅ Run Basic Capture Example
```sh
./build/basic_capture wlan0mon
```

---

## Usage

### 📡 Start Wireless Packet Capture
To capture packets and analyze signal strength:
```sh
./build/basic_capture <interface>
```
Example:
```sh
./build/basic_capture wlan0mon
```

### 🛠 Options & Functionality
- **Full Hex Dump** of packets printed to terminal.
- **Extracts MAC Addresses** from captured frames.
- **Displays RSSI Signal Strength** from packets containing valid radiotap headers.

---

## Example Output
```sh
Packet Hex Dump (42 bytes):
00 00 18 00 2E 48 00 00 10 02 6C 09 A0 20 08 00  
5A 01 00 00 FF FF FF FF FF FF 90 E6 BA 85 3D 6F  
B0 72 BF 5A 80 42 00 00

✅ RSSI: -42 dBm
📡 Source MAC: 90:E6:BA:85:3D:6F
📡 Destination MAC: FF:FF:FF:FF:FF:FF
```

---

## Requirements
- Linux (Tested on Kali Linux)
- `libpcap` (Install via `sudo apt install libpcap-dev`)
- C++17 or higher

---

## Contributing
Feel free to fork and submit PRs to improve functionality.

---

## License
This project is licensed under the MIT License.

