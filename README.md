# libkrf

**libkrf** is a powerful wireless network analysis tool designed for extracting radiotap headers, RSSI values, and MAC addresses from live network traffic. It provides advanced packet capture and real-time analysis using `libpcap` .
**IMPORTANT** ist works well in mon mode.
**BY KTMC** 
**PROGRAMMER : N V R K SAI KAMESH YADAVALLI**
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
 https://github.com/Kalasaikamesh944/libkrf.git
 cd libkrf
 sudo apt update
 sudo apt install g++ libpcap-dev
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
Packet Hex Dump (259 bytes):
00 00 26 00 2F 40 00 A0 20 08 00 A0 20 08 00 00 
2E 9A 60 01 00 00 00 00 10 02 99 09 A0 00 A1 00 
00 00 A1 00 A3 01 50 00 24 00 66 68 93 63 25 C1 
5E 5D 18 34 15 28 5E 5D 18 34 15 28 50 59 EF 4D 
2F 1D 02 00 00 00 64 00 11 04 00 11 72 65 61 6C 
6D 65 20 31 31 20 50 72 6F 2B 20 35 47 01 08 82 
84 8B 96 0C 12 18 24 03 01 0A 32 04 30 48 60 6C 
2A 01 04 2D 1A BD 09 03 FF FF 00 00 00 00 00 00 
00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 3D 
16 0A 00 04 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 7F 08 00 00 08 00 00 00 00 
40 DD 18 00 50 F2 02 01 01 80 04 03 A4 00 00 27 
A4 00 00 42 43 5E 00 62 32 2F 00 30 14 01 00 00 
0F AC 04 01 00 00 0F AC 04 01 00 00 0F AC 02 0C 
00 BF 0C 92 01 80 03 FA FF 00 00 FA FF 00 20 C0 
05 00 00 00 02 00 DD 07 00 0C E7 08 00 00 00 35 
69 F3 60 
✅ RSSI: 16 dBm
✅ 📡 BSSID MAC: 5E:5D:18:34:15:28
Decoding Hexdump Data:
Frame Control Field: 50
Type: 0 (Management)
Subtype: 5 (Probe Response)
Captured MAC: 00:A0:20:08:00:00

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

