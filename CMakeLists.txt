cmake_minimum_required(VERSION 3.10)
project(libkrf)

set(CMAKE_CXX_STANDARD 17)

# Include directories
include_directories(include /usr/include/libnl3)  # Add /usr/include/libnl3

# Source files
set(SOURCES src/capture.cpp src/monitor.cpp src/analysis.cpp src/utils.cpp)

# Build library
add_library(libkrf SHARED ${SOURCES})

# Link libraries
target_link_libraries(libkrf pcap nl-3 nl-genl-3)

# Build example
add_executable(basic_capture examples/basic_capture.cpp)
target_link_libraries(basic_capture libkrf)
