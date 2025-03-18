#!/bin/bash

# Exit on error
set -e


# Clean the build directory (if it exists)
if [ -d "build" ]; then
    echo "Cleaning build directory..."
    rm -rf build/*
else
    echo "Creating build directory..."
    mkdir -p build
fi

# Navigate to the build directory
cd build

# Configure the project with CMake
echo "Configuring project with CMake..."
cmake ..

# Build the project
echo "Building project..."
make

# Run the example program
echo "Running example program..."
sudo ./evilmon
