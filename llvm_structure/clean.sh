#!/bin/bash

# Define the build directory
BUILD_DIR="build"

# Check if the build directory exists
if [ -d "$BUILD_DIR" ]; then
    echo "Cleaning up the build directory..."
    rm -rf "$BUILD_DIR"
    echo "Build directory removed."
else
    echo "Build directory does not exist."
fi