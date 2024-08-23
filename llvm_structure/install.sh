#!/bin/bash

# Update package list
sudo apt-get update

# Install required packages
sudo apt-get install -y cmake ninja-build clang mingw-w64 g++-mingw-w64-x86-64

# Verify installation
echo "Verifying installations..."
which cmake
which ninja
which clang
which x86_64-w64-mingw32-clang
which g++-mingw-w64-x86-64