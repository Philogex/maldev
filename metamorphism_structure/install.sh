#!/bin/bash

# Update package list
sudo apt-get update

# Install required packages
sudo apt-get install -y cmake ninja-build clang mingw-w64 g++-mingw-w64-x86-64 lld libzstd-dev libcurl4-openssl-dev libffi-dev libedit-dev pkg-config llvm

# Verify installation
echo "Verifying installations..."
which cmake
which ninja
which clang
which lld