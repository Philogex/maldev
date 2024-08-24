#!/bin/bash

# Define the build directory for pass
PROJECT_DIR="lib/passes/build"
# Clear Directory
echo "Cleaning up the build directory for passes..."
rm -r "$PROJECT_DIR"/*
echo "Build directory cleared."

# Define the build directory for project
PASS_DIR="build"
# Clear Directory
echo "Cleaning up the build directory for project..."
rm -r "$PASS_DIR"/*
echo "Build directory cleared."

# Define the output directory for project
OUT_DIR="out"
# Clear Directory
echo "Cleaning up the output directory for project..."
rm -r "$OUT_DIR"/*
echo "Output directory cleared."