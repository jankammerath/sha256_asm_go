#!/bin/bash

# Build script for SHA-256 ARM64 assembly program on macOS

echo "Building SHA-256 assembly program..."

# Assemble the source file
as -arch arm64 -o main.o main.asm

if [ $? -ne 0 ]; then
    echo "Assembly failed!"
    exit 1
fi

# Create output directory
mkdir -p bin

# Link with system libraries
ld -arch arm64 -o bin/sha256_asm main.o -lSystem -syslibroot `xcrun --show-sdk-path`

if [ $? -ne 0 ]; then
    echo "Linking failed!"
    exit 1
fi

echo "Build successful! Executable: sha256_asm"
echo ""
echo "Usage: ./sha256_asm <string_to_hash>"
echo ""
echo "Example:"
echo "./sha256_asm 'hello world'"
