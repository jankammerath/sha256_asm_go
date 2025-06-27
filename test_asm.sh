#!/bin/bash

# Read test.txt file and process each line
line_number=0
while IFS= read -r line; do
    line_number=$((line_number + 1))
    if [ -z "$line" ]; then
        :  # Skip empty lines silently
    else
        ./sha256_asm/bin/sha256_asm "$line" > /dev/null 2>&1
    fi
done < test.txt
