#!/bin/bash
# enable-mglru.sh

echo 'y' | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null

# Check that it was successfully enabled
lru_val=$(cat /sys/kernel/mm/lru_gen/enabled)
[[ "$lru_val" == "0x0007" ]]
