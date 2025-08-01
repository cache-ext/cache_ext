#!/bin/bash
# disable-mglru.sh

echo 'n' | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null

# Check that it was successfully disabled
lru_val=$(cat /sys/kernel/mm/lru_gen/enabled)
[[ "$lru_val" == "0x0000" ]]
