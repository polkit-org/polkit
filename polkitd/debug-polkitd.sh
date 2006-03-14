#!/bin/sh

echo ========================================
echo Just type \'run\' to start debugging polkitd
echo ========================================
gdb run --args ./polkitd --no-daemon --verbose



