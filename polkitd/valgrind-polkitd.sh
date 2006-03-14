#!/bin/sh

valgrind --num-callers=20 --show-reachable=yes --leak-check=yes --tool=memcheck ./polkitd --no-daemon --verbose

