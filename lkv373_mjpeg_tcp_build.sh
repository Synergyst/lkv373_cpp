#!/bin/bash

#nano lkv373_sniffer.cpp
g++ -std=c++17 -O2 -Wall -Wextra -pthread -o /usr/local/bin/lkv373_mjpeg_tcp lkv373_mjpeg_tcp.cpp -lpcap -ljpeg
