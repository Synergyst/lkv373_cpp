#!/bin/bash

#nano kvm_agent_test.cpp
g++ -std=c++17 -O2 -pthread kvm_agent_test.cpp -o kvm-agent-test -ljpeg && ./kvm-agent-test --bind 0.0.0.0 --video-port 1347 --fps 5 --quality 23 --remote-w 1280 --remote-h 720 --w 1280 --h 720
