#!/bin/bash

#nano kvm_agent_test.cpp
g++ -std=c++17 -O2 -pthread kvm_agent_test.cpp -o kvm-agent-test -ljpeg
