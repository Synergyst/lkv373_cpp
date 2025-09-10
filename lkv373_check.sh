#!/bin/bash

(timeout 0.5 ./lkv373_sniffer --mkv=0 --debug=1 ; exit 0) | ffprobe -hide_banner -i pipe:0
