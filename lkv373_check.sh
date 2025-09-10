#!/bin/bash

(timeout 0.5 lkv373_sniffer --mkv=0 --debug=0 ; exit 0) | ffprobe -hide_banner -i pipe:0 2>&1 | grep 'Video:' | awk '{ printf "Format: %s%s Resolution: %s, FPS: %d\n", $6, $7, $8, $13 }'
