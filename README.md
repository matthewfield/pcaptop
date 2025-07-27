# pcaptop

## Introduction
An ncurses based terminal command for displaying top inbound connections to a selected network interface using libpcap. Created when i needed a lightweight solution to use over SSH to be able to watch a server for SYN DoS attacks in real time.

Individual IPs, or /24 networks can be ignored

Filtered packet output from the left pane can optionally be sent concurrently to a log file with timestamps.

Keys:
Up/down - select from top list 
I - ignore IP
N - ignore /24
U - undo last ignored
C - clear top list
A - clear ignore list

C++23, Dependencies: pcap, ncurses. Builds on OSX and Linux.

## Installation:

```console
git clone https://github.com/matthewfield/pcaptop
cd pcaptop

```
then with CMake

```console
cmake .
make
```

or gcc
```console

g++ src/pcaptop.cpp src/cargs.c src/cargs.h pcaptop -lncurses -lpcap
```

## Screenshots etc.

![Command line options](screenshots/pcaptop_command.png?raw=true)

Filtering can be by port, or for SYN packets only. SYN packets show up in yellow if terminal supports color, or with a S flag after them if not.

![Unfiltered capture, SYN packets show up in yellow if terminal supports color, else with an S flag after](screenshots/pcaptop_unfiltered_with_syn_packets_in_yellow.png?raw=true)

![Filtered capture, on port 443 displayed at top](screenshots/pcaptop_with_port_filter.png?raw=true)
