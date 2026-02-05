#include "cargs.h"
#include <algorithm> // IWYU pragma: keep
#include <arpa/inet.h>
#include <bitset> // IWYU pragma: keep
#include <chrono> // IWYU pragma: keep
#include <cstdlib>
#include <ctime>
#include <fstream>  // IWYU pragma: keep
#include <iostream> // IWYU pragma: keep
#include <ncurses.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <regex>   // IWYU pragma: keep
#include <sstream> // IWYU pragma: keep
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string> // IWYU pragma: keep
#include <sys/socket.h>
#include <sys/types.h>
#include <thread> // IWYU pragma: keep
#include <unistd.h>
#include <unordered_map> // IWYU pragma: keep
#include <vector>        // IWYU pragma: keep

#define VERSION "1.2.0"

#define RED 1
#define YELLOW 2

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

#define KEY_LC_A 97
#define KEY_LC_C 99
#define KEY_LC_I 105
#define KEY_LC_N 110
#define KEY_LC_Q 113
#define KEY_LC_U 117
#define KEY_LC_S 115

static struct cag_option options[] = {
    {.identifier = 'f',
     .access_letters = "f",
     .access_name = "ignore-file",
     .value_name = "VALUE",
     .description = "Import ignore list from file"},
    {.identifier = 'l',
     .access_letters = "l",
     .access_name = "log-file",
     .value_name = "VALUE",
     .description = "Log to file"},
    {.identifier = 'i',
     .access_letters = "i",
     .access_name = "interface",
     .value_name = "VALUE",
     .description = "The interface to capture on"},
    {.identifier = 'p',
     .access_letters = "p",
     .access_name = "port",
     .value_name = "VALUE",
     .description = "Filter traffic to port"},
    {.identifier = 's',
     .access_letters = "s",
     .access_name = "syn",
     .value_name = NULL,
     .description = "Filter SYN only"},
    {.identifier = 'v',
     .access_letters = "v",
     .access_name = "version",
     .description = "Version"},
    {.identifier = 'h',
     .access_letters = "h",
     .access_name = "help",
     .description = "Shows the command help"}};

typedef std::array<unsigned int, 5> ipv4;
typedef std::pair<ipv4, int> pair;

struct ArrayHasher {
    std::size_t operator()(const ipv4 &a) const {
        std::size_t h = 0;

        for (auto e : a) {
            h ^= std::hash<int>{}(e) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};
