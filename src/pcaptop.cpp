#include "cargs.h"
#include <algorithm>
#include <arpa/inet.h>
#include <bitset>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <ncurses.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <regex>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#define VERSION "1.1.0"

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
#define KEY_8 56

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

WINDOW *mainwin;
WINDOW *titlewin;
WINDOW *scrollwin;
WINDOW *topwin;

typedef std::array<unsigned int, 4> ipv4;
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

ipv4 last_ignored;
std::unordered_map<ipv4, int, ArrayHasher> ips;
std::unordered_map<ipv4, int, ArrayHasher> ignored;
std::unordered_map<ipv4, int, ArrayHasher> ignored_import;

int highlight = 0;
int key;
int ignore_list_line;
int ignore_rows;
std::thread::id uiThreadId;
pcap_t *handle; /* pcap session handle */
char *myip;
ipv4 myipv4;
bool use_color;
bool ignored_need_clearing = false;
bool filtering = false;
bool syn_only = false;
bool file_output = false;
std::ofstream logfile;
char *dev = NULL;              /* capture device */
char filter_exp[10] = "port "; /* port filter expression */
char syn_exp[45] =
    "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"; /* SYN filter expression */

void clearTopwin() {
    wclear(topwin);
    box(topwin, 0, 0);
    mvwprintw(topwin, 12, 12, "Ignored");
    wrefresh(topwin);
}

void redrawUI() {
    clear();
    int height, width;
    getmaxyx(stdscr, height, width);
    refresh();
    titlewin = newwin(4, 64, 1, 1);
    box(titlewin, 0, 0);
    mainwin = newwin(height - 6, 32, 5, 1);
    box(mainwin, 0, 0);
    scrollwin = newwin(height - 8, 28, 6, 4);
    topwin = newwin(height - 6, 32, 5, 33);
    ignore_rows = height - 9;
    wrefresh(mainwin);
    clearTopwin();

    scrollok(scrollwin, TRUE);

    mvwprintw(titlewin, 2, 13, "Latest");
    mvwprintw(titlewin, 2, 45, "Top");
    mvwprintw(titlewin, 1, 2, "Listen on %s at %s", dev, myip);
    if (filtering) {
        mvwprintw(titlewin, 1, 35, "Filter: %s", filter_exp);
    }
    if (syn_only) {
        mvwprintw(titlewin, 1, 53, "SYN only");
    }
    wrefresh(titlewin);
}

void writeNewPacket(ipv4 ip, int count, bool syn = false) {
    std::string s = "";
    if (syn) {
        if (use_color) {
            wattron(scrollwin, COLOR_PAIR(YELLOW));
        } else {
            s = "S";
        }
    }
    wprintw(scrollwin, "%3d.%3d.%3d.%3d  (%7i) %s\n", ip[0], ip[1], ip[2],
            ip[3], count, s.c_str());
    wattroff(scrollwin, COLOR_PAIR(YELLOW));
    if (file_output) {
        std::time_t t = std::time(nullptr);
        std::string timestamp = std::asctime(std::localtime(&t));
        timestamp.pop_back();
        std::cout << timestamp << " | " << ip[0] << "." << ip[1] << "." << ip[2]
                  << "." << ip[3] << " | " << count << " | " << (syn ? "S" : "")
                  << std::endl;
        std::cout.flush();
    }
}

std::string ipToString(ipv4 ip) {
    std::string ip_str = std::to_string(ip[0]) + "." + std::to_string(ip[1]) +
                         "." + std::to_string(ip[2]) + "." +
                         std::to_string(ip[3]);
    return ip_str;
}

ipv4 ipFromString(std::string ip) {
    std::vector<unsigned int> octets;
    std::stringstream ss(ip);
    while (ss.good()) {
        std::string octet;
        getline(ss, octet, '.');
        octets.push_back(std::stoul(octet));
    }
    ipv4 network = {octets[0], octets[1], octets[2], octets[3]};
    return network;
}

bool ipIsIgnored(ipv4 ip) {
    ipv4 ipnet24 = {ip[0], ip[1], ip[2], 0};
    ipv4 ipnet8 = {ip[0], ip[1], 0, 0};
    return (ignored.find(ipnet24) != ignored.end() ||
            ignored.find(ipnet8) != ignored.end() ||
            ignored.find(ip) != ignored.end());
}

void resetIgnoredRanges() {
    for (auto &ip : ips) {
        if (ip.second > 0 && ipIsIgnored(ip.first)) {
            ip.second = 0;
        }
    }
    ignored_need_clearing = false;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
              const u_char *packet) {

    bool syn = false;

    ipv4 ip = {packet[26], packet[27], packet[28], packet[29]};

    if (!syn_only) {
        std::bitset<8> flags(packet[47]);
        if (flags[1]) {
            syn = true;
        }
    }

    if (std::equal(std::begin(ip), std::end(ip), std::begin(myipv4))) {
        return;
    }

    if (ignored_need_clearing) {
        resetIgnoredRanges();
    }

    if (ipIsIgnored(ip)) {
        return;
    }

    if (ips.find(ip) == ips.end()) {
        ips[ip] = 1;
    } else {
        ips[ip] += 1;
    }
    writeNewPacket(ip, ips[ip], syn);
}

std::vector<pair>
sortedVector(std::unordered_map<ipv4, int, ArrayHasher> *map) {
    std::vector<pair> vec;

    // copy key-value pairs from the map to the vector
    std::copy(ips.begin(), ips.end(),
              std::back_inserter<std::vector<pair>>(vec));

    // sort the vector by increasing the order of its pair's second vaLue
    // if the second value is equal, order by the pair's first value
    std::sort(vec.begin(), vec.end(), [](const pair &l, const pair &r) {
        if (l.second != r.second) {
            return l.second > r.second;
        }
        return l.first > r.first;
    });
    return vec;
}

int handleKeys() {
    key = getch();
    if (key == KEY_UP) {
        highlight -= 1;
        if (highlight < 0)
            highlight = 0;
    } else if (key == KEY_DOWN) {
        highlight += 1;
        if (highlight > 9)
            highlight = 9;
    } else if (key == KEY_LC_C) {
        ips.clear();
        clearTopwin();
    } else if (key == KEY_LC_A) {
        ignored.clear();
        clearTopwin();
    } else if (key == KEY_LC_U && last_ignored[0] > 0) {
        ignored.erase(ignored.find(last_ignored));
        last_ignored = {};
        clearTopwin();
    } else if (key == KEY_LC_Q) {
        pcap_breakloop(handle);
        return 0;
    } else if (key == KEY_RESIZE) {
        endwin();
        redrawUI();
    }
    return 1;
}

void updateUI() {

    while (true) {

        if (!handleKeys())
            break;

        if (ips.size() > 0) {

            std::vector<pair> vec = sortedVector(&ips);

            if (highlight > vec.size() - 1) {
                highlight = (int)vec.size() - 1;
            }

            wrefresh(scrollwin);

            int i = 0;

            for (int line = 1; line < 11; line++) {
                mvwprintw(topwin, line, 3, "%27s", " ");

                if (i > vec.size() - 1) {
                    i++;
                    continue;
                }
                if (vec[i].second < 1 || ipIsIgnored(vec[i].first)) {
                    i++;
                    line--;
                    continue;
                }

                if ((key == KEY_LC_I || key == KEY_LC_N || key == KEY_8) &&
                    highlight == i) {
                    if (key == KEY_LC_I) {
                        ignored[vec[i].first] = vec[i].second;
                        last_ignored = vec[i].first;
                    } else if (key == KEY_LC_N) {
                        ipv4 range = {vec[i].first[0], vec[i].first[1],
                                      vec[i].first[2], 0};
                        ignored[range] = 0;
                        last_ignored = range;
                    } else if (key == KEY_8) {
                        ipv4 range = {vec[i].first[0], vec[i].first[1], 0, 0};
                        ignored[range] = 0;
                        last_ignored = range;
                    }
                    ignored_need_clearing = true;
                    highlight--;
                    if (highlight < 0)
                        highlight = 0;
                    key = 0;
                }

                if (i == highlight) {
                    wattron(topwin, A_REVERSE);
                }

                if (use_color && vec[i].second > 1000) {
                    wattron(topwin, COLOR_PAIR(RED));
                }

                mvwprintw(topwin, line, 3, "%3d.%3d.%3d.%3d  (%7d)",
                          vec[i].first[0], vec[i].first[1], vec[i].first[2],
                          vec[i].first[3], vec[i].second);

                wattroff(topwin, COLOR_PAIR(RED));
                wattroff(topwin, A_REVERSE);
                wrefresh(topwin);
                i++;
            }
        }

        // output ignore list
        ignore_list_line = 13;
        for (auto &ig : ignored) {
            if (ig.first[2] == 0 && ig.first[3] == 0) {
                mvwprintw(topwin, ignore_list_line, 3, "%3d.%3d.%3d.%3d /8  ",
                          ig.first[0], ig.first[1], ig.first[2], ig.first[3]);
            } else if (ig.first[3] == 0) {
                mvwprintw(topwin, ignore_list_line, 3, "%3d.%3d.%3d.%3d /24  ",
                          ig.first[0], ig.first[1], ig.first[2], ig.first[3]);
            } else {
                mvwprintw(topwin, ignore_list_line, 3, "%3d.%3d.%3d.%3d      ",
                          ig.first[0], ig.first[1], ig.first[2], ig.first[3]);
            }
            if (last_ignored == ig.first) {
                mvwprintw(topwin, ignore_list_line, 23, "u");
            }
            ignore_list_line++;
            if (ignore_list_line > ignore_rows - 1) {
                mvwprintw(topwin, ignore_list_line, 8, "+%d more",
                          ignored.size() + 13 - ignore_list_line);
                break;
            }
        }
        wrefresh(topwin);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;         /* The compiled filter */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */
    struct pcap_pkthdr header;     /* The header that pcap gives us */

    /* Define the device */
    // dev = pcap_lookupdev(errbuf);
    pcap_if_t *alldevsp;
    pcap_if_t *interface;
    struct pcap_addr *address;
    struct sockaddr_in *ipaddress;

    pcap_findalldevs(&alldevsp, errbuf);

    const char *requested_interface = NULL;
    const char *requested_port = NULL;
    const char *requested_ignorefile = NULL;
    const char *requested_logfile = NULL;

    cag_option_context context;
    cag_option_init(&context, options, CAG_ARRAY_SIZE(options), argc, argv);
    while (cag_option_fetch(&context)) {
        switch (cag_option_get_identifier(&context)) {
        case 'f':
            requested_ignorefile = cag_option_get_value(&context);
            if (!requested_ignorefile) {
                printf("No ignore filename specified\n");
                return EXIT_SUCCESS;
            } else {
                std::ifstream ignoreFile(requested_ignorefile);
                if (ignoreFile.fail()) {
                    printf("Ignore file not found\n");
                    return EXIT_SUCCESS;
                }
                std::string line;
                std::regex re(
                    "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25["
                    "0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/([1-9]{1,2})$");
                std::smatch m;
                while (getline(ignoreFile, line)) {
                    if (!std::regex_match(line, m, re)) {
                        continue;
                    }
                    int bits = stoi(m[2].str());
                    ipv4 ignoreip = ipFromString(m[1].str());
                    if (bits == 32 || bits == 24 || bits == 8) {
                        ignored[ignoreip] = 1;
                    } else {
                        ignored_import[ignoreip] = bits;
                    }
                    auto it = ignored_import.begin();
                }
                printf("%lu IP imported\n", ignored_import.size());
                ignoreFile.close();
            }
            break;
        case 'l':
            requested_logfile = cag_option_get_value(&context);
            if (!requested_logfile) {
                printf("No log filename specified\n");
                return EXIT_SUCCESS;
            } else {
                logfile.open(requested_logfile);
                std::streambuf *cout_buf = std::cout.rdbuf();
                std::streambuf *logfile_buf = logfile.rdbuf();
                std::cout.rdbuf(logfile_buf);
                file_output = true;
                break;
            }
        case 'i':
            requested_interface = cag_option_get_value(&context);
            break;
        case 'p':
            requested_port = cag_option_get_value(&context);
            break;
        case 's':
            syn_only = true;
            break;
        case 'h':
            printf("Usage: pcaptop [OPTION]...\n");
            cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
            return EXIT_SUCCESS;
        case 'v':
            printf("v%s\n", VERSION);
            return EXIT_SUCCESS;
        }
    }
    // if an interface was specified in argv[1] then iterate until we find
    // it, else list all available interfaces
    if (!requested_interface) {

        for (interface = alldevsp; interface != NULL;
             interface = interface->next) {
            fprintf(stderr, "Device: %s\n", interface->name);
        }
        return 0;

    } else {

        for (interface = alldevsp; interface != NULL;
             interface = interface->next) {

            if (strcmp(interface->name, requested_interface) == 0) {
                dev = interface->name;
                fprintf(stderr, "Device found: %s\n", dev);
                for (address = interface->addresses; address != NULL;
                     address = address->next) {
                    ipaddress = (struct sockaddr_in *)address->addr;
                    myip = inet_ntoa(ipaddress->sin_addr);
                    myipv4 = ipFromString(myip);
                }

                break;
            }
        }
    }

    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev,
                errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }

    // if a port was specified in argv[2] then create a filter for it
    if (requested_port) {
        filtering = true;
        strcpy(filter_exp, (char *)strcat(filter_exp, requested_port));

        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
                    pcap_geterr(handle));
            return (2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
                    pcap_geterr(handle));
            return (2);
        }
    }
    if (syn_only) {
        if (pcap_compile(handle, &fp, syn_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", syn_exp,
                    pcap_geterr(handle));
            return (2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", syn_exp,
                    pcap_geterr(handle));
            return (2);
        }
    }

    initscr();
    use_color = has_colors() ? TRUE : FALSE;

    if (use_color) {
        start_color();
        init_pair(RED, COLOR_RED, COLOR_BLACK);
        init_pair(YELLOW, COLOR_YELLOW, COLOR_BLACK);
    }

    noecho();
    cbreak();
    timeout(50);
    keypad(stdscr, TRUE);
    curs_set(0);

    redrawUI();

    std::thread t_updateUI(updateUI);
    uiThreadId = t_updateUI.get_id();

    pcap_set_timeout(handle, 1000);
    pcap_set_immediate_mode(handle, 1);

    // start the capture loop
    pcap_loop(handle, 0, callback, NULL);

    // stopCapture();
    endwin();
    if (file_output) {
        logfile.close();
    }
    t_updateUI.join();

    pcap_close(handle);

    /* And close the session */
    return (0);
}
