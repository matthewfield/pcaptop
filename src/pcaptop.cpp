#include "cargs.h"
#include <algorithm>
#include <arpa/inet.h>
#include <bitset>
#include <chrono>
#include <ncurses.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define RED 1
#define YELLOW 2

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define ETH_ALEN 6
#define KEY_BS 127
#define KEY_LC_C 99
#define KEY_LC_I 105
#define KEY_LC_R 114
#define KEY_LC_U 117

static struct cag_option options[] = {
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
    {.identifier = 'h',
     .access_letters = "h?",
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

struct ArrayEquality {
    bool operator()(ipv4 a, ipv4 b) const {
        return std::equal(a.begin(), a.end(), b.begin());
    }
};

ipv4 last_ignored;
std::unordered_map<ipv4, int, ArrayHasher, ArrayEquality> ips;
std::unordered_map<ipv4, int, ArrayHasher, ArrayEquality> ignored;

int highlight = 0;
ipv4 *highlit;
int key;
int c;
char *myip;
bool use_color;
bool ignored_need_clearing = false;
bool filtering = false;
bool syn_only = false;
char *dev = NULL;              /* The device to sniff on */
char filter_exp[10] = "port "; /* The filter expression */
char syn_exp[45] =
    "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"; /* SYN filter expression */

void clearTopwin() {
    wclear(topwin);
    box(topwin, 0, 0);
    mvwprintw(topwin, 12, 12, "Ignored");
    wrefresh(topwin);
}

void redrawUI() {
    refresh();
    int height = 30;
    titlewin = newwin(4, 64, 1, 1);
    box(titlewin, 0, 0);
    mainwin = newwin(height - 5, 32, 5, 1);
    box(mainwin, 0, 0);
    scrollwin = newwin(height - 7, 28, 6, 4);
    topwin = newwin(height - 5, 32, 5, 33);
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
    ipv4 ipnet = {ip[0], ip[1], ip[2], 0};
    return (ignored.find(ipnet) != ignored.end() ||
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

    char ip_str[15];
    char network[12];
    bool syn = false;

    ipv4 ip = {packet[26], packet[27], packet[28], packet[29]};

    snprintf(ip_str, 15, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    if (!syn_only) {
        std::bitset<8> flags(packet[47]);
        if (flags[1]) {
            syn = true;
        }
    }

    if (strcmp(ip_str, myip) == 0)
        return;

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
sortedVector(std::unordered_map<ipv4, int, ArrayHasher, ArrayEquality> *map) {
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

void handleKeys() {
    key = getch();
    // fprintf(stderr, "%d", key);
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
    } else if (key == KEY_LC_I) {
        ignored.clear();
        clearTopwin();
    } else if (key == KEY_LC_U && last_ignored[0] > 0) {
        ignored.erase(ignored.find(last_ignored));
        last_ignored = {};
        clearTopwin();
    } else if (key == KEY_RESIZE) {
        endwin();
        redrawUI();
    }
}

void updateUI() {

    while (true) {

        handleKeys();

        if (ips.size() > 0) {

            std::vector<pair> vec = sortedVector(&ips);

            if (highlight > vec.size() - 1) {
                highlight = vec.size() - 1;
            }

            wrefresh(scrollwin);

            for (int j = 2; j < 12; j++) {
                mvwprintw(topwin, j, 3, "%28s", " ");
            }
            wrefresh(topwin);

            // loop through the top 10 and display/handle ignore keypresses
            for (int i = 0; i < 10; i++) {

                if (ipIsIgnored(vec[i].first)) {
                    continue;
                }

                // if we are past the top vector length then continue to
                // line 10 with blank to overwrite
                if (i > vec.size() - 1 || vec[i].second < 1) {
                    continue;
                }

                if ((key == KEY_BS || key == KEY_LC_R) && highlight == i) {
                    if (key == KEY_BS) {
                        ignored[vec[i].first] = vec[i].second;
                        last_ignored = vec[i].first;
                    } else if (key == KEY_LC_R) {
                        ipv4 range = {vec[i].first[0], vec[i].first[1],
                                      vec[i].first[2], 0};
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

                mvwprintw(topwin, i + 1, 3, "%3d.%3d.%3d.%3d  (%7d)",
                          vec[i].first[0], vec[i].first[1], vec[i].first[2],
                          vec[i].first[3], vec[i].second);

                wattroff(topwin, COLOR_PAIR(RED));
                wattroff(topwin, A_REVERSE);
            }
            wrefresh(topwin);
        }

        // output ignore list
        c = 13;
        for (auto &ig : ignored) {
            if (ig.first[3] == 0) {
                mvwprintw(topwin, c, 3, "%3d.%3d.%3d.%3d /24  ", ig.first[0],
                          ig.first[1], ig.first[2], ig.first[3]);
            } else {
                mvwprintw(topwin, c, 3, "%3d.%3d.%3d.%3d      ", ig.first[0],
                          ig.first[1], ig.first[2], ig.first[3]);
            }
            if (last_ignored == ig.first) {
                mvwprintw(topwin, c, 23, "u");
            }
            c++;
        }
        wrefresh(topwin);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main(int argc, char *argv[]) {
    pcap_t *handle;                /* Session handle */
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

    cag_option_context context;
    cag_option_init(&context, options, CAG_ARRAY_SIZE(options), argc, argv);
    while (cag_option_fetch(&context)) {
        switch (cag_option_get_identifier(&context)) {
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
        case '?':
            cag_option_print_error(&context, stdout);
            break;
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

    // start the capture loop
    pcap_loop(handle, 0, callback, NULL);

    /* And close the session */
    pcap_close(handle);
    endwin();
    t_updateUI.join();
    return (0);
}
