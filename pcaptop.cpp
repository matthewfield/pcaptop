#include <algorithm>
#include <arpa/inet.h>
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

typedef std::pair<std::string, int> pair;

#define RED 1

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define ETH_ALEN 6
#define KEY_BS 127
#define KEY_LC_C 99
#define KEY_LC_I 105
#define KEY_LC_R 114
#define KEY_LC_U 117

WINDOW *mainwin;
WINDOW *titlewin;
WINDOW *scrollwin;
WINDOW *topwin;

int highlight = 0;
int key;
int c;
char *myip;
bool use_color;
bool filtering = false;
char *dev = NULL;              /* The device to sniff on */
char filter_exp[10] = "port "; /* The filter expression */
std::string last_ignored;
std::unordered_map<std::string, int> ips;
std::unordered_map<std::string, int> ignored;
std::unordered_map<std::string, int> new_ignore;

void get_network(char *ip, char *network, int bits = 24) {
    std::vector<std::string> v;
    std::stringstream ss(ip);
    while (ss.good()) {
        std::string substr;
        getline(ss, substr, '.');
        v.push_back(substr);
    }
    if (bits == 24) {
        snprintf(network, 12, "%s.%s.%s", v[0].c_str(), v[1].c_str(),
                 v[2].c_str());

    } else if (bits == 16) {
        snprintf(network, 7, "%s.%s", v[0].c_str(), v[1].c_str());
    }
}

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
    mvwprintw(titlewin, 1, 2, "Listening on %s at %s", dev, myip);
    if (filtering) {
        mvwprintw(titlewin, 1, 40, "Filtering on %s", filter_exp);
    }
    wrefresh(titlewin);
}

void writeNewPacket(std::string ip, int count) {
    wprintw(scrollwin, "%15s (%6i)\n", ip.c_str(), count);
    // wrefresh(scrollwin);
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
              const u_char *packet) {

    char ip[15];
    char network[12];

    snprintf(ip, 15, "%d.%d.%d.%d", packet[26], packet[27], packet[28],
             packet[29]);

    get_network(ip, network, 24);

    if (strcmp(ip, myip) == 0)
        return;

    if (ignored.find(ip) == ignored.end() &&
        ignored.find(network) == ignored.end()) {

        if (ips.find(ip) == ips.end()) {
            ips[ip] = 1;
        } else {
            ips[ip] += 1;
        }
        writeNewPacket(ip, ips[ip]);
    }
}

std::vector<pair> sortedVector(std::unordered_map<std::string, int> *map) {
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

void updateUI() {
    while (true) {
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
        } else if (key == KEY_LC_U && last_ignored != "") {
            ignored.erase(ignored.find(last_ignored));
            last_ignored = "";
            clearTopwin();
        } else if (key == KEY_RESIZE) {
            endwin();
            redrawUI();
        }

        if (ips.size() > 0) {

            std::vector<pair> vec = sortedVector(&ips);

            // clear any from top that are now covered by net blocks
            for (const pair &v : vec) {
                char clearrange[12];
                char iptoclear[15];
                snprintf(iptoclear, 15, "%s", v.first.c_str());
                get_network(iptoclear, clearrange, 24);
                if (ignored.find(clearrange) != ignored.end()) {
                    vec.erase(find(vec.begin(), vec.end(), v));
                    // new_ignore[iptoclear] = 0;
                    ips[iptoclear] = 0;
                }
            }

            if (highlight > vec.size() - 1) {
                highlight = vec.size() - 1;
            }

            wrefresh(scrollwin);

            // loop through the top 10 and display/handle ignore keypresses
            for (int i = 0; i < 10; i++) {

                if ((key == KEY_BS || key == KEY_LC_R) && highlight == i) {
                    if (key == KEY_BS) {
                        ignored[vec[i].first] = vec[i].second;
                        ips[vec[i].first] = 0;
                        last_ignored = vec[i].first;
                    } else if (key == KEY_LC_R) {
                        char range[12];
                        char rip[15];
                        snprintf(rip, 15, "%s", vec[i].first.c_str());
                        get_network(rip, range, 24);
                        ignored[range] = 0;
                        last_ignored = range;
                    }
                    highlight--;
                    if (highlight < 0)
                        highlight = 0;
                    key = 0;
                }

                // if we are past the top vector length then continue to line 10
                // with blank to overwrite
                if (i > vec.size() - 1 || vec[i].second < 1) {
                    for (int j = i; j < 10; j++) {
                        mvwprintw(topwin, j + 1, 3, "%28s", " ");
                    }
                    wrefresh(topwin);
                    break;
                }

                if (i == highlight) {
                    wattron(topwin, A_REVERSE);
                }

                if (use_color && vec[i].second > 1000) {
                    wattron(topwin, COLOR_PAIR(RED));
                }

                mvwprintw(topwin, i + 1, 3, "%15s (%6i)", vec[i].first.c_str(),
                          vec[i].second);

                wattroff(topwin, COLOR_PAIR(RED));
                wattroff(topwin, A_REVERSE);
            }
        }

        c = 13;

        // output ignore list
        for (auto &ig : ignored) {
            mvwprintw(topwin, c, 3, "%15s (%6i)", ig.first.c_str(), ig.second);
            c++;
        }
        wrefresh(topwin);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
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

    // if an interface was specified in argv[1] then iterate until we find it,
    // else list all available interfaces
    if (!argv[1]) {

        for (interface = alldevsp; interface != NULL;
             interface = interface->next) {
            fprintf(stderr, "Device: %s\n", interface->name);
        }
        return 0;

    } else {

        for (interface = alldevsp; interface != NULL;
             interface = interface->next) {

            if (strcmp(interface->name, argv[1]) == 0) {
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
    if (argv[2]) {
        filtering = true;
        strcpy(filter_exp, (char *)strcat(filter_exp, argv[2]));

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

    initscr();
    use_color = has_colors() ? TRUE : FALSE;

    if (use_color) {
        start_color();
        init_pair(RED, COLOR_RED, COLOR_BLACK);
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
