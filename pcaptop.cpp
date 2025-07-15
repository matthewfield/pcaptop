#include <algorithm>
#include <arpa/inet.h>
#include <format>
#include <iostream>
#include <ncurses.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

typedef std::pair<std::string, int> pair;

#define RED 1

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define ETH_ALEN 6

WINDOW *mainwin;
WINDOW *titlewin;
WINDOW *scrollwin;
WINDOW *topwin;

int highlight = 0;
int key;
char *myip;
bool use_color;
std::unordered_map<std::string, int> ips;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
              const u_char *packet) {

  char ip[15];

  snprintf(ip, 15, "%d.%d.%d.%d", packet[26], packet[27], packet[28],
           packet[29]);

  if (strcmp(ip, myip) == 0)
    return;

  if (ips.find(ip) == ips.end()) {
    ips[ip] = 1;
  } else {
    ips[ip] += 1;
  }

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
  }

  std::vector<pair> vec;

  // copy key-value pairs from the map to the vector
  std::copy(ips.begin(), ips.end(), std::back_inserter<std::vector<pair>>(vec));

  // sort the vector by increasing the order of its pair's second vaLue
  // if the second value is equal, order by the pair's first value
  std::sort(vec.begin(), vec.end(), [](const pair &l, const pair &r) {
    if (l.second != r.second) {
      return l.second > r.second;
    }
    return l.first > r.first;
  });

  wprintw(scrollwin, "%15s (%6i)\n", ip, ips[ip]);
  wrefresh(scrollwin);

  for (int i = 0; i < 10; i++) {

    if (key == 127 && highlight == i) {
      ips[vec[i].first] = 0;
      key = 0;
    }

    if (vec[i].second < 1) {
      break;
    }

    if (i == highlight) {
      wattron(topwin, A_REVERSE);
    }

    if (use_color && vec[i].second > 1000) {
      wattron(topwin, COLOR_PAIR(RED));
      wrefresh(topwin);
    }
    mvwprintw(topwin, i + 1, 2, "%15s (%6i)", vec[i].first.c_str(),
              vec[i].second);

    if (use_color && vec[i].second > 1000) {
      wattroff(topwin, COLOR_PAIR(RED));
    }
    wattroff(topwin, A_REVERSE);

    wrefresh(topwin);
  }
}

int main(int argc, char *argv[]) {
  pcap_t *handle;                /* Session handle */
  char *dev = NULL;              /* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  struct bpf_program fp;         /* The compiled filter */
  char filter_exp[10] = "port "; /* The filter expression */
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

  initscr();
  use_color = has_colors() ? TRUE : FALSE;

  if (use_color) {
    start_color();
    init_pair(RED, COLOR_RED, COLOR_BLACK);
  }

  noecho();
  cbreak();
  timeout(100);
  keypad(stdscr, TRUE);
  curs_set(0);

  int height, width;

  getmaxyx(stdscr, height, width);
  refresh();
  titlewin = newwin(3, 64, 1, 1);
  box(titlewin, 0, 0);
  mainwin = newwin(height - 4, 32, 4, 1);
  box(mainwin, 0, 0);
  scrollwin = newwin(height - 6, 29, 5, 3);
  topwin = newwin(height - 4, 32, 4, 33);
  box(topwin, 0, 0);
  wrefresh(mainwin);
  wrefresh(topwin);

  scrollok(scrollwin, TRUE);

  mvwprintw(titlewin, 1, 13, "Latest");
  mvwprintw(titlewin, 1, 45, "Top");
  wrefresh(titlewin);

  // if an interface was specified in argv[1] then iterate until we find it,
  // else list all available interfaces
  if (!argv[1]) {

    for (interface = alldevsp; interface != NULL; interface = interface->next) {
      fprintf(stderr, "Device: %s\n", interface->name);
    }
    return 0;

  } else {

    for (interface = alldevsp; interface != NULL; interface = interface->next) {

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
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
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
    fprintf(stderr, "Listening on %s\n", filter_exp);
  }

  fprintf(stderr, "Listening on %s at %s\n", dev, myip);

  pcap_loop(handle, 0, callback, NULL);

  /* And close the session */
  pcap_close(handle);
  endwin();
  return (0);
}
