/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  httpry.c 4/29/2005

  Copyright (c) 2005, Jason Bittel <jasonbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

#define _BSD_SOURCE 1 /* Needed for Linux/BSD compatibility */
#define TO_MS 0
#define MAX_TIME_LEN 20
#define RUN_DIR "/"
#define PID_FILE "/var/run/httpry.pid"
#define NULL_FILE "/dev/null"
#define DEFAULT_CAPFILTER "tcp dst port 80"
#define DELIM "\r\n"
#define SPACE_CHAR '\x20'
#define GET_REQUEST "GET "
#define HEAD_REQUEST "HEAD "
#define PID_LEN 10
#define PROG_NAME "httpry"
#define PROG_VER "0.0.6"

#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <pcap.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "httpry.h"

/* Macros for logging/displaying status messages */
#define info(x...) fprintf(stderr, x)
#define warn(x...) fprintf(stderr, "Warning: " x)
#define log(x...) { openlog(PROG_NAME, LOG_PID, LOG_DAEMON); syslog(LOG_ERR, x); closelog(); }
#define die(x...) { fprintf(stderr, "Error: " x); exit(EXIT_FAILURE); }

void get_dev_info(char **dev, bpf_u_int32 *net, char *interface);
pcap_t* open_dev(char *dev, int promisc, char *fname);
void set_filter(pcap_t *pcap_hnd, char *cap_filter, bpf_u_int32 net);
void change_user(char *new_user);
void get_packets(pcap_t *pcap_hnd, int pkt_count);
void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
void runas_daemon(char *run_dir);
void handle_signal(int sig);
void cleanup_exit();
void display_usage();

/* Gather information about local network device */
void get_dev_info(char **dev, bpf_u_int32 *net, char *interface) {
        char errbuf[PCAP_ERRBUF_SIZE]; // Pcap error string
        bpf_u_int32 mask;              // Network mask

        if (interface == NULL) {
                // Search for network device
                *dev = pcap_lookupdev(errbuf);
                if (dev == NULL) {
                        log("Cannot find capture device: %s\n", errbuf);
                        die("Cannot find capture device: %s\n", errbuf);
                }
        } else {
                // Use network interface from user parameter
                *dev = interface;
        }

        // Retrieve network information
        if (pcap_lookupnet(*dev, net, &mask, errbuf) == -1) {
                log("Cannot find network info: %s\n", errbuf);
                die("Cannot find network info: %s\n", errbuf);
        }

        return;
}

/* Open selected device for capturing */
pcap_t* open_dev(char *dev, int promisc, char *fname) {
        char errbuf[PCAP_ERRBUF_SIZE]; // Pcap error string
        pcap_t *pcap_hnd;              // Opened pcap device handle

        if (fname) {
                // Open saved capture file
                pcap_hnd = pcap_open_offline(fname, errbuf);
                if (pcap_hnd == NULL) {
                        log("Cannot open capture file '%s': %s\n", fname, errbuf);
                        die("Cannot open capture file '%s': %s\n", fname, errbuf);
                }
        } else {
                // Open live capture
                pcap_hnd = pcap_open_live(dev, BUFSIZ, promisc, TO_MS, errbuf);
                if (pcap_hnd == NULL) {
                        log("Invalid device '%s': %s\n", dev, errbuf);
                        die("Invalid device '%s': %s\n", dev, errbuf);
                }
        }

        return pcap_hnd;
}

/* Compile and set pcap filter on device handle */
void set_filter(pcap_t *pcap_hnd, char *cap_filter, bpf_u_int32 net) {
        struct bpf_program filter; // Compiled capture filter

        // Compile filter string
        if (pcap_compile(pcap_hnd, &filter, cap_filter, 0, net) == -1) {
                log("Bad capture filter syntax in '%s'\n", cap_filter);
                die("Bad capture filter syntax in '%s'\n", cap_filter);
        }

        // Apply compiled filter to pcap handle
        if (pcap_setfilter(pcap_hnd, &filter) == -1) {
                log("Cannot compile capture filter\n");
                die("Cannot compile capture filter\n");
        }

        // Clean up compiled filter
        pcap_freecode(&filter);

        return;
}

/* Change process owner to requested username */
void change_user(char *new_user) {
        struct passwd* user;

        // Make sure we have correct priviledges
        if (geteuid() > 0) {
                die("You must be root to switch users\n");
        }

        // Test for user existence in the system
        if (!(user = getpwnam(new_user))) {
                die("User '%s' not found in system\n", new_user);
        }

        // Set group information, GID and UID
        if (initgroups(user->pw_name, user->pw_gid)) {
                die("Cannot initialize the group access list\n");
        }
        if (setgid(user->pw_gid)) {
                die("Cannot set GID\n");
        }
        if (setuid(user->pw_uid)) {
                die("Cannot set UID\n");
        }

        // Test to see if we actually made it
        if ((getegid() != user->pw_gid) || (geteuid() != user->pw_uid)) {
                die("Cannot change process owner to '%s'\n", new_user);
        }

        return;
}

/* Begin packet capture/processing session */
void get_packets(pcap_t *pcap_hnd, int pkt_count) {
        if (pcap_loop(pcap_hnd, pkt_count, process_pkt, NULL) < 0) {
                log("Cannot read packets from interface\n");
                die("Cannot read packets from interface\n");
        }

        pcap_close(pcap_hnd);

        return;
}

/* Process each packet that passes the capture filter */
void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
        char saddr[INET_ADDRSTRLEN];
        char daddr[INET_ADDRSTRLEN];
        char ts[MAX_TIME_LEN]; // Pcap packet timestamp
        struct tm *pkt_time;
        char *data;            // Editable copy of packet data
        struct http_hdr http;  // HTTP request header fields
        char *req_header;      // Request header line

        const struct pkt_eth *eth; // These structs define the layout of the packet
        const struct pkt_ip *ip;
        const struct pkt_tcp *tcp;
        const char *payload;

        int size_eth = sizeof(struct pkt_eth); // Calculate size of packet components
        int size_ip = sizeof(struct pkt_ip);
        int size_data;

        // Position pointers within packet stream
        eth = (struct pkt_eth *)(pkt);
        ip = (struct pkt_ip *)(pkt + size_eth);
        tcp = (struct pkt_tcp *)(pkt + size_eth + size_ip);
        payload = (u_char *)(pkt + size_eth + size_ip + (tcp->th_off * 4));
        size_data = (header->caplen - (size_eth + size_ip + (tcp->th_off * 4)));

        if (size_data == 0) // Bail early if no data to parse
                return;

        // Copy packet payload to editable buffer
        if ((data = malloc(size_data + 1)) == NULL) {
                fprintf(stderr, "Cannot allocate memory for packet data\n");
                exit(EXIT_FAILURE);
        }
        memset(data, '\0', size_data + 1);
        strncpy(data, payload, size_data);

        // Parse request line
        if ((http.method = strtok(data, DELIM)) == NULL) {
                free(data);
                return;
        }

        if (strncmp(http.method, GET_REQUEST, 4) != 0 &&
            strncmp(http.method, HEAD_REQUEST, 5) != 0) {
                free(data);
                return;
        }

        // Parse URI field in request string
        if ((http.uri = strchr(http.method, SPACE_CHAR)) == NULL) {
                free(data);
                return;
        }
        *http.uri++ = '\0';

        // Parse version field in request string
        if ((http.version = strchr(http.uri, SPACE_CHAR)) == NULL) {
                free(data);
                return;
        }
        *http.version++ = '\0';

        // Iterate through HTTP request header lines
        http.hostname = NULL;
        while ((req_header = strtok(NULL, DELIM)) != NULL) {
                if (strncmp(req_header, "Host: ", 6) == 0) {
                        http.hostname = req_header + 6;
                }
        }

        if (http.hostname == NULL) { // No hostname found
                http.hostname = "-";
        }

        // Grab source/destination IP addresses
        strncpy(saddr, (char *) inet_ntoa(ip->ip_src), INET_ADDRSTRLEN);
        strncpy(daddr, (char *) inet_ntoa(ip->ip_dst), INET_ADDRSTRLEN);

        // Extract packet capture time
        pkt_time = localtime((time_t *) &header->ts.tv_sec);
        strftime(ts, MAX_TIME_LEN, "%m/%d/%Y %H:%M:%S", pkt_time);

        // Print data to stdout/output file
        printf("%s\t%s\t%s\t%s\t%s\n", ts, saddr, daddr, http.hostname, http.uri);

        free(data);

        return;
}

/* Run program as a daemon process */
void runas_daemon(char *run_dir) {
        int child_pid;
        int pid_file;
        char pid[PID_LEN];

        if (getppid() == 1) return; // We're already a daemon

        fflush(NULL);

        child_pid = fork();
        if (child_pid < 0) { // Error forking child
                log("Cannot fork child process\n");
                die("Cannot fork child process\n");
        }
        if (child_pid > 0) exit(0); // Parent bows out

        // Configure default output streams
        dup2(1,2);
        close(0);
        if (freopen(NULL_FILE, "a", stderr) == NULL) {
                log("Cannot open output stream to '%s'\n", optarg);
                die("Cannot open output stream to '%s'\n", optarg);
        }

        // Assign new process group for child
        if (setsid() == -1) {
                log("Cannot assign new session for child process\n");
                warn("Cannot assign new session for child process\n");
        }

        umask(0); // Reset file creation mask
        if (chdir(run_dir) == -1) {
                log("Cannot change run directory to '%s', defaulting to '%s'\n", run_dir, RUN_DIR);
                warn("Cannot change run directory to '%s', defaulting to '%s'\n", run_dir, RUN_DIR);
                chdir(RUN_DIR);
        }

        // Open/create pid file
        pid_file = open(PID_FILE, O_RDWR|O_CREAT, 0640);
        if (pid_file < 0) {
                log("Cannot open PID file '%s'\n", PID_FILE);
                warn("Cannot open PID file '%s'\n", PID_FILE);
        }
        if (lockf(pid_file, F_TLOCK, 0) < 0) {
                log("Cannot lock PID file '%s'\n", PID_FILE);
                warn("Cannot lock PID file '%s'\n", PID_FILE);
        }

        // Write pid into file
        snprintf(pid, PID_LEN, "%d\n", getpid());
        write(pid_file, pid, strlen(pid));
        close(pid_file);

        // Configure daemon signal handling
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
        signal(SIGTTIN, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        signal(SIGTERM, handle_signal);

        fflush(NULL);

        return;
}

/* Handle a limited set of signals when in daemon mode */
void handle_signal(int sig) {
        switch (sig) {
                case SIGINT:
                        info("Caught SIGINT, cleaning up...\n");
                        cleanup_exit();
                        exit(EXIT_SUCCESS);
                        break;
                case SIGTERM:
                        info("Caught SIGTERM, cleaning up...\n");
                        cleanup_exit();
                        exit(EXIT_SUCCESS);
                        break;
        }

        return;
}

/* Clean up/flush opened filehandles on exit */
void cleanup_exit() {
        fflush(NULL);

        // If daemon, we need this gone
        remove(PID_FILE);

        return;
}

/* Display help/usage information */
void display_usage() {
        warn("\n%s version %s\n"
             "Usage: %s [-dhp] [-c count] [-f file] [-i interface]\n"
             "        [-l filter] [-o file] [-r dir ] [-u user]\n", PROG_NAME, PROG_VER, PROG_NAME);

        exit(EXIT_SUCCESS);
}

/* Main, duh */
int main(int argc, char *argv[]) {
        char *dev = NULL;
        bpf_u_int32 net;
        pcap_t *pcap_hnd; // Opened pcap device handle

        // Command line flags/options
        int arg;
        int pkt_count    = -1; // Loop forever unless overridden
        int daemon_mode  = 0;
        char *use_infile = NULL;
        char *interface  = NULL;
        char *capfilter  = NULL;
        int use_outfile  = 0;
        int set_promisc  = 1; // Default to promiscuous mode for the NIC
        char *new_user   = NULL;
        char *run_dir    = NULL;

        // Process command line arguments
        while ((arg = getopt(argc, argv, "c:df:hi:l:o:pr:u:")) != -1) {
                switch (arg) {
                        case 'c': pkt_count = atoi(optarg); break;
                        case 'd': daemon_mode = 1; break;
                        case 'f': use_infile = optarg; break;
                        case 'h': display_usage(); break;
                        case 'i': interface = optarg; break;
                        case 'l': capfilter = optarg; break;
                        case 'o': if (freopen(optarg, "a", stdout) == NULL) {
                                          log("Cannot reopen output stream to '%s'\n", optarg);
                                          die("Cannot reopen output stream to '%s'\n", optarg);
                                  }
                                  use_outfile = 1; break;
                        case 'p': set_promisc = 0; break;
                        case 'r': run_dir = optarg; break;
                        case 'u': new_user = optarg; break;

                        case '?': if (isprint(optopt)) {
                                          warn("Unknown parameter '-%c'\n", optopt);
                                          display_usage();
                                  } else {
                                          warn("Unknown parameter\n");
                                          display_usage();
                                  }
                        default:  display_usage(); // Shouldn't be reached
                }
        }

        // Test for error and warn conditions
        if ((getuid() != 0) && !use_infile) {
                die("Root privs required to access the NIC\n");
        }
        if (daemon_mode && !use_outfile) {
                die("Daemon mode requires an output file\n");
        }
        if (!daemon_mode && run_dir) {
                warn("Run directory is only useful in daemon mode...ignored\n");
        }

        // General program setup
        if (!capfilter) {
                capfilter = DEFAULT_CAPFILTER;
        }
        if (!run_dir) {
                run_dir = RUN_DIR;
        }
        signal(SIGINT, handle_signal);

        // Set up packet capture
        if (!use_infile) {
                get_dev_info(&dev, &net, interface);
        }
        pcap_hnd = open_dev(dev, set_promisc, use_infile);
        set_filter(pcap_hnd, capfilter, net);

        if (daemon_mode) runas_daemon(run_dir);
        if (new_user) change_user(new_user);

        get_packets(pcap_hnd, pkt_count);

        cleanup_exit();

        return EXIT_SUCCESS;
}
