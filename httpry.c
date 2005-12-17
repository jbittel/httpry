/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  httpry.c 4/29/2005

  Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

#define _BSD_SOURCE 1 /* Needed for Linux/BSD compatibility */
#define TO_MS 0
#define MAX_TIME_LEN 20
#define MAX_CONFIG_LEN 512
#define SPACE_CHAR '\x20'

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
#include "config.h"

/* Macros for logging/displaying status messages */
#define info(x...) fprintf(stderr, x)
#define warn(x...) fprintf(stderr, "Warning: " x)
#define log(x...) { openlog(PROG_NAME, LOG_PID, LOG_DAEMON); syslog(LOG_ERR, x); closelog(); }
#define die(x...) { fprintf(stderr, "Error: " x); cleanup_exit(EXIT_FAILURE); }
#define log_die(x...) { log(x); die(x); }

/* Function declarations */
void parse_config(char *filename);
void get_dev_info(char **dev, bpf_u_int32 *net, char *interface);
pcap_t* open_dev(char *dev, int promisc, char *fname);
void set_filter(pcap_t *pcap_hnd, char *cap_filter, bpf_u_int32 net);
void change_user(char *new_user);
void get_packets(pcap_t *pcap_hnd, int pkt_count);
void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
void runas_daemon(char *run_dir);
void handle_signal(int sig);
char* safe_strdup(char *curr_str);
void cleanup_exit(int exit_value);
void display_version();
void display_help();

/* Program flags/options, set by arguments or config file */
static int  pkt_count    = -1;
static int  daemon_mode  = 0;
static char *use_infile  = NULL;
static char *interface   = NULL;
static char *capfilter   = NULL;
static char *use_outfile = NULL;
static int  set_promisc  = 1;
static char *new_user    = NULL;
static char *run_dir     = NULL;
static char *use_config  = NULL;
static int extended_info = 0;

/* Read options in from config file */
void parse_config(char *filename) {
        FILE *config_file;
        char buf[MAX_CONFIG_LEN];
        char *line;
        char *name;
        char *value;
        int line_count = 0;

        if ((config_file = fopen(filename, "r")) == NULL) {
                log_die("Cannot open config file '%s'\n", filename);
        }

        while ((line = fgets(buf, sizeof(buf), config_file))) {
                line_count++;
                while (isspace(*line)) line++;   // Skip leading spaces
                if (strlen(line) <= 1) continue; // Skip blank lines
                if (*line == '#') continue;      // Skip comments

                // Search for name/value pairs in the format 'Name Value'
                name = line;
                if ((value = strchr(line, SPACE_CHAR)) == NULL) {
                        die("Bad data in config file at line %d\n", line_count);
                }
                *value++ = '\0';

                if ((line = strchr(value, '\n')) == NULL) {
                        die("Bad data in config file at line %d\n", line_count);
                }
                *line = '\0';

                if (!strlen(value)) continue; // Skip empty values

                // Test parsed name/value pairs and set values accordingly
                // Only set if value is default to prevent overwriting arguments
                if (!strcmp(name, "DaemonMode") && !daemon_mode) {
                        daemon_mode = atoi(value);
                } else if (!strcmp(name, "InputFile") && !use_infile) {
                        use_infile = safe_strdup(value);
                } else if (!strcmp(name, "Interface") && !interface) {
                        interface = safe_strdup(value);
                } else if (!strcmp(name, "CaptureFilter") && !capfilter) {
                        capfilter = safe_strdup(value);
                } else if (!strcmp(name, "PacketCount") && (pkt_count == -1)) {
                        pkt_count = atoi(value);
                } else if (!strcmp(name, "OutputFile") && !use_outfile) {
                        use_outfile = safe_strdup(value);
                } else if (!strcmp(name, "PromiscuousMode") && set_promisc) {
                        set_promisc = atoi(value);
                } else if (!strcmp(name, "RunDir") && !run_dir) {
                        run_dir = safe_strdup(value);
                } else if (!strcmp(name, "User") && !new_user) {
                        new_user = safe_strdup(value);
                } else if (!strcmp(name, "ExtendedInfo") && !extended_info) {
                        extended_info = atoi(value);
                } else {
                        warn("Config file option '%s' not recognized...skipping", name);
                        continue;
                }
        }

        fclose(config_file);

        return;
}

/* Gather information about local network device */
void get_dev_info(char **dev, bpf_u_int32 *net, char *interface) {
        char errbuf[PCAP_ERRBUF_SIZE]; // Pcap error string
        bpf_u_int32 mask;              // Network mask

        if (!interface) {
                // Search for network device
                *dev = pcap_lookupdev(errbuf);
                if (dev == NULL) {
                        log_die("Cannot find capture device '%s'\n", errbuf);
                }
        } else {
                // Use network interface from user parameter
                *dev = interface;
        }

        // Retrieve network information
        if (pcap_lookupnet(*dev, net, &mask, errbuf) == -1) {
                log_die("Cannot find network info for '%s': %s\n", *dev, errbuf);
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
                        log_die("Cannot open capture file '%s': %s\n", fname, errbuf);
                }
        } else {
                // Open live capture
                pcap_hnd = pcap_open_live(dev, BUFSIZ, promisc, TO_MS, errbuf);
                if (pcap_hnd == NULL) {
                        log_die("Invalid device '%s': %s\n", dev, errbuf);
                }
        }

        return pcap_hnd;
}

/* Compile and set pcap filter on device handle */
void set_filter(pcap_t *pcap_hnd, char *cap_filter, bpf_u_int32 net) {
        struct bpf_program filter; // Compiled capture filter

        // Compile filter string
        if (pcap_compile(pcap_hnd, &filter, cap_filter, 0, net) == -1) {
                die("Bad capture filter syntax in '%s'\n", cap_filter);
        }

        // Apply compiled filter to pcap handle
        if (pcap_setfilter(pcap_hnd, &filter) == -1) {
                log_die("Cannot compile capture filter\n");
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
                log_die("You must be root to switch users\n");
        }

        // Test for user existence in the system
        if (!(user = getpwnam(new_user))) {
                log_die("User '%s' not found in system\n", new_user);
        }

        // Set group information, GID and UID
        if (initgroups(user->pw_name, user->pw_gid)) {
                log_die("Cannot initialize the group access list\n");
        }
        if (setgid(user->pw_gid)) {
                log_die("Cannot set GID\n");
        }
        if (setuid(user->pw_uid)) {
                log_die("Cannot set UID\n");
        }

        // Test to see if we actually made it to the new user
        if ((getegid() != user->pw_gid) || (geteuid() != user->pw_uid)) {
                log_die("Cannot change process owner to '%s'\n", new_user);
        }

        return;
}

/* Begin packet capture/processing session */
void get_packets(pcap_t *pcap_hnd, int pkt_count) {
        if (pcap_loop(pcap_hnd, pkt_count, process_pkt, NULL) < 0) {
                log_die("Cannot read packets from interface\n");
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

        if (size_data == 0) return; // Bail early if no data to parse

        // Copy packet payload to editable buffer
        if ((data = malloc(size_data + 1)) == NULL) {
                log_die("Cannot allocate memory for packet data\n");
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
                } else if (strncmp(req_header, "Referer: ", 9) == 0) {
                        http.referer = req_header + 9;
                } else if (strncmp(req_header, "User-Agent: ", 12) == 0) {
                        http.user_agent = req_header + 12;
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
        if (!extended_info) {
                printf("%s\t%s\t%s\t%s\t%s\n", ts, saddr, daddr, http.hostname, http.uri);
        } else {
                printf("%s\t%s:%d\t%s:%d\t%s\t%s\t", ts, saddr, ntohs(tcp->th_sport), daddr, ntohs(tcp->th_dport), http.hostname, http.uri);
                printf("%s\t%s\n", http.referer, http.user_agent);
        }

        free(data);

        return;
}

/* Run program as a daemon process */
void runas_daemon(char *run_dir) {
        int child_pid;
        FILE *pid_file;

        if (getppid() == 1) return; // We're already a daemon

        fflush(NULL);

        child_pid = fork();
        if (child_pid < 0) { // Error forking child
                log_die("Cannot fork child process\n");
        }
        if (child_pid > 0) exit(0); // Parent bows out

        // Configure default output streams
        dup2(1,2);
        close(0);
        if (freopen(NULL_FILE, "a", stderr) == NULL) {
                log_die("Cannot open output stream to '%s'\n", optarg);
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
                if (chdir(RUN_DIR) == -1) {
                        log_die("Cannot change run directory to '%s'\n", RUN_DIR);
                }
        }

        // Write PID into file
        if ((pid_file = fopen(PID_FILE, "w")) == NULL) {
                log("Cannot open PID file '%s'\n", PID_FILE);
                warn("Cannot open PID file '%s'\n", PID_FILE);
        } else {
                fprintf(pid_file, "%d\n", getpid());
                fclose(pid_file);
        }

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
                        cleanup_exit(EXIT_SUCCESS);
                        break;
                case SIGTERM:
                        info("Caught SIGTERM, cleaning up...\n");
                        cleanup_exit(EXIT_SUCCESS);
                        break;
        }

        return;
}

/* Centralize error checking for string duplication */
char* safe_strdup(char *curr_str) {
        char *new_str;

        if ((new_str = strdup(curr_str)) == NULL) {
                log_die("Cannot duplicate string '%s'\n", curr_str);
        }

        return new_str;
}

/* Clean up/flush opened filehandles on exit */
void cleanup_exit(int exit_value) {
        fflush(NULL);
        remove(PID_FILE); // If daemon, we need this gone

        exit(exit_value);
}

/* Display program version information */
void display_version() {
        info("%s version %s\n", PROG_NAME, PROG_VER);

        exit(EXIT_SUCCESS);
}

/* Display program help/usage information */
void display_help() {
        info("Usage: %s [-dhpvx] [-c file] [-f file] [-i interface]\n"
             "        [-l filter] [-n count] [-o file] [-r dir ] [-u user]\n", PROG_NAME);
        info("  -c ... specify config file\n"
             "  -d ... run as daemon\n"
             "  -f ... input file to read from\n"
             "  -h ... print help information\n"
             "  -i ... set interface to listen on\n"
             "  -l ... pcap style capture filter\n"
             "  -n ... number of packets to capture\n"
             "  -o ... output file to write into\n"
             "  -p ... disable promiscuous mode\n"
             "  -r ... set running directory\n"
             "  -u ... set process owner\n"
             "  -v ... display version information\n"
             "  -x ... print extended packet information\n");

        exit(EXIT_SUCCESS);
}

/* Main, duh */
int main(int argc, char *argv[]) {
        char *dev = NULL;
        bpf_u_int32 net;
        pcap_t *pcap_hnd; // Opened pcap device handle
        char default_capfilter[] = DEFAULT_CAPFILTER;
        char default_rundir[] = RUN_DIR;
        int arg;

        // Process command line arguments
        while ((arg = getopt(argc, argv, "c:df:hi:l:n:o:pr:u:vx")) != -1) {
                switch (arg) {
                        case 'c': use_config = safe_strdup(optarg); break;
                        case 'd': daemon_mode = 1; break;
                        case 'f': use_infile = safe_strdup(optarg); break;
                        case 'h': display_help(); break;
                        case 'i': interface = safe_strdup(optarg); break;
                        case 'l': capfilter = safe_strdup(optarg); break;
                        case 'n': pkt_count = atoi(optarg); break;
                        case 'o': use_outfile = safe_strdup(optarg); break;
                        case 'p': set_promisc = 0; break;
                        case 'r': run_dir = safe_strdup(optarg); break;
                        case 'u': new_user = safe_strdup(optarg); break;
                        case 'v': display_version(); break;
                        case 'x': extended_info = 1; break;
                        case '?': if (isprint(optopt)) {
                                          warn("Unknown parameter '-%c'\n", optopt);
                                          display_help();
                                  } else {
                                          warn("Unknown parameter\n");
                                          display_help();
                                  }
                        default:  display_help(); // Shouldn't be reached
                }
        }

        if (use_config) parse_config(use_config);

        // Test for error and warn conditions
        if ((getuid() != 0) && !use_infile) {
                die("Root priviledges required to access the NIC\n");
        }
        if (daemon_mode && !use_outfile) {
                die("Daemon mode requires an output file\n");
        }
        if ((pkt_count < 1) && (pkt_count != -1)) {
                die("Invalid -n value: must be -1 or greater than 0\n");
        }

        // General program setup
        if (use_outfile) {
                if (freopen(use_outfile, "a", stdout) == NULL) {
                        log_die("Cannot reopen output stream to '%s'\n", use_outfile);
        	}
        }
        if (!capfilter) capfilter = safe_strdup(default_capfilter);
        if (!run_dir) run_dir = safe_strdup(default_rundir);
        signal(SIGINT, handle_signal);

        // Set up packet capture
        get_dev_info(&dev, &net, interface);
        pcap_hnd = open_dev(dev, set_promisc, use_infile);
        set_filter(pcap_hnd, capfilter, net);

        if (daemon_mode) runas_daemon(run_dir);
        if (new_user) change_user(new_user);

        // Clean up allocated memory before main loop
        if (use_config)  free(use_config);
        if (use_infile)  free(use_infile);
        if (interface)   free(interface);
        if (capfilter)   free(capfilter);
        if (use_outfile) free(use_outfile);
        if (run_dir)     free(run_dir);
        if (new_user)    free(new_user);

        get_packets(pcap_hnd, pkt_count);

        cleanup_exit(EXIT_SUCCESS);

        return 1;
}
