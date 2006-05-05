/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  httpry.c 4/29/2005

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

#define _BSD_SOURCE 1 /* Needed for Linux/BSD compatibility */
#define TO_MS 0
#define MAX_TIME_LEN 20
#define MAX_CONFIG_LEN 512
#define MAX_FORMAT_OPT 22
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

/* Function declarations */
void parse_config(char *filename);
void parse_format_string(char *str);
void get_dev_info(char **dev, bpf_u_int32 *net, char *interface);
pcap_t* open_dev(char *dev, int promisc, char *fname);
void set_filter(pcap_t *pcap_hnd, char *cap_filter, bpf_u_int32 net);
void change_user(char *new_user);
void get_packets(pcap_t *pcap_hnd, int pkt_count);
void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
void runas_daemon(char *run_dir);
void handle_signal(int sig);
char* safe_strdup(char *curr_str);
char* strip_whitespace(char *str); 
void cleanup_exit(int exit_value);
void display_version();
void display_help();
extern int getopt(int argc, char *const argv[], const char *optstring);

/* Program flags/options, set by arguments or config file */
static char *use_binfile = NULL;
static int   pkt_count   = -1;
static int   daemon_mode = 0;
static char *use_infile  = NULL;
static char *interface   = NULL;
static char *capfilter   = NULL;
static char *use_outfile = NULL;
static int   set_promisc = 1;
static char *new_user    = NULL;
static char *out_format  = NULL;
static char *run_dir     = NULL;
static char *use_config  = NULL;

static pcap_t *pcap_hnd = NULL; /* Opened pcap device handle */
static pcap_dumper_t *dump_file = NULL;
static int pkt_parsed = 0;

static struct pkt_hdr packet;
static struct http_hdr http;  /* HTTP request header fields */

static char **format_str[MAX_FORMAT_OPT];
static int format_cnt = 0;

/* Read options in from config file */
void parse_config(char *filename) {
        FILE *config_file;
        char buf[MAX_CONFIG_LEN];
        char *line;
        char *name;
        char *value;
        int line_count = 0;
        int len;

        if ((config_file = fopen(filename, "r")) == NULL) {
                log_die("Cannot open config file '%s'\n", filename);
        }

        while ((line = fgets(buf, sizeof(buf), config_file))) {
                line_count++;

                line = strip_whitespace(line);

                /* Skip blank lines and comments */
                if (!strlen(line)) continue;
                if (*line == '#') continue;

                /* Parse each line into name/value pairs */
                name = line;
                if ((value = strchr(line, '=')) == NULL) {
                        warn("Bad data in config file at line %d\n", line_count);
                        continue;
                }
                *value++ = '\0';

                /* Strip inner spaces from name and value */
                len = strlen(name);
                while (len && isspace(*(name + len - 1)))
                        *(name + (len--) - 1) = '\0';
                while (isspace(*value)) value++;

                /* Test parsed name/value pairs and set values accordingly; only
                   set if default value is unchanged to prevent overwriting arguments */
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
                } else if (!strcmp(name, "OutputFormat") && !out_format) {
                        out_format = safe_strdup(value);
                } else if (!strcmp(name, "BinaryFile") && !use_binfile) {
                        use_binfile = safe_strdup(value);
                } else {
                        warn("Config file option '%s' at line %d not recognized...skipping\n", name, line_count);
                        continue;
                }
        }

        fclose(config_file);

        return;
}

/* Parse format string to determine output fields */
void parse_format_string(char *str) {
        char *element = NULL;
        
        str = strip_whitespace(str);

        element = strtok(str, ",");
        while ((element != NULL) && (format_cnt < MAX_FORMAT_OPT)) {
                if (strncmp(element, "Method", 6) == 0) { /* HTTP request line */
                        format_str[format_cnt] = &http.method; 
                } else if (strncmp(element, "URI", 3) == 0) {
                        format_str[format_cnt] = &http.uri; 
                } else if (strncmp(element, "Version", 7) == 0) {
                        format_str[format_cnt] = &http.version; 
                } else if (strncmp(element, "Accept", 6) == 0) { /* HTTP request headers */
                        format_str[format_cnt] = &http.accept; 
                } else if (strncmp(element, "Accept-Charset", 14) == 0) {
                        format_str[format_cnt] = &http.accept_charset; 
                } else if (strncmp(element, "Accept-Encoding", 15) == 0) {
                        format_str[format_cnt] = &http.accept_encoding; 
                } else if (strncmp(element, "Accept-Language", 15) == 0) {
                        format_str[format_cnt] = &http.accept_language; 
                } else if (strncmp(element, "Authorization", 13) == 0) {
                        format_str[format_cnt] = &http.authorization; 
                } else if (strncmp(element, "Expect", 6) == 0) {
                        format_str[format_cnt] = &http.expect; 
                } else if (strncmp(element, "From", 4) == 0) {
                        format_str[format_cnt] = &http.from; 
                } else if (strncmp(element, "Host", 4) == 0) {
                        format_str[format_cnt] = &http.host; 
                } else if (strncmp(element, "If-Match", 8) == 0) {
                        format_str[format_cnt] = &http.if_match; 
                } else if (strncmp(element, "If-Modified-Since", 17) == 0) {
                        format_str[format_cnt] = &http.if_modified_since; 
                } else if (strncmp(element, "If-None-Match", 13) == 0) {
                        format_str[format_cnt] = &http.if_none_match; 
                } else if (strncmp(element, "If-Range", 8) == 0) {
                        format_str[format_cnt] = &http.if_range; 
                } else if (strncmp(element, "If-Unmodified-Since", 19) == 0) {
                        format_str[format_cnt] = &http.if_unmodified_since; 
                } else if (strncmp(element, "Max-Forwards", 12) == 0) {
                        format_str[format_cnt] = &http.max_forwards; 
                } else if (strncmp(element, "Proxy-Authorization", 19) == 0) {
                        format_str[format_cnt] = &http.proxy_authorization; 
                } else if (strncmp(element, "Range", 5) == 0) {
                        format_str[format_cnt] = &http.range; 
                } else if (strncmp(element, "Referer", 7) == 0) {
                        format_str[format_cnt] = &http.referer; 
                } else if (strncmp(element, "TE", 2) == 0) {
                        format_str[format_cnt] = &http.te; 
                } else if (strncmp(element, "User-Agent", 10) == 0) {
                        format_str[format_cnt] = &http.user_agent; 
                } else {
                        warn("Format string element '%s' not recognized...skipping\n", element);
                        element = strtok(NULL, ",");
                        continue;
                }
                
                element = strtok(NULL, ",");
                format_cnt++;
        }

        return;
}

/* Gather information about local network device */
void get_dev_info(char **dev, bpf_u_int32 *net, char *interface) {
        char errbuf[PCAP_ERRBUF_SIZE]; /* Pcap error string */
        bpf_u_int32 mask;              /* Network mask */

        if (!interface) {
                /* Search for network device */
                *dev = pcap_lookupdev(errbuf);
                if (dev == NULL) {
                        log_die("Cannot find capture device '%s'\n", errbuf);
                }
        } else {
                /* Use network interface from user parameter */
                *dev = interface;
        }

        /* Retrieve network information */
        if (pcap_lookupnet(*dev, net, &mask, errbuf) == -1) {
                log_die("Cannot find network info for '%s': %s\n", *dev, errbuf);
        }

        return;
}

/* Open selected device for capturing */
pcap_t* open_dev(char *dev, int promisc, char *fname) {
        char errbuf[PCAP_ERRBUF_SIZE]; /* Pcap error string */
        pcap_t *pcap_hnd;              /* Opened pcap device handle */

        if (fname) {
                /* Open saved capture file */
                pcap_hnd = pcap_open_offline(fname, errbuf);
                if (pcap_hnd == NULL) {
                        log_die("Cannot open capture file '%s': %s\n", fname, errbuf);
                }
        } else {
                /* Open live capture */
                pcap_hnd = pcap_open_live(dev, BUFSIZ, promisc, TO_MS, errbuf);
                if (pcap_hnd == NULL) {
                        log_die("Invalid device '%s': %s\n", dev, errbuf);
                }
        }

        return pcap_hnd;
}

/* Compile and set pcap filter on device handle */
void set_filter(pcap_t *pcap_hnd, char *cap_filter, bpf_u_int32 net) {
        struct bpf_program filter; /* Compiled capture filter */

        /* Compile filter string */
        if (pcap_compile(pcap_hnd, &filter, cap_filter, 0, net) == -1) {
                die("Bad capture filter syntax in '%s'\n", cap_filter);
        }

        /* Apply compiled filter to pcap handle */
        if (pcap_setfilter(pcap_hnd, &filter) == -1) {
                log_die("Cannot compile capture filter\n");
        }

        /* Clean up compiled filter */
        pcap_freecode(&filter);

        return;
}

/* Change process owner to requested username */
void change_user(char *new_user) {
        struct passwd* user;

        /* Make sure we have correct priviledges */
        if (geteuid() > 0) {
                log_die("You must be root to switch users\n");
        }

        /* Test for user existence in the system */
        if (!(user = getpwnam(new_user))) {
                log_die("User '%s' not found in system\n", new_user);
        }

        /* Set group information, GID and UID */
        if (initgroups(user->pw_name, user->pw_gid)) {
                log_die("Cannot initialize the group access list\n");
        }
        if (setgid(user->pw_gid)) {
                log_die("Cannot set GID\n");
        }
        if (setuid(user->pw_uid)) {
                log_die("Cannot set UID\n");
        }

        /* Test to see if we actually made it to the new user */
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
        struct tm *pkt_time;
        char *data;            /* Editable copy of packet data */
        char *req_header;      /* Request header line */
        int i;

        const struct pkt_eth *eth; /* These structs define the layout of the packet */
        const struct pkt_ip *ip;
        const struct pkt_tcp *tcp;
        const char *payload;

        int size_eth = sizeof(struct pkt_eth); /* Calculate size of packet components */
        int size_ip = sizeof(struct pkt_ip);
        int size_data;

        /* Position pointers within packet stream */
        eth = (struct pkt_eth *)(pkt);
        ip = (struct pkt_ip *)(pkt + size_eth);
        tcp = (struct pkt_tcp *)(pkt + size_eth + size_ip);
        payload = (u_char *)(pkt + size_eth + size_ip + (tcp->th_off * 4));
        size_data = (header->caplen - (size_eth + size_ip + (tcp->th_off * 4)));

        if (size_data <= 0) return; /* Bail early if no data to parse */

        /* Copy packet payload to editable buffer */
        if ((data = malloc(size_data + 1)) == NULL) {
                log_die("Cannot allocate memory for packet data\n");
        }
        strncpy(data, payload, size_data);
        data[size_data] = '\0';

        /* Parse valid request line, bail if malformed */
        if ((http.method = strtok(data, DELIM)) == NULL) {
                free(data);
                return;
        }
        /* Not all HTTP/1.1 methods parsed as we're currently
           only interested in data requested from the server */
        if (strncmp(http.method, GET_REQUEST, 4) != 0 &&
            strncmp(http.method, HEAD_REQUEST, 5) != 0) {
                free(data);
                return;
        }
        if ((http.uri = strchr(http.method, SPACE_CHAR)) == NULL) {
                free(data);
                return;
        }
        *http.uri++ = '\0';
        if ((http.version = strchr(http.uri, SPACE_CHAR)) == NULL) {
                free(data);
                return;
        }
        *http.version++ = '\0';

        /* Ensure these pointers are cleared so we don't get garbage from previous packets */
        /*http.method = NULL;
        http.uri = NULL;
        http.version = NULL;*/
        http.accept = NULL;
        http.accept_charset = NULL;
        http.accept_encoding = NULL;
        http.accept_language = NULL;
        http.authorization = NULL;
        http.expect = NULL;
        http.from = NULL;
        http.host = NULL;
        http.if_match = NULL;
        http.if_modified_since = NULL;
        http.if_none_match = NULL;
        http.if_range = NULL;
        http.if_unmodified_since = NULL;
        http.max_forwards = NULL;
        http.proxy_authorization = NULL;
        http.range = NULL;
        http.referer = NULL;
        http.te = NULL;
        http.user_agent = NULL;

        /* Parse each HTTP request header line */
        while ((req_header = strtok(NULL, DELIM)) != NULL) {
                if (strncmp(req_header, "Accept: ", 8) == 0) {
                        http.accept = req_header + 8;
                } else if (strncmp(req_header, "Accept-Charset: ", 16) == 0) {
                        http.accept_charset = req_header + 16;
                } else if (strncmp(req_header, "Accept-Encoding: ", 17) == 0) {
                        http.accept_encoding = req_header + 17;
                } else if (strncmp(req_header, "Accept-Language: ", 17) == 0) {
                        http.accept_language = req_header + 17;
                } else if (strncmp(req_header, "Authorization: ", 15) == 0) {
                        http.authorization = req_header + 15;
                } else if (strncmp(req_header, "Expect: ", 8) == 0) {
                        http.expect = req_header + 8;
                } else if (strncmp(req_header, "From: ", 6) == 0) {
                        http.from = req_header + 6;
                } else if (strncmp(req_header, "Host: ", 6) == 0) {
                        http.host = req_header + 6;
                } else if (strncmp(req_header, "If-Match: ", 10) == 0) {
                        http.if_match = req_header + 10;
                } else if (strncmp(req_header, "If-Modified-Since: ", 19) == 0) {
                        http.if_modified_since = req_header + 19;
                } else if (strncmp(req_header, "If-None-Match: ", 15) == 0) {
                        http.if_none_match = req_header + 15;
                } else if (strncmp(req_header, "If-Range: ", 10) == 0) {
                        http.if_range = req_header + 10;
                } else if (strncmp(req_header, "If-Unmodified-Since: ", 21) == 0) {
                        http.if_unmodified_since = req_header + 21;
                } else if (strncmp(req_header, "Max-Forwards: ", 14) == 0) {
                        http.max_forwards = req_header + 14;
                } else if (strncmp(req_header, "Proxy-Authorization: ", 21) == 0) {
                        http.proxy_authorization = req_header + 21;
                } else if (strncmp(req_header, "Range: ", 7) == 0) {
                        http.range = req_header + 7;
                } else if (strncmp(req_header, "Referer: ", 9) == 0) {
                        http.referer = req_header + 9;
                } else if (strncmp(req_header, "TE: ", 4) == 0) {
                        http.te = req_header + 4;
                } else if (strncmp(req_header, "User-Agent: ", 12) == 0) {
                        http.user_agent = req_header + 12;
                }
        }

        /* Grab source/destination IP addresses */
        strncpy(packet.saddr, (char *) inet_ntoa(ip->ip_src), INET_ADDRSTRLEN);
        strncpy(packet.daddr, (char *) inet_ntoa(ip->ip_dst), INET_ADDRSTRLEN);

        /* Extract packet capture time */
        pkt_time = localtime((time_t *) &header->ts.tv_sec);
        strftime(packet.ts, MAX_TIME_LEN, "%m/%d/%Y %H:%M:%S", pkt_time);

        /* Print data to stdout/output file according to format array */
        printf("%s\t%s\t%s\t", packet.ts, packet.saddr, packet.daddr);
        for (i = 0; i < format_cnt; i++) {
                if (*(format_str[i]) != NULL) {
                        printf("%s\t", *(format_str[i]));
                } else {
                        printf("-\t");
                }
        }
        printf("\n");

        free(data);

        if (use_binfile) pcap_dump((u_char *) dump_file, header, pkt);
        pkt_parsed++;

        return;
}

/* Run program as a daemon process */
void runas_daemon(char *run_dir) {
        int child_pid;
        FILE *pid_file;

        if (getppid() == 1) return; /* We're already a daemon */

        fflush(NULL);

        child_pid = fork();
        if (child_pid < 0) { /* Error forking child */
                log_die("Cannot fork child process\n");
        }
        if (child_pid > 0) exit(0); /* Parent bows out */

        /* Configure default output streams */
        dup2(1,2);
        close(0);
        if (freopen(NULL_FILE, "a", stderr) == NULL) {
                log_die("Cannot re-open stderr to '%s'\n", NULL_FILE);
        }

        /* Assign new process group for child */
        if (setsid() == -1) {
                log("Cannot assign new session for child process\n");
                warn("Cannot assign new session for child process\n");
        }

        umask(0); /* Reset file creation mask */
        if (chdir(run_dir) == -1) {
                log("Cannot change run directory to '%s', defaulting to '%s'\n", run_dir, RUN_DIR);
                warn("Cannot change run directory to '%s', defaulting to '%s'\n", run_dir, RUN_DIR);
                if (chdir(RUN_DIR) == -1) {
                        log_die("Cannot change run directory to '%s'\n", RUN_DIR);
                }
        }

        /* Write PID into file */
        if ((pid_file = fopen(PID_FILE, "w")) == NULL) {
                log("Cannot open PID file '%s'\n", PID_FILE);
                warn("Cannot open PID file '%s'\n", PID_FILE);
        } else {
                fprintf(pid_file, "%d\n", getpid());
                fclose(pid_file);
        }

        /* Configure daemon signal handling */
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
                        info("\nCaught SIGINT, cleaning up...\n");
                        cleanup_exit(EXIT_SUCCESS);
                        break;
                case SIGTERM:
                        info("\nCaught SIGTERM, cleaning up...\n");
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

/* Strip leading and trailing spaces from parameter string */
char* strip_whitespace(char *str) {
        int len;
        
        while (isspace(*str)) str++;
        len = strlen(str);
        while (len && isspace(*(str + len - 1)))
                *(str + (len--) - 1) = '\0';

        return str;
}

/* Clean up/flush opened filehandles on exit */
void cleanup_exit(int exit_value) {
        struct pcap_stat pkt_stats; /* Store stats from pcap */

        fflush(NULL);
        remove(PID_FILE); /* If daemon, we need this gone */

        if (dump_file) {
                pcap_dump_flush(dump_file);
                pcap_dump_close(dump_file);
        }

        if (pcap_hnd && !use_infile) { /* Stats are not calculated when reading from an input file */
                if (pcap_stats(pcap_hnd, &pkt_stats) != 0) {
                        warn("Could not obtain packet capture statistics\n");
                } else {
                        info("  %d packets received\n", pkt_stats.ps_recv);
                        info("  %d packets dropped\n", pkt_stats.ps_drop);
                        info("  %d packets parsed\n", pkt_parsed);
                }
        }

        if (use_infile) free(use_infile);

        exit(exit_value);
}

/* Display program version information */
void display_version() {
        info("%s version %s\n", PROG_NAME, PROG_VER);

        exit(EXIT_SUCCESS);
}

/* Display program help/usage information */
void display_help() {
        info("%s version %s\n", PROG_NAME, PROG_VER);
        info("Usage: %s [-dhpv] [-b file] [-c file] [-f file] [-i interface]\n"
             "        [-l filter] [-n count] [-o file] [-r dir ] [-s string] [-u user]\n", PROG_NAME);
        info("  -b ... binary packet output file\n"
             "  -c ... specify config file\n"
             "  -d ... run as daemon\n"
             "  -f ... input file to read from\n"
             "  -h ... print help information\n"
             "  -i ... set interface to listen on\n"
             "  -l ... pcap style capture filter\n"
             "  -n ... number of packets to capture\n"
             "  -o ... output file to write into\n"
             "  -p ... disable promiscuous mode\n"
             "  -r ... set running directory\n"
             "  -s ... specify output format string\n"
             "  -u ... set process owner\n"
             "  -v ... display version information\n");

        exit(EXIT_SUCCESS);
}

/* Main, duh */
int main(int argc, char *argv[]) {
        char *dev = NULL;
        bpf_u_int32 net;
        char default_capfilter[] = DEFAULT_CAPFILTER;
        char default_format[] = DEFAULT_FORMAT;
        char default_rundir[] = RUN_DIR;
        int arg;
        extern char *optarg;
        extern int optopt;
        
        /* Process command line arguments */
        while ((arg = getopt(argc, argv, "b:c:df:hi:l:n:o:pr:s:u:vx")) != -1) {
                switch (arg) {
                        case 'b': use_binfile = safe_strdup(optarg); break;
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
                        case 's': out_format = safe_strdup(optarg); break;
                        case 'u': new_user = safe_strdup(optarg); break;
                        case 'v': display_version(); break;
                        case '?': if (isprint(optopt)) {
                                          warn("Unknown parameter '-%c'\n", optopt);
                                          display_help();
                                  } else {
                                          warn("Unknown parameter\n");
                                          display_help();
                                  }
                        default:  display_help(); /* Shouldn't be reached */
                }
        }

        if (use_config) parse_config(use_config);

        /* Test for error and warn conditions */
        if ((getuid() != 0) && !use_infile) {
                die("Root priviledges required to access the NIC\n");
        }
        if (daemon_mode && !use_outfile) {
                die("Daemon mode requires an output file\n");
        }
        if ((pkt_count < 1) && (pkt_count != -1)) {
                die("Invalid -n value: must be -1 or greater than 0\n");
        }

        /* General program setup */
        if (use_outfile) {
                if (freopen(use_outfile, "a", stdout) == NULL) {
                        log_die("Cannot reopen output stream to '%s'\n", use_outfile);
        	}
        }
        if (!capfilter) capfilter = safe_strdup(default_capfilter);
        if (!out_format) out_format = safe_strdup(default_format);
        if (!run_dir) run_dir = safe_strdup(default_rundir);
        signal(SIGINT, handle_signal);
        parse_format_string(out_format);

        /* Set up packet capture */
        get_dev_info(&dev, &net, interface);
        pcap_hnd = open_dev(dev, set_promisc, use_infile);
        set_filter(pcap_hnd, capfilter, net);

        /* Open binary pcap output file for writing */
        if (use_binfile) {
                if ((dump_file = pcap_dump_open(pcap_hnd, use_binfile)) == NULL) {
                        log_die("Cannot open dump file '%s'", use_binfile);
                }
        }

        if (daemon_mode) runas_daemon(run_dir);
        if (new_user) change_user(new_user);

        /* Clean up allocated memory before main loop */
        if (use_binfile) free(use_binfile);
        if (use_config)  free(use_config);
        if (interface)   free(interface);
        if (capfilter)   free(capfilter);
        if (use_outfile) free(use_outfile);
        if (run_dir)     free(run_dir);
        if (new_user)    free(new_user);
        if (out_format)  free(out_format);

        get_packets(pcap_hnd, pkt_count);

        cleanup_exit(EXIT_SUCCESS);

        return 1;
}
