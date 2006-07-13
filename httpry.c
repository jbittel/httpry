/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  httpry.c | created: 4/29/2005

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

#define _BSD_SOURCE 1 /* Needed for Linux/BSD compatibility */
#define TO_MS 0
#define MAX_CONFIG_LEN 512
#define MAX_TIME_LEN 20
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
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "error.h"
#include "httpry.h"
#include "list.h"
#include "tcp.h"

/* Function declarations */
void parse_args(int argc, char** argv);
void parse_config(char *filename);
void parse_format_string(char *str);
void get_dev_info(char **dev, bpf_u_int32 *net, char *interface);
pcap_t *open_dev(char *dev, int promisc, char *fname);
void set_filter(pcap_t *pcap_hnd, char *cap_filter, bpf_u_int32 net);
void change_user(char *new_user);
void get_packets(pcap_t *pcap_hnd, int pkt_count);
void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
int parse_client_request(char *header_line);
int parse_server_response(char *header_line);
void runas_daemon(char *run_dir);
void handle_signal(int sig);
char *safe_strdup(char *curr_str);
char *strip_whitespace(char *str);
void cleanup_exit(int exit_value);
void display_version();
void display_help();

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

static pcap_t *pcap_hnd         = NULL; /* Opened pcap device handle */
static pcap_dumper_t *dump_file = NULL;
static unsigned pkt_parsed      = 0;    /* Count of fully parsed HTTP packets */
NODE *format_str                = NULL;

/* Parse command line arguments */
void parse_args(int argc, char** argv) {
        int argn = 1;

        /* Look for config file argument and process it first to ensure that the
           command line arguments always take prescedence over the config file */
        while ((argn < argc) && (argv[argn][0] == '-')) {
                if ((strncmp(argv[argn], "-c", 2) == 0) && (argn + 1 < argc)) {
                        argn++;
                        parse_config(argv[argn]);
                        break;
                }

                argn++;
        }

        /* Parse the rest of the command line arguments */
        argn = 1;
        while ((argn < argc) && (argv[argn][0] == '-')) {
                if (!strncmp(argv[argn], "-b", 2) && (argn + 1 < argc)) {
                        argn++;
                        use_binfile = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-c", 2) && (argn + 1 < argc)) {
                        argn++;
                        /* Config file; already parsed above */
                } else if (!strncmp(argv[argn], "-d", 2)) {
                        daemon_mode = 1;
                } else if (!strncmp(argv[argn], "-f", 2) && (argn + 1 < argc)) {
                        argn++;
                        use_infile = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-h", 2)) {
                        display_help();
                } else if (!strncmp(argv[argn], "-i", 2) && (argn + 1 < argc)) {
                        argn++;
                        interface = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-l", 2) && (argn + 1 < argc)) {
                        argn++;
                        capfilter = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-n", 2) && (argn + 1 < argc)) {
                        argn++;
                        pkt_count = atoi(argv[argn]);
                } else if (!strncmp(argv[argn], "-o", 2) && (argn + 1 < argc)) {
                        argn++;
                        use_outfile = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-p", 2)) {
                        set_promisc = 0;
                } else if (!strncmp(argv[argn], "-r", 2) && (argn + 1 < argc)) {
                        argn++;
                        run_dir = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-s", 2) && (argn + 1 < argc)) {
                        argn++;
                        out_format = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-u", 2) && (argn + 1 < argc)) {
                        argn++;
                        new_user = safe_strdup(argv[argn]);
                } else if (!strncmp(argv[argn], "-v", 2)) {
                        display_version();
                } else {
                        warn("Parameter '%s' unknown or missing required value\n", argv[argn]);
                        display_help();
                }

                argn++;
        }

        if (argn != argc)
                display_help();

        return;
}

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

                if (!strcmp(name, "DaemonMode")) {
                        daemon_mode = atoi(value);
                } else if (!strcmp(name, "InputFile")) {
                        use_infile = safe_strdup(value);
                } else if (!strcmp(name, "Interface")) {
                        interface = safe_strdup(value);
                } else if (!strcmp(name, "CaptureFilter")) {
                        capfilter = safe_strdup(value);
                } else if (!strcmp(name, "PacketCount")) {
                        pkt_count = atoi(value);
                } else if (!strcmp(name, "OutputFile")) {
                        use_outfile = safe_strdup(value);
                } else if (!strcmp(name, "PromiscuousMode")) {
                        set_promisc = atoi(value);
                } else if (!strcmp(name, "RunDir")) {
                        run_dir = safe_strdup(value);
                } else if (!strcmp(name, "User")) {
                        new_user = safe_strdup(value);
                } else if (!strcmp(name, "OutputFormat")) {
                        out_format = safe_strdup(value);
                } else if (!strcmp(name, "BinaryFile")) {
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

        format_str = create_node();
        str = strip_whitespace(str);

        element = strtok(str, ",");
        while (element != NULL) {
                if (insert_node(format_str, element) == 0) {
                        warn("Format element '%s' already provided...skipping\n", element);
                }

                element = strtok(NULL, ",");
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
pcap_t *open_dev(char *dev, int promisc, char *fname) {
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
                log_die("Bad capture filter syntax in '%s'\n", cap_filter);
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
        if (pcap_loop(pcap_hnd, pkt_count, parse_packet, NULL) < 0) {
                log_die("Cannot read packets from interface\n");
        }

        pcap_close(pcap_hnd);

        return;
}

/* Process each packet that passes the capture filter */
void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
        struct tm *pkt_time;
        char *data;            /* Editable copy of packet data */
        char *header_line;
        char *req_value;
        NODE *element;
        /*int is_request;*/
        char client_request[] = ">";
        char server_response[] = "<";
        char saddr[INET_ADDRSTRLEN];
        char daddr[INET_ADDRSTRLEN];
        char ts[MAX_TIME_LEN]; /* Pcap packet timestamp */

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

        /* Parse valid header line, bail if malformed */
        if ((header_line = strtok(data, DELIM)) == NULL) {
                free(data);
                return;
        }

        /* Ensure we have a valid client request or server response */
        if (strncmp(header_line, GET_STRING, 4) == 0 ||
            strncmp(header_line, HEAD_STRING, 5) == 0) {
                if (parse_client_request(header_line) == 0) {
                        free(data);
                        return;
                }
        } else if (strncmp(header_line, HTTP_STRING, 5) == 0) {
                if (parse_server_response(header_line) == 0) {
                        free(data);
                        return;
                }
        } else {
                free(data);
                return;
        }

        /* Iterate through each HTTP request/response header line */
        while ((header_line = strtok(NULL, DELIM)) != NULL) {
                if ((req_value = strchr(header_line, ':')) == NULL) continue;
                *req_value++ = '\0';
                while (isspace(*req_value)) req_value++; /* Strip leading whitespace */

                if ((element = find_node(format_str, header_line)) == NULL) continue;
                element->value = req_value;
        }

        /* Grab source/destination IP addresses */
        strncpy(saddr, (char *) inet_ntoa(ip->ip_src), INET_ADDRSTRLEN);
        strncpy(daddr, (char *) inet_ntoa(ip->ip_dst), INET_ADDRSTRLEN);

        /* Extract packet capture time */
        pkt_time = localtime((time_t *) &header->ts.tv_sec);
        strftime(ts, MAX_TIME_LEN, "%m/%d/%Y %H:%M:%S", pkt_time);

        /* Print data to stdout/output file according to format list */
        printf("%s\t%s\t%s\t", ts, saddr, daddr);
        print_list(format_str);

        free(data);

        if (use_binfile) pcap_dump((u_char *) dump_file, header, pkt);
        pkt_parsed++;

        return;
}

/* Parse a HTTP client request, bail at first sign of malformed data */
int parse_client_request(char *header_line) {
        HTTP_CLIENT client;
        NODE *element;

        client.method = header_line;

        if ((client.request_uri = strchr(client.method, SPACE_CHAR)) == NULL) {
                return 0;
        }
        *client.request_uri++ = '\0';
        if ((client.http_version = strchr(client.request_uri, SPACE_CHAR)) == NULL) {
                return 0;
        }
        *client.http_version++ = '\0';

        if ((element = find_node(format_str, "Method")) != NULL) {
                element->value = client.method;
        }
        if ((element = find_node(format_str, "Request-URI")) != NULL) {
                element->value = client.request_uri;
        }
        if ((element = find_node(format_str, "HTTP-Version")) != NULL) {
                element->value = client.http_version;
        }
        if ((element = find_node(format_str, "Direction")) != NULL) {
                element->value = client_request;
        }

        return 1;
}

/* Parse a HTTP server response, bail at first sign of malformed data */
int parse_server_response(char *header_line) {
        HTTP_SERVER server;
        NODE *element;

        server.http_version = header_line;

        if ((server.status_code = strchr(server.http_version, SPACE_CHAR)) == NULL) {
                return 0;
        }
        *server.status_code++ = '\0';
        if ((server.reason_phrase = strchr(server.status_code, SPACE_CHAR)) == NULL) {
                return 0;
        }
        *server.reason_phrase++ = '\0';

        if ((element = find_node(format_str, "HTTP-Version")) != NULL) {
                element->value = server.http_version;
        }
        if ((element = find_node(format_str, "Status-Code")) != NULL) {
                element->value = server.status_code;
        }
        if ((element = find_node(format_str, "Reason-Phrase")) != NULL) {
                element->value = server.reason_phrase;
        }
        if ((element = find_node(format_str, "Direction")) != NULL) {
                element->value = server_response;
        }

        return 1;
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

/* Perform clean shutdown if proper signal received */
void handle_signal(int sig) {
        switch (sig) {
                case SIGINT:
                        info("Caught SIGINT, shutting down...\n");
                        cleanup_exit(EXIT_SUCCESS);
                        break;
                case SIGTERM:
                        info("Caught SIGTERM, shutting down...\n");
                        cleanup_exit(EXIT_SUCCESS);
                        break;
        }

        return;
}

/* Centralize error checking for string duplication */
char *safe_strdup(char *curr_str) {
        char *new_str;

        if ((new_str = strdup(curr_str)) == NULL) {
                log_die("Cannot duplicate string '%s'\n", curr_str);
        }

        return new_str;
}

/* Strip leading and trailing spaces from parameter string */
char *strip_whitespace(char *str) {
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

        if (daemon_mode) remove(PID_FILE);
        if (use_infile) free(use_infile);
        if (format_str) free_list(format_str);

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
             "        [-l filter] [-n count] [-o file] [-r dir ] [-s format] [-u user]\n", PROG_NAME);
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

        signal(SIGINT, handle_signal);

        /* Process command line arguments */
        parse_args(argc, argv);

        /* Test for error and warning conditions */
        if ((getuid() != 0) && !use_infile) {
                log_die("Root priviledges required to access the NIC\n");
        }
        if (daemon_mode && !use_outfile) {
                log_die("Daemon mode requires an output file\n");
        }
        if (pkt_count < -1) {
                log_die("Invalid -n value of '%d': must be -1 or greater\n", pkt_count);
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
