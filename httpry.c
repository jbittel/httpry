/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.edu>

*/

#define _BSD_SOURCE 1 /* Needed for Linux/BSD compatibility */
#define MAX_TIME_LEN 20

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
#include "list.h"
#include "tcp.h"

/* Function declarations */
extern int getopt(int,char * const *,const char *);
void parse_format_string(char *str);
pcap_t *prepare_capture(char *interface, int promisc, char *filename, char *capfilter);
void change_user(char *name, uid_t uid, gid_t gid);
void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
int parse_client_request(char *header_line);
int parse_server_response(char *header_line);
void runas_daemon(char *run_dir);
void handle_signal(int sig);
char *strip_whitespace(char *str);
void cleanup();
void display_usage();

/* Program flags/options, set by arguments or config file */
static int parse_count = -1;
static int daemon_mode = 0;
static char *use_infile = NULL;
static char *interface = NULL;
static char *capfilter = NULL;
static char *use_outfile = NULL;
static int set_promisc = 1;
static char *new_user = NULL;
static char *out_format = NULL;
static char *run_dir = NULL;

extern char *optarg;
static pcap_t *pcap_hnd = NULL; /* Opened pcap device handle */
static char default_capfilter[] = DEFAULT_CAPFILTER;
static char default_format[] = DEFAULT_FORMAT;
static char default_rundir[] = RUN_DIR;

/* Parse format string to configure output fields */
void parse_format_string(char *str) {
        char *name;

        /* TODO: do we want to copy out_format to a temp string so we don't destroy it? */

        for (str = strip_whitespace(str); (name = strtok(str, ",")); str = NULL) {
                insert_node(name);
        }

        return;
}

/* Find and prepare ethernet device for capturing */
pcap_t *prepare_capture(char *interface, int promisc, char *filename, char *capfilter) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *pcap_hnd;
        char *dev = NULL;
        bpf_u_int32 net, mask;
        struct bpf_program filter;

        /* Find interface to use and retrieve capture handle */
        if (!filename) {
                if (!interface) {
                        dev = pcap_lookupdev(errbuf);
                        if (dev == NULL)
                                LOG_DIE("Cannot find a valid capture device: %s", errbuf);
                } else {
                        dev = interface;
                }

                if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
                        LOG_DIE("Cannot find network info for '%s': %s", dev, errbuf);

                pcap_hnd = pcap_open_live(dev, BUFSIZ, promisc, 0, errbuf);
                if (pcap_hnd == NULL)
                        LOG_DIE("Cannot start capture on '%s': %s", dev, errbuf);
        } else {
                pcap_hnd = pcap_open_offline(filename, errbuf);
                if (pcap_hnd == NULL)
                        LOG_DIE("Cannot open capture file: %s", errbuf);
        }

        /* Compile capture filter and apply to handle */
        if (pcap_compile(pcap_hnd, &filter, capfilter, 0, net) == -1)
                LOG_DIE("Bad capture filter syntax in '%s'", capfilter);

        if (pcap_setfilter(pcap_hnd, &filter) == -1)
                LOG_DIE("Cannot compile capture filter");

        pcap_freecode(&filter);

        return pcap_hnd;
}

/* Change process owner to specified username */
void change_user(char *name, uid_t uid, gid_t gid) {
        if (initgroups(name, gid))
                LOG_DIE("Cannot initialize the group access list");
        
        if (setgid(gid))
                LOG_DIE("Cannot set GID");
        
        if (setuid(uid))
                LOG_DIE("Cannot set UID");

        /* Test to see if we actually made it to the new user */
        if ((getegid() != gid) || (geteuid() != uid))
                LOG_DIE("Cannot change process owner to '%s'", name);

        return;
}

/* Process each packet that passes the capture filter */
void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
        struct tm *pkt_time;
        char *data;            /* Editable copy of packet data */
        char *header_line;
        char *req_value;
        char saddr[INET_ADDRSTRLEN];
        char daddr[INET_ADDRSTRLEN];
        char ts[MAX_TIME_LEN]; /* Pcap packet timestamp */
        static unsigned pkt_parsed = 0; /* Count of fully parsed HTTP packets */

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

        if (ip->ip_p != 0x6) return; /* Not TCP */
        if (size_data <= 0) return; /* No data to parse */

        /* Copy packet payload to editable buffer */
        if ((data = malloc(size_data + 1)) == NULL) {
                LOG_DIE("Cannot allocate memory for packet data");
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

                insert_value("Direction", ">");
        } else if (strncmp(header_line, HTTP_STRING, 5) == 0) {
                if (parse_server_response(header_line) == 0) {
                        free(data);
                        return;
                }

                insert_value("Direction", "<");
        } else {
                free(data);
                return;
        }

        /* Iterate through each HTTP request/response header line */
        while ((header_line = strtok(NULL, DELIM)) != NULL) {
                if ((req_value = strchr(header_line, ':')) == NULL) continue;
                *req_value++ = '\0';
                while (isspace(*req_value)) req_value++; /* Strip leading whitespace */

                insert_value(header_line, req_value);
        }

        /* Grab source/destination IP addresses */
        strncpy(saddr, (char *) inet_ntoa(ip->ip_src), INET_ADDRSTRLEN);
        strncpy(daddr, (char *) inet_ntoa(ip->ip_dst), INET_ADDRSTRLEN);
        insert_value("Source-IP", saddr);
        insert_value("Dest-IP", daddr);

        /* Extract packet capture time */
        pkt_time = localtime((time_t *) &header->ts.tv_sec);
        strftime(ts, MAX_TIME_LEN, "%m/%d/%Y %H:%M:%S", pkt_time);
        insert_value("Timestamp", ts);

        print_list();

        free(data);

        pkt_parsed++;
        if ((parse_count != -1) && (pkt_parsed >= parse_count)) {
                cleanup();
                exit(EXIT_SUCCESS);
        }

        return;
}

/* Parse a HTTP client request, bail at first sign of invalid request */
int parse_client_request(char *header_line) {
        char *method, *request_uri, *http_version;

        method = header_line;

        if ((request_uri = strchr(method, ' ')) == NULL) return 0;
        *request_uri++ = '\0';
        if ((http_version = strchr(request_uri, ' ')) == NULL) return 0;
        *http_version++ = '\0';

        insert_value("Method", method);
        insert_value("Request-URI", request_uri);
        insert_value("HTTP-Version", http_version);

        return 1;
}

/* Parse a HTTP server response, bail at first sign of invalid response */
int parse_server_response(char *header_line) {
        char *http_version, *status_code, *reason_phrase;

        http_version = header_line;

        if ((status_code = strchr(http_version, ' ')) == NULL) return 0;
        *status_code++ = '\0';
        if ((reason_phrase = strchr(status_code, ' ')) == NULL) return 0;
        *reason_phrase++ = '\0';

        insert_value("HTTP-Version", http_version);
        insert_value("Status-Code", status_code);
        insert_value("Reason-Phrase", reason_phrase);

        return 1;
}

/* Run program as a daemon process */
void runas_daemon(char *run_dir) {
        int child_pid;
        FILE *pid_file;

        if (getppid() == 1) return; /* We're already a daemon */

        fflush(NULL);

        child_pid = fork();
        if (child_pid < 0) LOG_DIE("Cannot fork child process");
        if (child_pid > 0) exit(0); /* Parent bows out */

        /* Configure default output streams */
        dup2(1,2);
        close(0);
        if (freopen(NULL_FILE, "a", stderr) == NULL)
                LOG_DIE("Cannot reopen stderr to '%s'", NULL_FILE);

        /* Assign new process group for child */
        if (setsid() == -1)
                LOG_WARN("Cannot assign new session for child process");

        umask(0); /* Reset file creation mask */
        if (chdir(run_dir) == -1) {
                LOG_WARN("Cannot change run directory to '%s', defaulting to '%s'", run_dir, RUN_DIR);

                if (chdir(RUN_DIR) == -1) {
                        LOG_DIE("Cannot change run directory to '%s'", RUN_DIR);
                }
        }

        /* Write PID into file */
        if ((pid_file = fopen(PID_FILE, "w")) == NULL) {
                LOG_WARN("Cannot open PID file '%s'", PID_FILE);
        } else {
                fprintf(pid_file, "%d", getpid());
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
                        LOG_WARN("Caught SIGINT, shutting down...");
                        cleanup();

                        exit(EXIT_SUCCESS);
                case SIGTERM:
                        LOG_WARN("Caught SIGTERM, shutting down...");
                        cleanup();

                        exit(EXIT_SUCCESS);
        }

        return;
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
void cleanup() {
        fflush(NULL);
        free_list();
        if (daemon_mode) remove(PID_FILE);
        pcap_close(pcap_hnd);

        return;
}

/* Display program help/usage information */
void display_usage() {
        INFO("%s version %s", PROG_NAME, PROG_VER);
        INFO("Usage: %s [-dhp] [-f file] [-i interface]\n"
             "        [-l filter] [-n count] [-o file] [-r dir ] [-s format] [-u user]", PROG_NAME);
        INFO("  -d ... run as daemon\n"
             "  -f ... input file to read from\n"
             "  -h ... print help information\n"
             "  -i ... set interface to listen on\n"
             "  -l ... pcap style capture filter\n"
             "  -n ... number of HTTP packets to parse\n"
             "  -o ... specify output file\n"
             "  -p ... disable promiscuous mode\n"
             "  -r ... set running directory\n"
             "  -s ... specify output format string\n"
             "  -u ... set process owner\n");

        INFO("Additional information can be found at:\n"
             "    http://dumpsterventures.com/jason/httpry\n");

        exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
        struct passwd *user = NULL;
        int opt;

        signal(SIGINT, handle_signal);

        /* Process command line arguments */
        while ((opt = getopt(argc, argv, "dhpf:i:l:n:o:r:s:u:")) != -1) {
                switch (opt) {
                        case 'd': daemon_mode = 1; break;
                        case 'f': use_infile = optarg; break;
                        case 'h': display_usage(); break;
                        case 'i': interface = optarg; break;
                        case 'l': capfilter = optarg; break;
                        case 'n': parse_count = atoi(optarg);
                                  if ((parse_count != -1) && (parse_count < 1))
                                          LOG_DIE("Invalid -n value");
                                  break;
                        case 'o': use_outfile = optarg; break;
                        case 'p': set_promisc = 0; break;
                        case 'r': run_dir = optarg; break;
                        case 's': out_format = optarg; break;
                        case 'u': new_user = optarg; break;
                        default: display_usage();
                }
        }

        /* Test for argument error and warning conditions */
        if (daemon_mode && !use_outfile)
                LOG_DIE("Daemon mode requires an output file");
        if (!daemon_mode && run_dir)
                LOG_WARN("Run directory only utilized when running in daemon mode");

        /* General program setup */
        if (!capfilter) capfilter = default_capfilter;
        if (!out_format) out_format = default_format;
        if (!run_dir) run_dir = default_rundir;
        parse_format_string(out_format);
        
        /* Get user information if we need to switch from root */
        if (new_user) {
                if (getuid() != 0)
                        LOG_DIE("You must be root to switch users");

                /* Get user info; die if user doesn't exist */
                if (!(user = getpwnam(new_user)))
                        LOG_DIE("User '%s' not found in system", new_user);
        }

        /* Prepare output file as necessary */
        if (use_outfile) {
                if (use_outfile[0] != '/')
                        LOG_WARN("Output file path is not absolute and may become inaccessible");

                if (freopen(use_outfile, "a", stdout) == NULL)
                        LOG_DIE("Cannot reopen output stream to '%s'", use_outfile);

        	if (new_user) {
                        if (chown(use_outfile, user->pw_uid, user->pw_gid) < 0)
                                LOG_WARN("Cannot change ownership of output file");
        	}

                print_header_line();
        }

        pcap_hnd = prepare_capture(interface, set_promisc, use_infile, capfilter);

        if (daemon_mode) runas_daemon(run_dir);
        if (new_user) change_user(new_user, user->pw_uid, user->pw_gid);

        /* Main packet capture loop */ 
        if (pcap_loop(pcap_hnd, -1, parse_http_packet, NULL) < 0)
                LOG_DIE("Cannot read packets from interface");

        cleanup();

        return EXIT_SUCCESS;
}
