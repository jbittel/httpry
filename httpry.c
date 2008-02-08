/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>

*/

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
#include "format.h"
#include "tcp.h"

/* Function declarations */
int getopt(int, char * const *, const char *);
pcap_t *prepare_capture(char *interface, int promisc, char *filename, char *capfilter);
void set_header_offset(int header_type);
void runas_daemon();
void change_user(char *name);
void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
char *parse_header_line(char *header_line);
int parse_client_request(char *header_line);
int parse_server_response(char *header_line);
void handle_signal(int sig);
void cleanup();
void display_usage();

/* Program flags/options, set by arguments or config file */
static int parse_count = 0;
static int daemon_mode = 0;
static char *use_infile = NULL;
static char *interface = NULL;
static char *capfilter = NULL;
static char *use_outfile = NULL;
static int set_promisc = 1;
static char *new_user = NULL;
static char *out_format = NULL;

static pcap_t *pcap_hnd = NULL; /* Opened pcap device handle */
static char *buf = NULL;
static unsigned num_parsed = 0; /* Count of fully parsed HTTP packets */
static unsigned start_time = 0; /* Start tick for statistics calculations */
static int header_offset = 0;
static char default_capfilter[] = DEFAULT_CAPFILTER;
static char default_format[] = DEFAULT_FORMAT;

/* Find and prepare ethernet device for capturing */
pcap_t *prepare_capture(char *interface, int promisc, char *filename, char *capfilter) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *pcap_hnd;
        char *dev = NULL;
        bpf_u_int32 net, mask;
        struct bpf_program filter;

        if (!filename) {
                /* Starting live capture, so find and open network device */
                if (!interface) {
                        dev = pcap_lookupdev(errbuf);
                        if (dev == NULL)
                                LOG_DIE("Cannot find a valid capture device: %s", errbuf);
                } else {
                        dev = interface;
                }

                if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) net = 0;

                pcap_hnd = pcap_open_live(dev, BUFSIZ, promisc, 0, errbuf);

                if (pcap_hnd == NULL)
                        LOG_DIE("Cannot open live capture on '%s': %s", dev, errbuf);
        } else {
                /* Reading from a saved capture, so open file */
                pcap_hnd = pcap_open_offline(filename, errbuf);

                if (pcap_hnd == NULL)
                        LOG_DIE("Cannot open saved capture file: %s", errbuf);
        }

        set_header_offset(pcap_datalink(pcap_hnd));

        /* Compile capture filter and apply to handle */
        if (pcap_compile(pcap_hnd, &filter, capfilter, 0, net) == -1)
                LOG_DIE("Cannot compile capture filter '%s': %s", capfilter, pcap_geterr(pcap_hnd));

        if (pcap_setfilter(pcap_hnd, &filter) == -1)
                LOG_DIE("Cannot apply capture filter: %s", pcap_geterr(pcap_hnd));

        pcap_freecode(&filter);

        if (!filename) LOG_PRINT("Starting capture on %s interface", dev);

        return pcap_hnd;
}

/* Set the proper packet header offset length based on the datalink type */
void set_header_offset(int header_type) {

#ifdef DEBUG
        ASSERT(header_type > 0);
#endif

        switch (header_type) {
                case DLT_EN10MB:
                        header_offset = 14;
                        break;
#ifdef DLT_IEEE802_11
                case DLT_IEEE802_11:
                        header_offset = 32;
                        break;
#endif
#ifdef DLT_LINUX_SLL
                case DLT_LINUX_SLL:
                        header_offset = 16;
                        break;
#endif
#ifdef DLT_LOOP
                case DLT_LOOP:
                        header_offset = 4;
                        break;
#endif
                case DLT_NULL:
                        header_offset = 4;
                        break;
                case DLT_RAW:
                        header_offset = 0;
                        break;
                default:
                        LOG_DIE("Unsupported datalink type: %s", pcap_datalink_val_to_name(header_type));
                        break;
        }

        return;
}

/* Run program as a daemon process */
void runas_daemon() {
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

        umask(022); /* Reset file creation mask */
        if (chdir("/") == -1)
                LOG_DIE("Cannot change run directory to '/'");

        if ((pid_file = fopen(PID_FILE, "w"))) {
                fprintf(pid_file, "%d", getpid());
                fclose(pid_file);
        } else {
                LOG_WARN("Cannot open PID file '%s'", PID_FILE);
        }

        signal(SIGCHLD, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
        signal(SIGTTIN, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        signal(SIGTERM, &handle_signal);

        fflush(NULL);

        return;
}

/* Change process owner to specified username */
void change_user(char *name) {
        struct passwd *user = NULL;

#ifdef DEBUG
        ASSERT(name);
        ASSERT(strlen(name) > 0);
#endif

        if ((getuid() != 0) && (geteuid() != 0))
                LOG_DIE("You must be root to switch users");

        if (!(user = getpwnam(name)))
                LOG_DIE("User '%s' not found in system", name);

        /* Change ownership of the output file before we drop privs */
        if (use_outfile) {
                if (chown(use_outfile, user->pw_uid, user->pw_gid) < 0)
                        LOG_WARN("Cannot change ownership of output file '%s'", use_outfile);
        }

        if (initgroups(name, user->pw_gid))
                LOG_DIE("Cannot initialize the group access list");

        if (setgid(user->pw_gid)) LOG_DIE("Cannot set GID");
        if (setuid(user->pw_uid)) LOG_DIE("Cannot set UID");

        /* Test to see if we actually made it to the new user */
        if ((getegid() != user->pw_gid) || (geteuid() != user->pw_uid))
                LOG_DIE("Cannot change process owner to '%s'", name);

        return;
}

/* Process each packet that passes the capture filter */
void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
        struct tm *pkt_time;
        char *header_line, *req_value;
        char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
        char ts[MAX_TIME_LEN];
        int is_request = 0, is_response = 0;

        const struct ip_header *ip;
        const struct tcp_header *tcp;
        const char *data;
        int size_ip, size_tcp, size_data;

        /* Position pointers within packet stream and do sanity checks */
        ip = (struct ip_header *) (pkt + header_offset);
	size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
#ifdef DEBUG
		PRINT("Invalid IP header length: %u bytes", size_ip);
                ASSERT(size_ip < 20);
#endif
		return;
	}
        if (ip->ip_p != IPPROTO_TCP) return;

        tcp = (struct tcp_header *) (pkt + header_offset + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
#ifdef DEBUG
		PRINT("Invalid TCP header length: %u bytes", size_tcp);
                ASSERT(size_tcp < 20);
#endif
		return;
	}

        data = (char *) (pkt + header_offset + size_ip + size_tcp);
        size_data = (header->caplen - (header_offset + size_ip + size_tcp));
        if (size_data <= 0) return;

        /* Check if we appear to have a valid request or response */
        /* TODO: Add support for any request method */
        if (strncmp(data, GET_STRING, strlen(GET_STRING)) == 0 ||
            strncmp(data, HEAD_STRING, strlen(HEAD_STRING)) == 0) {
                is_request = 1;
        } else if (strncmp(data, HTTP_STRING, strlen(HTTP_STRING)) == 0) {
                is_response = 1;
        } else {
                return;
        }

        /* Copy packet data to editable buffer */
        if (size_data > BUFSIZ) size_data = BUFSIZ;
        strncpy(buf, data, size_data);
        buf[size_data] = '\0';

        /* Parse header line, bail if malformed */
        if ((header_line = parse_header_line(buf)) == NULL) return;

        if (is_request) {
                if (parse_client_request(header_line) == 0) return;
        } else if (is_response) {
                if (parse_server_response(header_line) == 0) return;
        }

        /* Iterate through request/entity header fields */
        while ((header_line = parse_header_line(NULL)) != NULL) {
                if ((req_value = strchr(header_line, ':')) == NULL) continue;
                *req_value++ = '\0';
                while (isspace(*req_value)) req_value++;

                insert_value(header_line, req_value);
        }

        /* Grab source/destination IP addresses */
        strncpy(saddr, (char *) inet_ntoa(ip->ip_src), INET_ADDRSTRLEN);
        strncpy(daddr, (char *) inet_ntoa(ip->ip_dst), INET_ADDRSTRLEN);
        insert_value("source-ip", saddr);
        insert_value("dest-ip", daddr);

        /* Extract packet capture time */
        pkt_time = localtime((time_t *) &header->ts.tv_sec);
        strftime(ts, MAX_TIME_LEN, "%m/%d/%Y %H:%M:%S", pkt_time);
        insert_value("timestamp", ts);

        print_values();

        num_parsed++;
        if (parse_count && (num_parsed >= parse_count)) {
                cleanup();
                exit(EXIT_SUCCESS);
        }

        return;
}

/* Tokenize a HTTP header into lines; the first call should pass the string
   to tokenize, all subsequent calls for the same string should pass NULL */
char *parse_header_line(char *header_line) {
        static char *pos;
        char *tmp;

        if (header_line) pos = header_line;

        if ((tmp = strstr(pos, HEADER_DELIM)) == NULL) return NULL;
        if (tmp == pos) return NULL; /* Reached the end of the header */

        *tmp = '\0';
        header_line = pos;
        pos = tmp + strlen(HEADER_DELIM);

        return header_line;
}

/* Parse a HTTP client request; bail at first sign of an invalid request */
int parse_client_request(char *header_line) {
        char *method, *request_uri, *http_version;

        method = header_line;

        if ((request_uri = strchr(method, ' ')) == NULL) return 0;
        *request_uri++ = '\0';
        if ((http_version = strchr(request_uri, ' ')) == NULL) return 0;
        *http_version++ = '\0';
        if (strncmp(http_version, HTTP_STRING, strlen(HTTP_STRING)) != 0) return 0;

        insert_value("method", method);
        insert_value("request-uri", request_uri);
        insert_value("http-version", http_version);
        insert_value("direction", ">");

        return 1;
}

/* Parse a HTTP server response; bail at first sign of an invalid response */
int parse_server_response(char *header_line) {
        char *http_version, *status_code, *reason_phrase;

        http_version = header_line;

        if (strncmp(http_version, HTTP_STRING, strlen(HTTP_STRING)) != 0) return 0;
        if ((status_code = strchr(http_version, ' ')) == NULL) return 0;
        *status_code++ = '\0';
        if ((reason_phrase = strchr(status_code, ' ')) == NULL) return 0;
        *reason_phrase++ = '\0';

        insert_value("http-version", http_version);
        insert_value("status-code", status_code);
        insert_value("reason-phrase", reason_phrase);
        insert_value("direction", "<");

        return 1;
}

/* Perform clean shutdown if proper signal received */
void handle_signal(int sig) {
        switch (sig) {
                case SIGINT:
                        LOG_PRINT("Caught SIGINT, shutting down...");
                        cleanup();
                        break;
                case SIGTERM:
                        LOG_PRINT("Caught SIGTERM, shutting down...");
                        cleanup();
                        break;
                default:
                        LOG_WARN("Ignoring unknown signal '%d'", sig);
                        return;
        }

        exit(sig);
}

/* Perform end of run tasks and prepare to exit gracefully */
void cleanup() {
        struct pcap_stat pkt_stats;
        float run_time;

#ifdef PCAP_BREAKLOOP
        pcap_breakloop(pcap_hnd);
#endif

        /* Print capture/parsing statistics when available */
        if (pcap_hnd && !use_infile) {
                if (pcap_stats(pcap_hnd, &pkt_stats) != 0) {
                        WARN("Cannot obtain packet capture statistics: %s", pcap_geterr(pcap_hnd));
                } else {
                        run_time = (float) (time(0) - start_time);

#ifdef DEBUG
        ASSERT(run_time > 0);
#endif

                        LOG_PRINT("%d packets received, %d packets dropped, %d http packets parsed", \
                             pkt_stats.ps_recv, pkt_stats.ps_drop, num_parsed);
                        LOG_PRINT("%0.1f packets/min, %0.1f http packets/min", \
                             ((pkt_stats.ps_recv * 60) / run_time), ((num_parsed * 60) / run_time));
                }
        } else if (pcap_hnd) {
                PRINT("%d http packets parsed", num_parsed);
        }

        fflush(NULL);

        free_format();
        if (buf) free(buf);

        /* Note that this won't get removed if we've switched to a
           user that doesn't have permission to delete the file */
        if (daemon_mode) remove(PID_FILE);
        if (pcap_hnd) pcap_close(pcap_hnd);

        return;
}

/* Display program help/usage information */
void display_usage() {
        PRINT("%s version %s", PROG_NAME, PROG_VER);
        PRINT("Usage: %s [-dhp] [-f filter] [-i device] [-n count] [-o file]\n"
              "              [-r file] [-s format] [-u user]\n", PROG_NAME);

        PRINT("  -d           run as daemon\n"
              "  -f filter    libpcap style capture filter\n"
              "  -h           print help information\n"
              "  -i device    set interface to listen on\n"
              "  -n count     number of HTTP packets to parse\n"
              "  -o file      write output log file\n"
              "  -p           disable promiscuous mode\n"
              "  -r file      input file to read from\n"
              "  -s format    specify output format string\n"
              "  -u user      set process owner\n");

        PRINT("Additional information can be found at:\n"
              "    http://dumpsterventures.com/jason/httpry\n");

        exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
        int opt;
        extern char *optarg;

        signal(SIGINT, &handle_signal);

        /* Process command line arguments */
        while ((opt = getopt(argc, argv, "dhpf:i:n:o:r:s:u:")) != -1) {
                switch (opt) {
                        case 'd': daemon_mode = 1; break;
                        case 'f': capfilter = optarg; break;
                        case 'h': display_usage(); break;
                        case 'i': interface = optarg; break;
                        case 'n': parse_count = atoi(optarg);
                                  if (parse_count < 0) LOG_DIE("Invalid -n value");
                                  break;
                        case 'o': use_outfile = optarg; break;
                        case 'p': set_promisc = 0; break;
                        case 'r': use_infile = optarg; break;
                        case 's': out_format = optarg; break;
                        case 'u': new_user = optarg; break;
                        default: display_usage();
                }
        }

        /* Test for argument error and warning conditions */
        if (daemon_mode && !use_outfile)
                LOG_DIE("Daemon mode requires an output file");

        if (!capfilter) capfilter = default_capfilter;
        if (!out_format) out_format = default_format;
        parse_format_string(out_format);

        /* Prepare output file as necessary */
        if (use_outfile) {
                if (freopen(use_outfile, "a", stdout) == NULL)
                        LOG_DIE("Cannot reopen output stream to '%s'", use_outfile);

                printf("# %s version %s\n", PROG_NAME, PROG_VER);
                print_header_line();
        }

        pcap_hnd = prepare_capture(interface, set_promisc, use_infile, capfilter);

        if (daemon_mode) runas_daemon();
        if (new_user) change_user(new_user);

        if ((buf = malloc(BUFSIZ + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for packet data buffer");

        start_time = time(0);
        if (pcap_loop(pcap_hnd, -1, &parse_http_packet, NULL) < 0)
                LOG_DIE("Cannot read packets from interface: %s", pcap_geterr(pcap_hnd));

        cleanup();

        return EXIT_SUCCESS;
}
