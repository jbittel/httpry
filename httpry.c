/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

*/

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
#include <sys/socket.h>
#include "config.h"
#include "error.h"
#include "format.h"
#include "methods.h"
#include "tcp.h"
#include "rate.h"

/* Function declarations */
int getopt(int, char * const *, const char *);
pcap_t *prepare_capture(char *interface, int promisc, char *filename, char *capfilter);
void set_link_offset(int header_type);
void open_outfiles();
void runas_daemon();
void change_user(char *name);
void parse_http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
int process_ip6_nh(const u_char *pkt, int size_ip, unsigned int caplen, unsigned int offset);
char *parse_header_line(char *header_line);
int parse_client_request(char *header_line);
int parse_server_response(char *header_line);
void handle_signal(int sig);
void cleanup();
void print_stats();
void display_banner();
void display_usage();

/* Program flags/options, set by arguments or config file */
static unsigned int parse_count = 0;
static int daemon_mode = 0;
static int eth_skip_bits = 0;
static char *use_infile = NULL;
static char *interface = NULL;
static char *capfilter = NULL;
static char *use_outfile = NULL;
static int set_promisc = 1;
static char *pid_filename = NULL;
static char *new_user = NULL;
static char *format_str = NULL;
static char *methods_str = NULL;
static char *use_dumpfile = NULL;
static int rate_stats = 0;
static int rate_interval = DEFAULT_RATE_INTERVAL;
static int rate_threshold = DEFAULT_RATE_THRESHOLD;
static int force_flush = 0;
int quiet_mode = 0;               /* Defined as extern in error.h */
int use_syslog = 0;               /* Defined as extern in error.h */

static pcap_t *pcap_hnd = NULL;   /* Opened pcap device handle */
static char *buf = NULL;
static unsigned int num_parsed = 0;      /* Count of fully parsed HTTP packets */
static time_t start_time = 0;      /* Start tick for statistics calculations */
static int link_offset = 0;
static pcap_dumper_t *dumpfile = NULL;
static char default_capfilter[] = DEFAULT_CAPFILTER;
static char default_format[] = DEFAULT_FORMAT;
static char rate_format[] = RATE_FORMAT;
static char default_methods[] = DEFAULT_METHODS;

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

                pcap_hnd = pcap_open_live(dev, BUFSIZ, promisc, 1000, errbuf);

                if (pcap_hnd == NULL)
                        LOG_DIE("Cannot open live capture on '%s': %s", dev, errbuf);
        } else {
                /* Reading from a saved capture, so open file */
                pcap_hnd = pcap_open_offline(filename, errbuf);

                if (pcap_hnd == NULL)
                        LOG_DIE("Cannot open saved capture file: %s", errbuf);
        }

        set_link_offset(pcap_datalink(pcap_hnd));

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
void set_link_offset(int header_type) {

#ifdef DEBUG
        ASSERT(header_type >= 0);
#endif

        switch (header_type) {
                case DLT_EN10MB:
                        link_offset = 14;
                        break;
#ifdef DLT_IEEE802_11
                case DLT_IEEE802_11:
                        link_offset = 32;
                        break;
#endif
#ifdef DLT_LINUX_SLL
                case DLT_LINUX_SLL:
                        link_offset = 16;
                        break;
#endif
#ifdef DLT_LOOP
                case DLT_LOOP:
                        link_offset = 4;
                        break;
#endif
                case DLT_NULL:
                        link_offset = 4;
                        break;
                case DLT_RAW:
                        link_offset = 0;
                        break;
                case DLT_PPP:
                        link_offset = 4;
                        break;
#ifdef DLT_PPP_SERIAL
                case DLT_PPP_SERIAL:
#endif
                case DLT_PPP_ETHER:
                        link_offset = 8;
                        break;
                default:
                        LOG_DIE("Unsupported datalink type: %s", pcap_datalink_val_to_name(header_type));
                        break;
        }

        return;
}

/* Open any requested output files */
void open_outfiles() {
        /* Redirect stdout to the specified output file if requested */
        if (use_outfile) {
                if (daemon_mode && (use_outfile[0] != '/'))
                        LOG_WARN("Output file path is not absolute and may be inaccessible after daemonizing");

                if (freopen(use_outfile, "a", stdout) == NULL)
                        LOG_DIE("Cannot reopen output stream to '%s'", use_outfile);

                PRINT("Writing output to file: %s", use_outfile);

                printf("# %s version %s\n", PROG_NAME, PROG_VER);
                print_format_list();
        }

        /* Open pcap binary capture file if requested */
        if (use_dumpfile) {
                if (daemon_mode && (use_dumpfile[0] != '/'))
                        LOG_WARN("Binary capture file path is not absolute and may be inaccessible after daemonizing");

                if ((dumpfile = pcap_dump_open(pcap_hnd, use_dumpfile)) == NULL)
                        LOG_DIE("Cannot open binary dump file '%s'", use_dumpfile);
                PRINT("Writing binary dump file: %s", use_dumpfile);
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

        /* Create PID file */
        if (pid_filename[0] != '/')
                LOG_WARN("PID file path is not absolute and may be inaccessible after daemonizing");
        if ((pid_file = fopen(pid_filename, "w"))) {
                fprintf(pid_file, "%d", getpid());
                fclose(pid_file);
        } else {
                LOG_WARN("Cannot open PID file '%s'", pid_filename);
        }

        signal(SIGCHLD, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
        signal(SIGTTIN, SIG_IGN);
        signal(SIGTERM, &handle_signal);

        fflush(NULL);

        return;
}

/* Change process owner to specified username */
void change_user(char *name) {
        struct passwd *user = NULL;

#ifdef DEBUG
        ASSERT(name);
#endif

        if ((getuid() != 0) && (geteuid() != 0))
                LOG_DIE("You must be root to switch users");

        if (!(user = getpwnam(name)))
                LOG_DIE("User '%s' not found in system", name);

        /* Change ownership of output files before we drop privs */
        if (use_outfile) {
                if (chown(use_outfile, user->pw_uid, user->pw_gid) < 0)
                        LOG_WARN("Cannot change ownership of output file '%s'", use_outfile);
        }

        if (use_dumpfile) {
                if (chown(use_dumpfile, user->pw_uid, user->pw_gid) < 0)
                        LOG_WARN("Cannot change ownership of dump file '%s'", use_dumpfile);
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
        char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
        char sport[PORTSTRLEN], dport[PORTSTRLEN];
        char ts[MAX_TIME_LEN], fmt[MAX_TIME_LEN];
        int is_request = 0, is_response = 0;
        unsigned int eth_type = 0, offset;

        const struct eth_header *eth;
        const struct ip_header *ip;
        const struct ip6_header *ip6;
        const struct tcp_header *tcp;
        const char *data;
        int size_ip, size_tcp, size_data, family;

        /* Check the ethernet type and insert a VLAN offset if necessary */
        eth = (struct eth_header *) pkt;
        eth_type = ntohs(eth->ether_type);
        if (eth_type == ETHER_TYPE_VLAN) {
                offset = link_offset + 4;
        } else {
                offset = link_offset;
        }

        offset += eth_skip_bits;

        /* Position pointers within packet stream and do sanity checks */
        ip = (struct ip_header *) (pkt + offset);
        ip6 = (struct ip6_header *) (pkt + offset);

        switch (IP_V(ip)) {
                case 4: family = AF_INET; break;
                case 6: family = AF_INET6; break;
                default: return;
        }

        if (family == AF_INET) {
                size_ip = IP_HL(ip) * 4;
                if (size_ip < 20) return;
                if (ip->ip_p != IPPROTO_TCP) return;
        } else { /* AF_INET6 */
                size_ip = sizeof(struct ip6_header);
                if (ip6->ip6_nh != IPPROTO_TCP)
                        size_ip = process_ip6_nh(pkt, size_ip, header->caplen, offset);
                if (size_ip < 40) return;
        }

        tcp = (struct tcp_header *) (pkt + offset + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20) return;

        data = (char *) (pkt + offset + size_ip + size_tcp);
        size_data = (header->caplen - (offset + size_ip + size_tcp));
        if (size_data <= 0) return;

        /* Check if we appear to have a valid request or response */
        if (is_request_method(data)) {
                is_request = 1;
        } else if (strncmp(data, HTTP_STRING, strlen(HTTP_STRING)) == 0) {
                is_response = 1;
        } else {
                return;
        }

        /* Copy packet data to editable buffer that was created in main() */
        if (size_data > BUFSIZ) size_data = BUFSIZ;
        memcpy(buf, data, size_data);
        buf[size_data] = '\0';

        /* Parse header line, bail if malformed */
        if ((header_line = parse_header_line(buf)) == NULL) return;

        if (is_request) {
                if (parse_client_request(header_line)) return;
        } else if (is_response) {
                if (parse_server_response(header_line)) return;
        }

        /* Iterate through request/entity header fields */
        while ((header_line = parse_header_line(NULL)) != NULL) {
                if ((req_value = strchr(header_line, ':')) == NULL) continue;
                *req_value++ = '\0';
                while (isspace(*req_value)) req_value++;

                insert_value(header_line, req_value);
        }

        /* Grab source/destination IP addresses */
        if (family == AF_INET) {
                inet_ntop(family, &ip->ip_src, saddr, sizeof(saddr));
                inet_ntop(family, &ip->ip_dst, daddr, sizeof(daddr));
        } else { /* AF_INET6 */
                inet_ntop(family, &ip6->ip_src, saddr, sizeof(saddr));
                inet_ntop(family, &ip6->ip_dst, daddr, sizeof(daddr));
        }
        insert_value("source-ip", saddr);
        insert_value("dest-ip", daddr);

        /* Grab source/destination ports */
        snprintf(sport, PORTSTRLEN, "%d", ntohs(tcp->th_sport));
        snprintf(dport, PORTSTRLEN, "%d", ntohs(tcp->th_dport));
        insert_value("source-port", sport);
        insert_value("dest-port", dport);

        /* Extract packet capture time */
        pkt_time = localtime((time_t *) &header->ts.tv_sec);
        strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M:%S.%%03u", pkt_time);
        snprintf(ts, sizeof(ts), fmt, header->ts.tv_usec / 1000);
        insert_value("timestamp", ts);

        if (rate_stats) {
                update_host_stats(get_value("host"), header->ts.tv_sec);
                clear_values();
        } else {
                print_format_values();
        }

        if (dumpfile)
                pcap_dump((unsigned char *) dumpfile, header, pkt);

        num_parsed++;
        if (parse_count && (num_parsed >= parse_count))
                pcap_breakloop(pcap_hnd);

        return;
}

/* Iterate through IPv6 extension headers looking for a TCP header. Returns
   the total size of the IPv6 header, including all extension headers.
   Return 0 to abort processing of this packet. */
int process_ip6_nh(const u_char *pkt, int size_ip, unsigned int caplen, unsigned int offset) {
        const struct ip6_ext_header *ip6_eh;
        unsigned int len = caplen - offset;
        ip6_eh = (struct ip6_ext_header *) (pkt + offset + size_ip);

        while (ip6_eh->ip6_eh_nh != IPPROTO_TCP) {
                switch (ip6_eh->ip6_eh_nh) {
                        case 0:  /* Hop-by-hop options */
                        case 43: /* Routing */
                        case 44: /* Fragment */
                        case 51: /* Authentication Header */
                        case 50: /* Encapsulating Security Payload */
                        case 60: /* Destination Options */
                                size_ip = size_ip + (ip6_eh->ip6_eh_len * 8) + 8;
                                break;
                        case 59: /* No next header */
                        default:
                                return 0;
                }

                if (size_ip > len) return 0;

                ip6_eh = (struct ip6_ext_header *) (pkt + offset + size_ip);
        }

        /* Next header is TCP, so increment past the final extension header */
        size_ip = size_ip + (ip6_eh->ip6_eh_len * 8) + 8;

        return size_ip;
}

/* Tokenize a HTTP header into lines; the first call should pass the string
   to tokenize, all subsequent calls for the same string should pass NULL */
char *parse_header_line(char *header_line) {
        static char *pos;
        char *tmp;

        if (header_line) pos = header_line;

        /* Search for a '\n' line terminator, ignoring a leading
           '\r' if it exists (per RFC2616 section 19.3) */
        tmp = strchr(pos, '\n');
        if (!tmp && header_line) {
                return header_line;
        } else if (!tmp) {
                return NULL;
        }
        *tmp = '\0';
        if (*(tmp - 1) == '\r') *(--tmp) = '\0';

        if (tmp == pos) return NULL; /* Reached the end of the header */

        header_line = pos;
        /* Increment past the '\0' character(s) inserted above */
        if (*tmp == '\0') {
                tmp++;
                if (*tmp == '\0') tmp++;
        }
        pos = tmp;

        return header_line;
}

/* Parse a HTTP client request; bail at first sign of an invalid request */
int parse_client_request(char *header_line) {
        char *method, *request_uri, *http_version;

#ifdef DEBUG
        ASSERT(header_line);
        ASSERT(strlen(header_line) > 0);
#endif

        method = header_line;

        if ((request_uri = strchr(method, ' ')) == NULL) return 1;
        *request_uri++ = '\0';
        while (isspace(*request_uri)) request_uri++;

        if ((http_version = strchr(request_uri, ' ')) != NULL) {
                *http_version++ = '\0';
                while (isspace(*http_version)) http_version++;
                if (strncmp(http_version, HTTP_STRING, strlen(HTTP_STRING)) != 0) return 1;
                insert_value("http-version", http_version);
        }

        insert_value("method", method);
        insert_value("request-uri", request_uri);
        insert_value("direction", ">");

        return 0;
}

/* Parse a HTTP server response; bail at first sign of an invalid response */
int parse_server_response(char *header_line) {
        char *http_version, *status_code, *reason_phrase;

#ifdef DEBUG
        ASSERT(header_line);
        ASSERT(strlen(header_line) > 0);
#endif

        http_version = header_line;

        if ((status_code = strchr(http_version, ' ')) == NULL) return 1;
        *status_code++ = '\0';
        while (isspace(*status_code)) status_code++;

        if ((reason_phrase = strchr(status_code, ' ')) == NULL) return 1;
        *reason_phrase++ = '\0';
        while (isspace(*reason_phrase)) reason_phrase++;

        insert_value("http-version", http_version);
        insert_value("status-code", status_code);
        insert_value("reason-phrase", reason_phrase);
        insert_value("direction", "<");

        return 0;
}

/* Handle signals for clean reloading or shutdown */
void handle_signal(int sig) {

#ifdef DEBUG
        ASSERT(sig > 0);
#endif

        switch (sig) {
                case SIGHUP:
                        LOG_PRINT("Caught SIGHUP, reloading...");
                        print_stats();
                        if (rate_stats)
                                cleanup_rate_stats();
                        open_outfiles();
                        if (rate_stats)
                                init_rate_stats(rate_interval, use_infile, rate_threshold);
                        return;
                case SIGINT:
                        LOG_PRINT("Caught SIGINT, shutting down...");
                        print_stats();
                        cleanup();
                        break;
                case SIGTERM:
                        LOG_PRINT("Caught SIGTERM, shutting down...");
                        print_stats();
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
        /* This may have already been called, but might not
           have depending on how we got here */
        if (pcap_hnd) pcap_breakloop(pcap_hnd);
        if (rate_stats) cleanup_rate_stats();

        fflush(NULL);

        free_format();
        free_methods();
        if (buf) free(buf);

        /* Note that this won't get removed if we've switched to a
           user that doesn't have permission to delete the file */
        if (daemon_mode) remove(pid_filename);
        if (pcap_hnd) pcap_close(pcap_hnd);

        return;
}

/* Print packet capture statistics */
void print_stats() {
        struct pcap_stat pkt_stats;
        float run_time;

        if (rate_stats)
                display_rate_stats(use_infile, rate_threshold);

        if (pcap_hnd && !use_infile) {
                if (pcap_stats(pcap_hnd, &pkt_stats) != 0) {
                        WARN("Cannot obtain packet capture statistics: %s", pcap_geterr(pcap_hnd));
                        return;
                }

                LOG_PRINT("%u packets received, %u packets dropped, %u http packets parsed", \
                     pkt_stats.ps_recv, pkt_stats.ps_drop, num_parsed);

                run_time = (float) (time(0) - start_time);
                if (run_time > 0) {
                        LOG_PRINT("%0.1f packets/min, %0.1f http packets/min", \
                             ((pkt_stats.ps_recv * 60) / run_time), ((num_parsed * 60) / run_time));
                }
        } else if (pcap_hnd) {
                PRINT("%u http packets parsed", num_parsed);
        }

        return;
}

/* Display startup/informational banner */
void display_banner() {
        PRINT("%s version %s -- "
              "HTTP logging and information retrieval tool", PROG_NAME, PROG_VER);
        PRINT("Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>");

        return;
}

/* Display program usage information */
void display_usage() {
        display_banner();

        printf("Usage: %s [ -dFhpqs ] [-b file ] [ -f format ] [ -i device ] [ -l threshold ]\n"
               "              [ -m methods ] [ -n count ] [ -o file ] [ -P file ] [ -r file ]\n"
               "              [ -t seconds] [ -u user ] [ 'expression' ]\n\n", PROG_NAME);

        printf("   -b file      write HTTP packets to a binary dump file\n"
               "   -d           run as daemon\n"
               "   -f format    specify output format string\n"
               "   -F           force output flush\n"
               "   -h           print this help information\n"
               "   -i device    listen on this interface\n"
               "   -l threshold specify a rps threshold for rate statistics\n"
               "   -m methods   specify request methods to parse\n"
               "   -n count     set number of HTTP packets to parse\n"
               "   -o file      write output to a file\n"
               "   -p           disable promiscuous mode\n"
               "   -P file      use custom PID filename when running in daemon mode \n"
               "   -q           suppress non-critical output\n"
               "   -r file      read packets from input file\n"
               "   -s           run in HTTP requests per second mode\n"
               "   -t seconds   specify the display interval for rate statistics\n"
               "   -u user      set process owner\n"
               "   expression   specify a bpf-style capture filter\n\n");

        printf("Additional information can be found at:\n"
               "   http://dumpsterventures.com/jason/httpry\n\n");

        exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
        int opt;
        extern char *optarg;
        extern int optind;
        int loop_status;

        signal(SIGHUP, &handle_signal);
        signal(SIGINT, &handle_signal);

        /* Process command line arguments */
        while ((opt = getopt(argc, argv, "b:df:Fhpqi:l:m:n:o:P:r:st:u:S:")) != -1) {
                switch (opt) {
                        case 'b': use_dumpfile = optarg; break;
                        case 'd': daemon_mode = 1; use_syslog = 1; break;
                        case 'f': format_str = optarg; break;
                        case 'F': force_flush = 1; break;
                        case 'h': display_usage(); break;
                        case 'i': interface = optarg; break;
                        case 'l': rate_threshold = atoi(optarg); break;
                        case 'm': methods_str = optarg; break;
                        case 'n': parse_count = atoi(optarg); break;
                        case 'o': use_outfile = optarg; break;
                        case 'p': set_promisc = 0; break;
                        case 'P': pid_filename = optarg; break;
                        case 'q': quiet_mode = 1; break;
                        case 'r': use_infile = optarg; break;
                        case 's': rate_stats = 1; break;
                        case 't': rate_interval = atoi(optarg); break;
                        case 'u': new_user = optarg; break;
                        case 'S': eth_skip_bits = atoi(optarg); break;
                        default: display_usage();
                }
        }

        display_banner();

        if (daemon_mode && !use_outfile)
                LOG_DIE("Daemon mode requires an output file");

        if (parse_count < 0)
                LOG_DIE("Invalid -n value, must be 0 or greater");

        if (rate_interval < 1)
                LOG_DIE("Invalid -t value, must be 1 or greater");

        if (rate_threshold < 1)
                LOG_DIE("Invalid -l value, must be 1 or greater");

        if (argv[optind] && *(argv[optind])) {
                capfilter = argv[optind];
        } else {
                capfilter = default_capfilter;
        }

        if (!format_str) format_str = default_format;
        if (rate_stats) format_str = rate_format;
        parse_format_string(format_str);

        if (!methods_str) methods_str = default_methods;
        parse_methods_string(methods_str);

        if (force_flush) {
                if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
                        LOG_WARN("Cannot disable buffering on stdout");
        }

        if (!pid_filename) pid_filename = PID_FILENAME;

        pcap_hnd = prepare_capture(interface, set_promisc, use_infile, capfilter);

        open_outfiles();

        if (daemon_mode) runas_daemon();
        if (new_user) change_user(new_user);

        if ((buf = malloc(BUFSIZ + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for packet data buffer");

        if (rate_stats)
                init_rate_stats(rate_interval, use_infile, rate_threshold);

        start_time = time(0);
        loop_status = pcap_loop(pcap_hnd, -1, &parse_http_packet, NULL);
        if (loop_status == -1) {
                LOG_DIE("Problem reading packets from interface: %s", pcap_geterr(pcap_hnd));
        } else if (loop_status == -2) {
                PRINT("Loop halted, shutting down...");
        }

        print_stats();
        cleanup();

        return loop_status == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}
