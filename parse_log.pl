#!/usr/bin/perl -w

#
# parse_log.pl 6/25/2005
#
# Copyright (c) 2005, Jason Bittel. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use MIME::Lite;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "parse_log.pl";
my $PROG_VER = "0.0.4";
my $SENDMAIL = '/usr/lib/sendmail -i -t';
my $SUMMARY_CAP = 15; # Default value, can be overridden with -c

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %top_hosts;
my %top_talkers;
my %ip_hits;
my %host_hits;
my %filetypes;
my $total_line_cnt = 0;
my $line_cnt = 0;
my $ip_cnt = 0;
my $host_cnt = 0;
my $size_cnt = 0;
my $file_cnt = 0;
my $ext_cnt = 0;
my @hits;
my @hitlist;
my @output_data;
my $ignore_hosts = "";
my $summary_cap;
my $start_time;  # Start tick for timing code
my $end_time;    # End tick for timing code

# Command line arguments
my %opts;
my $email_addr;
my $check_ip;
my $filetype;
my $check_host;
my $log_summary;
my $hitlist_file;
my $ignore_file;
my $output_file;
my @input_files;
my $extended_hosts;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&parse_logfiles();
&generate_output();
&print_output();

# -----------------------------------------------------------------------------
# Core engine, parses all input file based on options provided
# -----------------------------------------------------------------------------
sub parse_logfiles {
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);

        if ($hitlist_file) {
                open(HITLIST, "$hitlist_file") || die "\nError: Cannot open $hitlist_file - $!\n";
                        @hitlist = <HITLIST>;
                close(HITLIST);
        }

        if ($ignore_file) {
                open(IGNORE, "$ignore_file") || die "\nError: Cannot open $ignore_file - $!\n";
                        while (<IGNORE>) {
                                chomp;
                                if (!$ignore_hosts) {
                                        $ignore_hosts .= $_;
                                } else {
                                        $ignore_hosts .= " $_";
                                }
                        }
                close(IGNORE);
        }

        $start_time = (times)[0];
        foreach $curr_file (@input_files) {
                unless(open(INFILE, "$curr_file")) {
                        print "\nError: Cannot open $curr_file - $!\n";
                        next;
                }

                $file_cnt++;
                $size_cnt += int((stat(INFILE))[7] / 1000000);

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ tr/\x80-\xFF//d; # Strip non-printable chars
                        next if $curr_line eq "";
                        $total_line_cnt++;

                        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

                        next if (!$hostname or !$src_ip or !$uri);

                        if ($ignore_hosts) {
                                next if ($ignore_hosts =~ /$src_ip/);
                        }

                        if ($filetype && ($uri =~ /\.(\w{3,4}?)$/)) {
                                filetype_check($1);
                        }

                        if ($log_summary) {
                                &do_summary($hostname, $src_ip);
                        }

                        if ($check_ip && ($check_ip eq $src_ip)) {
                                &ip_check($hostname);
                        }

                        if ($check_host && ($check_host eq $hostname)) {
                                &host_check($src_ip);
                        }

                        if ($hitlist_file) {
                                &content_check($hostname, $uri, $curr_line);
                        }
                }

                close(INFILE);
        }
        $end_time = (times)[0];
}

# -----------------------------------------------------------------------------
# Collect summary information on logfile
# -----------------------------------------------------------------------------
sub do_summary {
        my $hostname = shift;
        my $src_ip = shift;

        $line_cnt++; # Increment line counter

        if (exists($top_hosts{$hostname})) {
                $top_hosts{$hostname} += 1;
        } else {
                $top_hosts{$hostname} = 1;
        }

        if (exists($top_talkers{$src_ip})) {
                $top_talkers{$src_ip} += 1;
        } else {
                $top_talkers{$src_ip} = 1;
        }
}

# -----------------------------------------------------------------------------
# Log all hosts a particular IP has visited
# -----------------------------------------------------------------------------
sub ip_check {
        my $hostname = shift;

        $ip_cnt++; # Increment IP counter

        if (exists($ip_hits{$hostname})) {
                $ip_hits{$hostname} += 1;
        } else {
                $ip_hits{$hostname} = 1;
        }
}

# -----------------------------------------------------------------------------
# Log all IPs that have visited a particular host
# -----------------------------------------------------------------------------
sub host_check {
        my $ip = shift;

        $host_cnt++; # Increment IP counter

        if (exists($host_hits{$ip})) {
                $host_hits{$ip} += 1;
        } else {
                $host_hits{$ip} = 1;
        }
}

# -----------------------------------------------------------------------------
# Search fields for offensive content
# -----------------------------------------------------------------------------
sub content_check {
        my $hostname = shift;
        my $uri = shift;
        my $curr_line = shift;
        my $word;

        $hostname = quotemeta($hostname);
        $uri = quotemeta($uri);
        foreach $word (@hitlist) {
                chomp $word;
                if (($hostname =~ /$word/i) || ($uri =~ /$word/i)) {
                        push @hits, $curr_line;
                }
        }
}

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------
sub filetype_check {
        my $extension = shift;

        $ext_cnt++;

        if (exists($filetypes{$extension})) {
                $filetypes{$extension} += 1;
        } else {
                $filetypes{$extension} = 1;
        }
}

# -----------------------------------------------------------------------------
# Build array of output data to prepare for printing
# -----------------------------------------------------------------------------
sub generate_output {
        my $key;
        my $i = 0;
        my $j = 0;

        if ($log_summary) {
                $output_data[$j++] = "\n\nSUMMARY STATS\n\n";
                $output_data[$j++] = "Total files:\t$file_cnt\n";
                $output_data[$j++] = "Total size:\t$size_cnt MB\n";
                $output_data[$j++] = "Total lines:\t$total_line_cnt\n";
                $output_data[$j++] = "Total time:\t".sprintf("%.2f", $end_time - $start_time)." secs\n";

                if ($ignore_hosts) {
                        $output_data[$j++] = "\nHOST IGNORING ACTIVE: Some output may be suppressed!\n";
                        $output_data[$j++] = "SOURCE LIST: $ignore_file\n";
                }

                $output_data[$j++] = "\n\nTOP $summary_cap VISITED HOSTS\n\n";
                foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                        $output_data[$j++] = "$key\t$top_hosts{$key}\t".percent_of($top_hosts{$key}, $line_cnt)."%\n";
                        $i++;
                        last if ($i == $summary_cap);
                }

                $i = 0;
                $output_data[$j++] = "\n\nTOP $summary_cap TOP TALKERS\n\n";
                foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                        $output_data[$j++] = "$key\t$top_talkers{$key}\t".percent_of($top_talkers{$key}, $line_cnt)."%\n";
                        $i++;
                        last if ($i == $summary_cap);
                }
        }

        if ($filetype) {
                $i = 0;
                $output_data[$j++] = "\n\nTOP $summary_cap FILE EXTENSIONS\n\n";
                foreach $key (sort { $filetypes{$b} <=> $filetypes{$a} } keys %filetypes) {
                        $output_data[$j++] = "$key\t$filetypes{$key}\t".percent_of($filetypes{$key}, $ext_cnt)."%\n";
                        $i++;
                        last if ($i == $summary_cap);
                }
        }

        if ($check_host) {
                $output_data[$j++] = "\n\nIP SUMMARY FOR $check_host\n\n";
                foreach $key (sort { $host_hits{$b} <=> $host_hits{$a} } keys %host_hits) {
                        $output_data[$j++] = "$key\t$host_hits{$key}\t".percent_of($host_hits{$key}, $host_cnt)."%\n";
                }
        }

        if ($check_ip) {
                $output_data[$j++] = "\n\nHOST SUMMARY FOR $check_ip\n\n";
                foreach $key (sort { $ip_hits{$b} <=> $ip_hits{$a} } keys %ip_hits) {
                        $output_data[$j++] = "$key\t$ip_hits{$key}\t".percent_of($ip_hits{$key}, $ip_cnt)."%\n";
                }
        }

        if ($hitlist_file) {
                $output_data[$j++] = "\n\nURI CONTENT CHECKS\n";
                $output_data[$j++] = "FILTER FILE: $hitlist_file\n\n";

                if (scalar(@hits) > 0) {
                        foreach (@hits) {
                               $output_data[$j++] = "$_\n";
                        }
                } else {
                        $output_data[$j++] = "No matching records found\n";
                }
        }
}

# -----------------------------------------------------------------------------
# Print output to correct medium/send email
# -----------------------------------------------------------------------------
sub print_output {
        my $output;
        my $curr_line;
        my $local_ip;
        my $msg;

        # Create a reference to output medium
        if ($output_file) {
                open(OUTFILE, ">$output_file") || die "\nError: Cannot open $output_file - $!\n";
                $output = *OUTFILE{IO};
        } else {
                $output = *STDOUT{IO};
        }
        foreach (@output_data) {
                print $output "$_";
        }
        if ($output_file) { close(OUTFILE); }

        # Create subfile for each host tagged in content checks
        if ($extended_hosts) {
                foreach $curr_line (@hits) {
                        my @records;

                        @records = split(/$PATTERN/, $curr_line);
                        $local_ip = $records[1];

                        open(HOSTFILE, ">>$extended_hosts/$local_ip.txt") || die "\nError: cannot open $extended_hosts/$local_ip.txt - $!\n";
                        print HOSTFILE "$curr_line\n";
                        close(HOSTFILE);
                }
        }

        # Send email if requested
        if ($email_addr && $output_file) {
                $msg = MIME::Lite->new(
                        From    =>'admin@corban.edu',
                        To      =>"$email_addr",
                        Subject =>'HTTPry Report - ' . localtime(),
                        Type    =>'multipart/mixed'
                        );

                $msg->attach(
                        Type =>'TEXT',
                        Data =>'HTTPry report for ' . localtime()
                        );

                $msg->attach(
                        Type        =>'TEXT',
                        Path        =>"$output_file",
                        Filename    =>"$output_file",
                        Disposition =>'attachment'
                        );

                open(EMAIL,"|$SENDMAIL") || die "\nError: Cannot open $SENDMAIL - $!\n";
                print $msg->as_string;
                close(EMAIL);
        } elsif ($email_addr && !$output_file) {
                my $email_body = "";

                foreach (@output_data) {
                        $email_body .= $_;
                }

                $msg = MIME::Lite->new(
                        From    =>'admin@corban.edu',
                        To      =>"$email_addr",
                        Subject =>'HTTPry Report - ' . localtime(),
                        Data    =>"$email_body"
                        );

                open(EMAIL,"|$SENDMAIL") || die "\nError: Cannot open $SENDMAIL - $!\n";
                print EMAIL $msg->as_string;
                close(EMAIL);
        }
}

# -----------------------------------------------------------------------------
# Calculate ratio information
# -----------------------------------------------------------------------------
sub percent_of {
        my $subset = shift;
        my $total = shift;

        return sprintf("%.1f", ($subset / $total) * 100);
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('c:e:fg:i:l:o:st:hx:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        &print_usage() unless ($ARGV[0]);

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $summary_cap = $SUMMARY_CAP unless ($summary_cap = $opts{c});
        $output_file = 0 unless ($output_file = $opts{o});
        $hitlist_file = 0 unless ($hitlist_file = $opts{l});
        $ignore_file = 0 unless ($ignore_file = $opts{g});
        $log_summary = 0 unless ($log_summary = $opts{s});
        $check_ip = 0 unless ($check_ip = $opts{i});
        $check_host = 0 unless ($check_host = $opts{t});
        $email_addr = 0 unless ($email_addr = $opts{e});
        $filetype = 0 unless ($filetype = $opts{f});
        $extended_hosts = 0 unless ($extended_hosts = $opts{x});

        if (!$hitlist_file && $extended_hosts) {
                $extended_hosts = 0;
        }

        if (!$log_summary && !$hitlist_file && !$check_ip && !$check_host && !$filetype) {
                print "\nError: no processing option selected!\n";
                &print_usage();
        }
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-fs] [-c count] [-l file] [-o file]
        [-e email] [-g file] [-x dir] [input files]
USAGE
}
