#!/usr/bin/perl -w

#
# parse_log.pl 6/25/2005
#
# Copyright (c) 2005, Jason Bittel. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use File::Basename;
use MIME::Lite;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "parse_log.pl";
my $PROG_VER = "0.0.5";
my $SENDMAIL = "/usr/lib/sendmail -i -t";
my $SUMMARY_CAP = 15; # Default value, can be overridden with -c

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %top_hosts = ();
my %top_talkers = ();
my %ip_hits = ();
my %host_hits = ();
my %filetypes = ();
my %content_hits = ();
my $total_line_cnt = 0;
my $line_cnt = 0;
my $ip_cnt = 0;
my $host_cnt = 0;
my $size_cnt = 0;
my $file_cnt = 0;
my $ext_cnt = 0;
my @hits;
my @hitlist;
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
my $host_detail;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&parse_logfiles();
&write_output_file();
if ($host_detail) {
        &write_host_subfiles();
}
if ($email_addr) {
        &send_email();
}

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
                                $ext_cnt++;
                                $filetypes{$1}++;
                        }

                        if ($log_summary) {
                                $line_cnt++;
                                $top_hosts{$hostname}++;
                                $top_talkers{$src_ip}++;
                        }

                        if ($check_ip && ($check_ip eq $src_ip)) {
                                $ip_cnt++;
                                $ip_hits{$hostname}++;
                        }

                        if ($check_host && ($check_host eq $hostname)) {
                                $host_cnt++;
                                $host_hits{$src_ip}++;
                        }

                        if ($hitlist_file) {
                                &content_check($hostname, $uri, \$curr_line);
                        }
                }

                close(INFILE);
        }
        $end_time = (times)[0];
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
                        push @hits, $$curr_line;
                }
        }
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $key;
        my $subkey;
        my $count = 0;

        open(OUTFILE, ">$output_file") || die "\nError: Cannot open $output_file - $!\n";

        if ($log_summary) {
                print OUTFILE "\n\nSUMMARY STATS\n\n";
                print OUTFILE "Total files:\t$file_cnt\n";
                print OUTFILE "Total size:\t$size_cnt MB\n";
                print OUTFILE "Total lines:\t$total_line_cnt\n";
                print OUTFILE "Total time:\t".sprintf("%.2f", $end_time - $start_time)." secs\n";

                if ($ignore_hosts) {
                        print OUTFILE "\nHOST IGNORING ACTIVE: Some output may be suppressed!\n";
                        print OUTFILE "SOURCE LIST: $ignore_file\n";
                }

                print OUTFILE "\n\nTOP $summary_cap VISITED HOSTS\n\n";
                foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                        print OUTFILE "$key\t$top_hosts{$key}\t".percent_of($top_hosts{$key}, $line_cnt)."%\n";
                        $count++;
                        last if ($count == $summary_cap);
                }

                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap TOP TALKERS\n\n";
                foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                        print OUTFILE "$key\t$top_talkers{$key}\t".percent_of($top_talkers{$key}, $line_cnt)."%\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ($filetype) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap FILE EXTENSIONS\n\n";
                foreach $key (sort { $filetypes{$b} <=> $filetypes{$a} } keys %filetypes) {
                        print OUTFILE "$key\t$filetypes{$key}\t".percent_of($filetypes{$key}, $ext_cnt)."%\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ($check_host) {
                print OUTFILE "\n\nIP SUMMARY FOR $check_host\n\n";
                foreach $key (sort { $host_hits{$b} <=> $host_hits{$a} } keys %host_hits) {
                        print OUTFILE "$key\t$host_hits{$key}\t".percent_of($host_hits{$key}, $host_cnt)."%\n";
                }
        }

        if ($check_ip) {
                print OUTFILE "\n\nHOST SUMMARY FOR $check_ip\n\n";
                foreach $key (sort { $ip_hits{$b} <=> $ip_hits{$a} } keys %ip_hits) {
                        print OUTFILE "$key\t$ip_hits{$key}\t".percent_of($ip_hits{$key}, $ip_cnt)."%\n";
                }
        }

        if ($hitlist_file) {
                print OUTFILE "\n\nURI CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                if (scalar(@hits) > 0) {
                        &build_content_hits();

                        foreach $key (map $_->[0],
                                      sort {
                                              $a->[1] <=> $b->[1] or # Sort IPs in true numeric order
                                              $a->[2] <=> $b->[2] or
                                              $a->[3] <=> $b->[3] or
                                              $a->[4] <=> $b->[4]
                                      }
                                      map [$_, split /\./], keys %content_hits) {
                                print OUTFILE "$key\n";
                                foreach $subkey (sort keys %{ $content_hits{$key} }) {
                                        print OUTFILE "\t$subkey\t$content_hits{$key}->{$subkey}\n";
                                }
                                print OUTFILE "\n";
                        }
                } else {
                        print OUTFILE "No matching records found\n";
                }
        }

        close(OUTFILE);
}

# -----------------------------------------------------------------------------
# Build summary for all hosts tagged in content checks
# -----------------------------------------------------------------------------
sub build_content_hits {
        my $curr_line;
        my $src_ip;
        my $dst_hostname;
        my $key;
        my $subkey;

        # Build multi-dimensional hash of all hosts, hostnames and access counts
        foreach $curr_line (@hits) {
                my @records;

                @records = split(/$PATTERN/, $curr_line);
                $src_ip = $records[1];
                $dst_hostname = $records[3];

                $content_hits{$src_ip}->{$dst_hostname}++;
        }

        # Prune hash tree to remove all small and empty values
        foreach $key (keys %content_hits) {
                foreach $subkey (keys %{ $content_hits{$key} }) {
                        if ($content_hits{$key}->{$subkey} <= 2) {
                                delete $content_hits{$key}->{$subkey};
                        }
                }

                if (scalar keys(%{ $content_hits{$key} }) == 0) {
                        delete $content_hits{$key};
                }
        }
}

# -----------------------------------------------------------------------------
# Create subfile for each host tagged in content checks
# -----------------------------------------------------------------------------
sub write_host_subfiles {
        my $curr_line;
        my $key;

        foreach $key (keys %content_hits) {
                open(HOSTFILE, ">>$host_detail/$key.txt") || die "\nError: cannot open $host_detail/$key.txt - $!\n";

                foreach $curr_line (@hits) {
                        my @record;

                        @record = split(/$PATTERN/, $curr_line);
                        print HOSTFILE "$curr_line\n" if  ($record[1] eq $key);
                }

                close(HOSTFILE);
        }
}

# -----------------------------------------------------------------------------
# Send email to specified address and attach output file
# -----------------------------------------------------------------------------
sub send_email {
        my $output;
        my $msg;
        my $output_filename = basename($output_file);

        $msg = MIME::Lite->new(
                From    => 'admin@corban.edu',
                To      => "$email_addr",
                Subject => 'HTTPry Report - ' . localtime(),
                Type    => 'multipart/mixed'
                );

        $msg->attach(
                Type => 'TEXT',
                Data => 'HTTPry report for ' . localtime()
                );

        $msg->attach(
                Type        => 'TEXT',
                Path        => "$output_file",
                Filename    => "$output_filename",
                Disposition => 'attachment'
                );

        $msg->send('sendmail', $SENDMAIL) || die "\nError: Cannot send mail - $!\n";
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
        getopts('c:d:e:fg:i:l:o:st:h', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        &print_usage() unless ($ARGV[0]);

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $summary_cap = $SUMMARY_CAP unless ($summary_cap = $opts{c});
        $host_detail = 0 unless ($host_detail = $opts{d});
        $email_addr = 0 unless ($email_addr = $opts{e});
        $filetype = 0 unless ($filetype = $opts{f});
        $ignore_file = 0 unless ($ignore_file = $opts{g});
        $check_ip = 0 unless ($check_ip = $opts{i});
        $hitlist_file = 0 unless ($hitlist_file = $opts{l});
        $output_file = 0 unless ($output_file = $opts{o});
        $log_summary = 0 unless ($log_summary = $opts{s});
        $check_host = 0 unless ($check_host = $opts{t});

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                &print_usage();
        }
        if (!$hitlist_file && $host_detail) {
                print "\nError: cannot build host detail files without hitlist file\n";
                &print_usage();
        }
        if (!$log_summary && !$hitlist_file && !$check_ip && !$check_host && !$filetype) {
                print "\nError: no processing option selected\n";
                &print_usage();
        }
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-fhs] [-c count] [-d dir] [-e email] [-g file]
        [-i ip] [-l file] [-o file] [-t hostname] [input files]
USAGE
}
