#!/usr/bin/perl -w

#
# parse_flows.pl 11/2/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "parse_flows.pl";
my $PROG_VER = "0.0.2";
my $SENDMAIL = "/usr/lib/sendmail -i -t";
my $TAGGED_LIMIT = 5;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %content_hits = (); # Summary of all tagged flows
my @flow_data;
my @hitlist;
my $start_time; # Start tick for timing code
my $end_time;   # End tick for timing codet;

# Counters
my $total_line_cnt = 0;
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 999999;
my $flow_max_len = 0;
my $file_cnt = 0;
my $size_cnt = 0;
my $tagged_lines_cnt = 0;
my $tagged_flows_cnt = 0;
my $total_tagged_lines_cnt = 0;

# Command line arguments
my %opts;
my @input_files;
my $output_file;
my $hitlist_file;
my $flows_summary;
my $convert_hex;
my $host_detail;
my $email_addr;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&parse_flows();
&write_summary_file() if $flows_summary;

# -----------------------------------------------------------------------------
# Core parsing engine, processes all input files based on options provided
# -----------------------------------------------------------------------------
sub parse_flows {
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);   # Log record fields
        my ($ip, $flow_len, $start_time, $end_time, $tagged); # Flow detail information

        if ($hitlist_file) {
                open(HITLIST, "$hitlist_file") || die "\nError: Cannot open $hitlist_file - $!\n";
                        @hitlist = <HITLIST>;
                close(HITLIST);
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

                        if ($curr_line =~ /^>>> (.*)!(.*)!(.*)!(.*) >/) { # Start of flow marker
                                $ip = $1;
                                $flow_len = $2;
                                $start_time = $3;
                                $end_time = $4;

                                # Set up variables for new flow
                                @flow_data = ();
                                $tagged_lines_cnt = 0;
                                $flow_cnt++;
                                $flow_line_cnt += $flow_len;

                                # Set minimum/maximum flow length
                                if ($flow_len < $flow_min_len) {
                                        $flow_min_len = $flow_len;
                                }
                                if ($flow_len > $flow_max_len) {
                                        $flow_max_len = $flow_len;
                                }
                        } elsif ($curr_line =~ /^<<</) { # End of flow marker
                                if ($tagged_lines_cnt > $TAGGED_LIMIT) {
                                        $tagged_flows_cnt++;
                                        $total_tagged_lines_cnt += $tagged_lines_cnt;
                                        $tagged = $tagged_lines_cnt;

                                        &write_host_subfile($ip) if $host_detail;
                                        push(@{$content_hits{$ip}}, "[$start_time]->[$end_time] ($flow_len/$tagged_lines_cnt)");
                                }
                        } else { # Flow data line
                                if ($convert_hex) {
                                        $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
                                        $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
                                }

                                push(@flow_data, $curr_line);

                                if ($hitlist_file) {
                                        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

                                        if (&content_check($hostname, $uri)) {
                                                $tagged_lines_cnt++;
                                        }
                                }
                        }
                }

                close(INFILE);
        }
        $end_time = (times)[0];
}

# -----------------------------------------------------------------------------
# Write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $key;
        my $flow;

        open(OUTFILE, ">$output_file") || die "\nError: Cannot open $output_file - $!\n";

        print OUTFILE "\n\nSUMMARY STATS\n\n";
        print OUTFILE "Generated:\t" . localtime() . "\n";
        print OUTFILE "Total files:\t$file_cnt\n";
        print OUTFILE "Total size:\t$size_cnt MB\n";
        print OUTFILE "Total lines:\t$total_line_cnt\n";
        print OUTFILE "Total time:\t" . sprintf("%.2f", $end_time - $start_time) . " secs\n";

        print OUTFILE "\n\nFLOW STATS\n\n";
        print OUTFILE "Flow count:\t$flow_cnt\n";
        print OUTFILE "Flow lines:\t$flow_line_cnt\n";
        print OUTFILE "Min/Max/Avg:\t$flow_min_len/$flow_max_len/" . sprintf("%d", $flow_line_cnt / $flow_cnt) . "\n";
        print OUTFILE "Tagged flows:\t$tagged_flows_cnt\n";
        print OUTFILE "Tagged lines:\t$total_tagged_lines_cnt\n";

        if ($hitlist_file) {
                print OUTFILE "\n\nFLOW CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                if ($total_tagged_lines_cnt > 0) {
                        foreach $key (map { inet_ntoa $_ }
                                      sort
                                      map { inet_aton $_ } keys %content_hits) {
                                print OUTFILE "$key\n";
                                foreach $flow (@{$content_hits{$key}}) {
                                        print OUTFILE "\t$flow\n";
                                }
                                print OUTFILE "\n";
                        }
                } else {
                        print OUTFILE "No tagged flows found\n";
                }
        }

        close(OUTFILE);
}

# -----------------------------------------------------------------------------
# Write detail subfile for specified client ip
# -----------------------------------------------------------------------------
sub write_host_subfile {
        my $ip = shift;

        open(HOSTFILE, ">>$host_detail/$ip.txt") || die "\nError: cannot open $host_detail/$ip.txt - $!\n";

        print HOSTFILE '>' x 80 . "\n";
        foreach (@flow_data) {
                print HOSTFILE "$_\n";
        }
        print HOSTFILE '<' x 80 . "\n";

        close(HOSTFILE);
}

# -----------------------------------------------------------------------------
# Search fields for specified content; returns true if match occurs
# -----------------------------------------------------------------------------
sub content_check {
        my $hostname = shift;
        my $uri = shift;
        my $word;

        $hostname = quotemeta($hostname);
        $uri = quotemeta($uri);
        foreach $word (@hitlist) {
                chomp $word;
                if (($hostname =~ /$word/i) || ($uri =~ /$word/i)) {
                        return 1;
                }
        }

        return 0;
}

# -----------------------------------------------------------------------------
# Send email to specified address and attach output file
# -----------------------------------------------------------------------------
sub send_email {
        my $msg;
        my $output_filename = basename($output_file);

        $msg = MIME::Lite->new(
                From    => 'admin@corban.edu',
                To      => "$email_addr",
                Subject => 'HTTPry Flow Report - ' . localtime(),
                Type    => 'multipart/mixed'
                );

        $msg->attach(
                Type => 'TEXT',
                Data => 'HTTPry flow report for ' . localtime()
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
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('d:e:l:o:sx', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        &print_usage() unless ($ARGV[0]);

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $host_detail = 0 unless ($host_detail = $opts{d});
        $email_addr = 0 unless ($email_addr = $opts{e});
        $hitlist_file = 0 unless ($hitlist_file = $opts{l});
        $output_file = 0 unless ($output_file = $opts{o});
        $flows_summary = 0 unless ($flows_summary = $opts{s});
        $convert_hex = 0 unless ($convert_hex = $opts{x});

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                &print_usage();
        }
        if ($host_detail && !$hitlist_file) {
                print "\nWarning: -d requires -l, ignoring\n";
                $host_detail = 0;
        }
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-hsx] [-d dir] [-l file] [-o file] [input files]
USAGE
}
