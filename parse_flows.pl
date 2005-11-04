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

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "parse_flows.pl";
my $PROG_VER = "0.0.1";
my $SENDMAIL = "/usr/lib/sendmail -i -t";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %flow_info = ();
my @flow_data;
my @hitlist;
my $start_time; # Start tick for timing code
my $end_time;   # End tick for timing codet;

# Counters
my $total_line_cnt = 0;
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 99999;
my $flow_max_len = 0;
my $file_cnt = 0;
my $size_cnt = 0;
my $tagged_lines_cnt = 0;
my $tagged_flows_cnt = 0;

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
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);

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

                        if ($convert_hex) {
                                $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
                                $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
                        }

                        if ($curr_line =~ /^>>>/) { # Start of flow marker
                                $curr_line =~ /^>>> (.*)!(.*)!(.*)!(.*)/;
                                $flow_info{"ip"} = $1;
                                $flow_info{"length"} = $2;
                                $flow_info{"start_time"} = $3;
                                $flow_info{"end_time"} = $4;

                                @flow_data = ();
                                $tagged_lines_cnt = 0;

                                if ($flow_info{"length"} < $flow_min_len) {
                                        $flow_min_len = $flow_info{"length"};
                                }
                                if ($flow_info{"length"} > $flow_max_len) {
                                        $flow_max_len = $flow_info{"length"};
                                }
                                $flow_cnt++;
                                $flow_line_cnt += $flow_info{"length"};
                        } elsif ($curr_line =~ /^<<</) { # End of flow marker
                                if ($tagged_lines_cnt > 1) {
                                        $tagged_flows_cnt++;
                                        $flow_info{"tagged"} = $tagged_lines_cnt;

                                        &write_host_subfile($flow_info{"ip"}) if $host_detail;
                                        # Populate data hash for summary
                                }
                        } else {
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
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $key;
        my $subkey;
        my $count = 0;

        open(OUTFILE, ">$output_file") || die "\nError: Cannot open $output_file - $!\n";

        print OUTFILE "\n\nSUMMARY STATS\n\n";
        print OUTFILE "Generated:\t" . localtime() . "\n";
        print OUTFILE "Total files:\t$file_cnt\n";
        print OUTFILE "Total size:\t$size_cnt MB\n";
        print OUTFILE "Total lines:\t$total_line_cnt\n";
        print OUTFILE "Total time:\t".sprintf("%.2f", $end_time - $start_time)." secs\n";

        print OUTFILE "\n\nFLOW STATS\n\n";
        print OUTFILE "Count:\t$flow_cnt\n";
        print OUTFILE "Lines:\t$flow_line_cnt\n";
        print OUTFILE "Min/Max/Avg:\t$flow_min_len/$flow_max_len/";
        print OUTFILE sprintf("%d", $flow_line_cnt / $flow_cnt)."\n";
        print OUTFILE "Tagged:\t$tagged_flows_cnt\n";

        close(OUTFILE);
}

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------
sub write_host_subfile {
        my $ip = shift;

        open(HOSTFILE, ">>$host_detail/$ip.txt") || die "\nError: cannot open $host_detail/$ip.txt - $!\n";

        foreach (@flow_data) {
                print HOSTFILE "$_\n";
        }
        print HOSTFILE '=' x 80 . "\n";

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
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('d:e:l:o:sx', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        &print_usage() unless ($ARGV[0]);

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $output_file = 0 unless ($output_file = $opts{o});
        $hitlist_file = 0 unless ($hitlist_file = $opts{l});
        $flows_summary = 0 unless ($flows_summary = $opts{s});
        $convert_hex = 0 unless ($convert_hex = $opts{x});
        $host_detail = 0 unless ($host_detail = $opts{d});
        $email_addr = 0 unless ($email_addr = $opts{e});

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                &print_usage();
        }

        # -d requires -l
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-hsx] [-l file] [-o file]
USAGE
}
