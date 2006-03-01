#!/usr/bin/perl -w

#
# content_check.pl 2/16/2006
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "content_check.pl";
my $PROG_VER = "0.0.1";
my $SENDMAIL = "/usr/lib/sendmail -i -t";
my $FLOW_TIMEOUT = 300;
my $FLOW_DISCARD = 10;
my $TAGGED_LIMIT = 5;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %opts = ();
my @input_files = ();
my $host_detail;
my $email_addr;
my $hitlist_file;
my $output_file;
my $flows_summary;
my $start_time; # Start tick for timing code
my $end_time;   # End tick for timing code

# Counter variables
my $file_cnt = 0;
my $size_cnt = 0;
my $total_line_cnt = 0;
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 999999;
my $flow_max_len = 0;
my $tagged_flows_cnt = 0;
my $total_tagged_lines_cnt = 0;

# Data structures
my %flow_info = ();       # Holds metadata about each flow
my %flow_data_lines = (); # Holds actual log file lines for each flow
my %tagged_flows = ();    # Ip/flow/hostname information for tagged flows
my %output_flows = ();    # Pruned and cleaned tagged flows for display
my @hitlist = ();

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&parse_flows();
&write_summary_file() if $flows_summary;
&send_email() if $email_addr;

# -----------------------------------------------------------------------------
# Break input log files into flows and perform content checks
# -----------------------------------------------------------------------------
sub parse_flows {
        my $curr_line;
        my $curr_file;
        my $flow_key;
        my ($timestamp, $epochstamp, $src_ip, $dst_ip, $hostname, $uri);

        $start_time = (times)[0];
        foreach $curr_file (@input_files) {
                unless(open(INFILE, "$curr_file")) {
                        print "\nWarning: skipping $curr_file: $!\n";
                        next;
                }

                $file_cnt++;
                $size_cnt += int((stat(INFILE))[7] / 1000000);

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ tr/\x80-\xFF//d; # Strip non-printable chars

                        # Convert hex characters to ASCII
                        $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
                        $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

                        next if $curr_line eq "";
                        $total_line_cnt++;

                        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

                        # Convert timestamp of current record to epoch seconds
                        $timestamp =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
                        $epochstamp = timelocal($6, $5, $4, $2, $1 - 1, $3);

                        if (!exists $flow_info{$src_ip}) {
                                $flow_cnt++;
                                $flow_line_cnt++;

# TODO: convert %flow_info to a hash of lists

                                $flow_info{$src_ip}->{"id"} = $flow_cnt;
                                $flow_info{$src_ip}->{"src_ip"} = $src_ip;
                                $flow_info{$src_ip}->{"start_time"} = $timestamp;
                                $flow_info{$src_ip}->{"end_time"} = $timestamp;
                                $flow_info{$src_ip}->{"start_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"end_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"length"} = 1;
                                $flow_info{$src_ip}->{"tagged_lines"} = 0;

                                push(@{$flow_data_lines{$src_ip}}, $curr_line);

                                if ($hitlist_file && &content_check($hostname, $uri)) {
                                        $tagged_flows{$src_ip}->{$flow_info{$src_ip}->{"id"}}->{$hostname}++;
                                        $flow_info{$src_ip}->{"tagged_lines"}++;
                                }
                        } else {
                                $flow_line_cnt++;

                                $flow_info{$src_ip}->{"end_time"} = $timestamp;
                                $flow_info{$src_ip}->{"end_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"length"}++;

                                push(@{$flow_data_lines{$src_ip}}, $curr_line);

                                if ($hitlist_file && &content_check($hostname, $uri)) {
                                        $tagged_flows{$src_ip}->{$flow_info{$src_ip}->{"id"}}->{$hostname}++;
                                        $flow_info{$src_ip}->{"tagged_lines"}++;
                                }
                        }

                        &timeout_flow($flow_key, $epochstamp);
                }
        }
        $end_time = (times)[0];

        return;
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
# Handle end of flow duties: flush to disk and delete hash entries
# -----------------------------------------------------------------------------
sub timeout_flow {
        my $flow_key = shift;
        my $epochstamp = shift;
        my $flow_str;
        my $hostname;

        foreach $flow_key (keys %flow_info) {
                next unless (($epochstamp - $flow_info{$flow_key}->{"end_epoch"}) > $FLOW_TIMEOUT);

                # Set minimum/maximum flow length
                if ($flow_info{$flow_key}->{"length"} < $flow_min_len) {
                        $flow_min_len = $flow_info{$flow_key}->{"length"};
                }
                if ($flow_info{$flow_key}->{"length"} > $flow_max_len) {
                        $flow_max_len = $flow_info{$flow_key}->{"length"};
                }

                # Check if we have enough hits to be interested in the flow
                if ($flow_info{$flow_key}->{"tagged_lines"} > $TAGGED_LIMIT) {
                        $tagged_flows_cnt++;
                        $total_tagged_lines_cnt += $flow_info{$flow_key}->{"tagged_lines"};

                        # Copy data to output hash so we can prune and reformat
                        $flow_str = "[$flow_info{$flow_key}->{'start_time'}]->[$flow_info{$flow_key}->{'end_time'}]";
                        foreach $hostname (keys %{$tagged_flows{$flow_key}->{$flow_info{$flow_key}->{"id"}}}) {
                                $output_flows{$flow_key}->{$flow_str}->{$hostname} = $tagged_flows{$flow_key}->{$flow_info{$flow_key}->{"id"}}->{$hostname};
                        }
                        delete $tagged_flows{$flow_key};

                        &append_host_subfile("$host_detail/detail_$flow_key.txt", $flow_key) if $host_detail;
                } else {
                        # Not an interesting flow, but delete any tagged lines that do exist
                        delete $tagged_flows{$flow_key}->{$flow_info{$flow_key}->{"id"}} if exists $tagged_flows{$flow_key};
                        delete $tagged_flows{$flow_key} if (keys %{$tagged_flows{$flow_key}} == 0);
                }

                delete $flow_info{$flow_key};
                delete $flow_data_lines{$flow_key};
        }

        return;
}

# -----------------------------------------------------------------------------
# Write detail subfile for specified client ip
# -----------------------------------------------------------------------------
sub append_host_subfile {
        my $path = shift;
        my $flow_key = shift;

        open(HOSTFILE, ">>$path") || die "\nError: cannot open $path - $!\n";

        print HOSTFILE '>' x 80 . "\n";
        foreach (@{$flow_data_lines{$flow_key}}) {
                print HOSTFILE $_, "\n";
        }
        print HOSTFILE '<' x 80 . "\n";

        close(HOSTFILE);

        return;
}

# -----------------------------------------------------------------------------
# Write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $ip;
        my $flow;
        my $hostname;

        open(OUTFILE, ">$output_file") || die "\nError: Cannot open $output_file: $!\n";

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

        if ($hitlist_file) {
                print OUTFILE "Tagged IPs:\t" . (keys %tagged_flows) . "\n";
                print OUTFILE "Tagged flows:\t$tagged_flows_cnt\n";
                print OUTFILE "Tagged lines:\t$total_tagged_lines_cnt\n";
                print OUTFILE "\n\nFLOW CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                if ($total_tagged_lines_cnt > 0) {
                        foreach $ip (map { inet_ntoa $_ }
                                     sort
                                     map { inet_aton $_ } keys %output_flows) {
                                print OUTFILE "$ip\n";
                                foreach $flow (sort keys %{$output_flows{$ip}}) {
                                        print OUTFILE "\t$flow\n";

                                        foreach $hostname (sort keys %{$output_flows{$ip}->{$flow}}) {
                                                print OUTFILE "\t\t$hostname\t$output_flows{$ip}->{$flow}->{$hostname}\n";
                                        }
                                }
                                print OUTFILE "\n";
                        }
                } else {
                        print OUTFILE "No tagged flows found\n";
                }
        }

        close(OUTFILE);

        return;
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
                Subject => 'HTTPry Content Check Report - ' . localtime(),
                Type    => 'multipart/mixed'
                );

        $msg->attach(
                Type => 'TEXT',
                Data => 'HTTPry content check report for ' . localtime()
                );

        $msg->attach(
                Type        => 'TEXT',
                Path        => "$output_file",
                Filename    => "$output_filename",
                Disposition => 'attachment'
                );

        $msg->send('sendmail', $SENDMAIL) || die "\nError: Cannot send mail: $!\n";

        return;
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('d:e:l:o:s', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "\nError: no input file(s) provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $host_detail = 0 unless ($host_detail = $opts{d});
        $email_addr = 0 unless ($email_addr = $opts{e});
        $hitlist_file = 0 unless ($hitlist_file = $opts{l});
        $output_file = 0 unless ($output_file = $opts{o});
        $flows_summary = 0 unless ($flows_summary = $opts{s});

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                &print_usage();
        }
        if ($host_detail && !$hitlist_file) {
                print "\nWarning: -d requires -l, ignoring\n";
                $host_detail = 0;
        }

        # Read in option files
        if ($hitlist_file) {
                open(HITLIST, "$hitlist_file") || die "\nError: Cannot open $hitlist_file: $!\n";
                        @hitlist = <HITLIST>;
                close(HITLIST);
        }

        return;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-hs] [-d dir] [-e email] [-l file] [-o file] [input files]
USAGE
}
