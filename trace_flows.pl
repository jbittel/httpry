#!/usr/bin/perl -w

#
# trace_flows.pl 10/25/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "trace_flows.pl";
my $PROG_VER = "0.0.2";
my $FLOW_TIMEOUT = 300; # Timeout for flows, in seconds
my $FLOW_DISCARD = 5; # Discard flows below this length

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %flow_info = ();
my %flow_data = ();

# Command line arguments
my %opts;
my @input_files;
my $output_file;
my $flow_timeout;
my $flow_discard;
my $flow_one2one;
my $flow_one2many;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
if (-e $output_file) { unlink $output_file };
&parse_flows();

# -----------------------------------------------------------------------------
# Core parsing engine, processes all input files based on options provided
# -----------------------------------------------------------------------------
sub parse_flows {
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);
        my $flow_key;
        my $key;
        my $epochstamp;

        foreach $curr_file (@input_files) {
                unless(open(INFILE, "$curr_file")) {
                        print "\nError: Cannot open $curr_file - $!\n";
                        next;
                }

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        next if $curr_line eq "";

                        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

                        # Determine the type of flow requested
                        if ($flow_one2many) {
                                $flow_key = $src_ip;
                        } elsif ($flow_one2one) {
                                $flow_key = $src_ip.'-'.$dst_ip;
                        }

                        # Convert timestamp of current record to epoch seconds
                        $timestamp =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
                        $epochstamp = timelocal($6, $5, $4, $2, $1 - 1, $3);

                        # Let's make magic happen here, baby
                        if (!exists $flow_info{$flow_key}) {
                                $flow_info{$flow_key}->{"src_ip"} = $src_ip;
                                $flow_info{$flow_key}->{"start_time"} = $timestamp;
                                $flow_info{$flow_key}->{"end_time"} = $timestamp;
                                $flow_info{$flow_key}->{"start_epoch"} = $epochstamp;
                                $flow_info{$flow_key}->{"end_epoch"} = $epochstamp;
                                $flow_info{$flow_key}->{"length"} = 1;

                                push(@{$flow_data{$flow_key}}, $curr_line);
                        } else {
                                $flow_info{$flow_key}->{"end_time"} = $timestamp;
                                $flow_info{$flow_key}->{"end_epoch"} = $epochstamp;
                                $flow_info{$flow_key}->{"length"}++;

                                push(@{$flow_data{$flow_key}}, $curr_line);
                        }

                        # Timeout old flows
                        foreach $key (keys %flow_info) {
                                if (($epochstamp - $flow_info{$key}->{"end_epoch"}) > $flow_timeout) {
                                        &timeout_flow($key);
                                }
                        }
                }

                close(INFILE);

                # Clean up remaining flows that didn't time out
                foreach $key (keys %flow_info) {
                        &timeout_flow($key);
                }
        }
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: flush to disk and delete hash entry
# -----------------------------------------------------------------------------
sub timeout_flow {
        my $flow_key = shift;

        # Discard brief flows
        if ($flow_info{$flow_key}->{'length'} <= $flow_discard) {
                delete $flow_info{$flow_key};
                delete $flow_data{$flow_key};

                return;
        }

        &print_flow($flow_key);

        delete $flow_info{$flow_key};
        delete $flow_data{$flow_key};
}

# -----------------------------------------------------------------------------
# Print flow to output file along with header/footer lines
# -----------------------------------------------------------------------------
sub print_flow {
        my $flow_key = shift;
        my $line;
        my $metadata;

        open(OUTFILE, ">>$output_file") || die "\nError: cannot open $output_file - $!\n";

        # Print flow header line
        $metadata = sprintf("%s!%d!%s!%s", $flow_info{$flow_key}->{'src_ip'},
                                           $flow_info{$flow_key}->{'length'},
                                           $flow_info{$flow_key}->{'start_time'},
                                           $flow_info{$flow_key}->{'end_time'});
        print OUTFILE ">>> $metadata " . '>' x (75 - length($metadata)) . "\n";

        # Print flow data lines
        foreach $line ( @{$flow_data{$flow_key}} ) {
                print OUTFILE "$line\n";
        }

        # Print flow footer line
        print OUTFILE '<' x 80 . "\n";

        close(OUTFILE);
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('1d:hmo:t:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "\nError: no input file provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $flow_timeout = $FLOW_TIMEOUT unless ($flow_timeout = $opts{t});
        $flow_discard = $FLOW_DISCARD unless ($flow_discard = $opts{d});
        $output_file = 0 unless ($output_file = $opts{o});
        $flow_one2one = 0 unless ($flow_one2one = $opts{1});
        $flow_one2many = 0 unless ($flow_one2many = $opts{m});

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                &print_usage();
        }
        if ((!$flow_one2one && !$flow_one2many) || ($flow_one2one && $flow_one2many)) {
                print "\nWarning: invalid flow output type specified, defaulting to one-to-many\n";
                $flow_one2many = 1;
        }
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-1hm] [-d discard] [-o file] [-t timeout] [input files]
USAGE
}
