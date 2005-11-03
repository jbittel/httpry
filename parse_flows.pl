#!/usr/bin/perl -w

#
# parse_flows.pl 11/2/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "parse_flows.pl";
my $PROG_VER = "0.0.1";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %flow_info = ();

# Command line arguments
my %opts;
my @input_files;
my $output_file;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&parse_flows();

# -----------------------------------------------------------------------------
# Core parsing engine, processes all input files based on options provided
# -----------------------------------------------------------------------------
sub parse_flows {
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);

        foreach $curr_file (@input_files) {
                unless(open(INFILE, "$curr_file")) {
                        print "\nError: Cannot open $curr_file - $!\n";
                        next;
                }

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        next if $curr_line eq "";

                        if ($curr_line =~ /^>>>/) {
                                # Parse metadata
                        } elsif ($curr_line =~ /^<<</) {
                                # Flush current flow to disk
                        } else {
                                # Add current line to buffer array
                                ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);
                        }
                }

                close(INFILE);
        }
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('o:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        &print_usage() unless ($ARGV[0]);

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $output_file = 0 unless ($output_file = $opts{o});

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                &print_usage();
        }
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-1hm] [-d discard] [-o file] [-t timeout]
USAGE
}
