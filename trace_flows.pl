#!/usr/bin/perl -w

#
# trace_flows.pl 10/25/2005
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
my $PROG_NAME = "trace_flows.pl";
my $PROG_VER = "0.0.1";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my $start_time; # Start tick for timing code
my $end_time;   # End tick for timing code

# Command line arguments
my %opts;
my @input_files;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();

$start_time = (times)[0];
&parse_flows();
$end_time = (times)[0];
print "Execution time was ".sprintf("%.2f", $end_time - $start_time)." secs\n";

# -----------------------------------------------------------------------------
# Core parsing engine, processes all input files based on options provided
# -----------------------------------------------------------------------------
sub parse_flows {

}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('h', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        &print_usage() unless ($ARGV[0]);

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-h]
USAGE
}
