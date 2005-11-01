#!/usr/bin/perl -w

#
# trace_flows.pl 10/25/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use Date::Calc qw(Delta_DHMS);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "trace_flows.pl";
my $PROG_VER = "0.0.1";
my $FLOW_TIMEOUT = 5; # Timeout for flows, in minutes
my $DEBUG = 0; # Debug flag for helpful print messages

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %flow_info = ();
my %flow_data = ();
my $start_time; # Start tick for timing code
my $end_time;   # End tick for timing code

my $key;
my $subkey;

# Command line arguments
my %opts;
my @input_files;
my $output_file;
my $flow_timeout;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
if (-e $output_file) { unlink $output_file };
&parse_flows();

print "\nExecution time was ".sprintf("%.2f", $end_time - $start_time)." secs\n";

# -----------------------------------------------------------------------------
# Core parsing engine, processes all input files based on options provided
# -----------------------------------------------------------------------------
sub parse_flows {
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);
        my $flow_key;
        my $flow_id = 0;
        my @curr_time;
        my @end_time;
        my @time_diff;
        my $key;

        $start_time = (times)[0];
        foreach $curr_file (@input_files) {
                unless(open(INFILE, "$curr_file")) {
                        print "\nError: Cannot open $curr_file - $!\n";
                        next;
                }

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ tr/\x80-\xFF//d; # Strip non-printable chars
                        next if $curr_line eq "";

                        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

                        next if (!$src_ip or !$dst_ip or !$hostname);
                        $flow_key = $src_ip.'-'.$dst_ip;

                        # Let's make magic happen here, baby
                        if (!exists $flow_info{$flow_key}) {
                                print "New flow #$flow_id\n" if $DEBUG;
                                $flow_info{$flow_key}->{"id"} = $flow_id++;
                                $flow_info{$flow_key}->{"src_ip"} = $src_ip;
                                $flow_info{$flow_key}->{"dst_ip"} = $dst_ip;
                                $flow_info{$flow_key}->{"hostname"} = $hostname;
                                $flow_info{$flow_key}->{"start_time"} = $timestamp; # Encode in epoch seconds (Mktime())
                                $flow_info{$flow_key}->{"end_time"} = $timestamp; # Encode in epoch seconds
                                $flow_info{$flow_key}->{"length"} = 1;

                                @{$flow_data{$flow_key}}[0] = $timestamp.$PATTERN.$uri;
                                #$#{$flow_data{$flow_key}} = 1000;
                        } else {
                                $flow_info{$flow_key}->{"end_time"} = $timestamp; # Encode in epoch seconds
                                #$flow_info{$flow_key}->{"length"}++;

                                @{$flow_data{$flow_key}}[$flow_info{$flow_key}->{"length"}++] = $timestamp.$PATTERN.$uri;
                        }

                        # Return this in epoch seconds
                        # Parse current record time [08/13/2005 04:40:22]
                        $timestamp =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
                        @curr_time = ($3, $1, $2, $4, $5, $6);

                        # Timeout old flows
                        foreach $key (keys %flow_info) {
                                print ".";
                                # No need to parse, already in epoch seconds
                                $flow_info{$key}->{"end_time"} =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
                                @end_time = ($3, $1, $2, $4, $5, $6);

                                # Simply subtract values and /60 to get this value
                                @time_diff = Delta_DHMS(@end_time, @curr_time);
                                if ($time_diff[2] > $flow_timeout) {
                                        &timeout_flow($key);
                                }
                        }
                        print "\n";
                }

                close(INFILE);

                # Clean up remaining flows that didn't time out
                foreach $key (keys %flow_info) {
                        &timeout_flow($key);
                }
        }
        $end_time = (times)[0];
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: flush to disk and delete hash entry
# -----------------------------------------------------------------------------
sub timeout_flow {
        my $flow_key = shift;

        # Discard brief flows
        if ($flow_info{$flow_key}->{'length'} <= 1) {
                print "Flow $flow_info{$flow_key}->{'id'} discarded\n" if $DEBUG;

                delete $flow_info{$flow_key};
                delete $flow_data{$flow_key};

                return;
        }

        print "Flow $flow_info{$flow_key}->{'id'} concluded\n" if $DEBUG;
        &print_flow($flow_key);

        delete $flow_info{$flow_key};
        delete $flow_data{$flow_key};
}

# -----------------------------------------------------------------------------
# Print flow to output file along with header/footer lines
# -----------------------------------------------------------------------------
sub print_flow {
        my $flow_key = shift;
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);
        my $key;
        my $line;
        my $metadata;

        open(OUTFILE, ">>$output_file") || die "\nError: cannot open $output_file - $!\n";

        # Print flow header line
        $metadata = sprintf("%d!%d!%s!%s", $flow_info{$flow_key}->{'id'},
                                           $flow_info{$flow_key}->{'length'},
                                           $flow_info{$flow_key}->{'start_time'},
                                           $flow_info{$flow_key}->{'end_time'});
        #print OUTFILE ">>> $flow_info{$flow_key}->{'id'}!$flow_info{$flow_key}->{'length'} ";
        print OUTFILE ">>> $metadata " . '>' x (75 - length($metadata)) . "\n";
        #print length($flow_key);
        #print "\n";

#        foreach $key (keys %{ $flow_info{$flow_key} }) {
#                print "$flow_info{$flow_key}->{$key}, ";
#        }
#        print ">>>\n";

        # Print flow data lines
        $src_ip = $flow_info{$flow_key}->{"src_ip"};
        $dst_ip = $flow_info{$flow_key}->{"dst_ip"};
        $hostname = $flow_info{$flow_key}->{"hostname"};
        foreach $line ( @{$flow_data{$flow_key}} ) {
                ($timestamp, $uri) = split(/$PATTERN/, $line);

                print OUTFILE "$timestamp\t$src_ip\t$dst_ip\t$hostname\t$uri\n";
        }

        # Print flow footer line
        print OUTFILE '<' x 80 . "\n";

        close(OUTFILE);
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('ho:t:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        &print_usage() unless ($ARGV[0]);

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $flow_timeout = $FLOW_TIMEOUT unless ($flow_timeout = $opts{t});
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
Usage: $PROG_NAME [-h] [-o file] [-t timeout]
USAGE
}
