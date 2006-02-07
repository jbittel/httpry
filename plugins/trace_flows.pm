#!/usr/bin/perl -w

#
# trace_flows.pm 10/25/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

package trace_flows;

#use strict;
use Getopt::Std;
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PROG_NAME = "trace_flows.pm";
my $PROG_VER = "0.0.2";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %flow_info = ();
my %flow_data = ();

&main::register_plugin(__PACKAGE__);

sub new {
        return bless {};
}

sub init {
        if (&load_config() < 0) {
                return -1;
        }
        unlink $output_file if (-e $output_file);
}

sub main {
        my $self = shift;
        my $data = shift;

        &process_data($data);
}

sub end {
        my $key;

        # Clean up remaining flows that didn't time out
        foreach $key (keys %flow_info) {
                &timeout_flow($key);
        }

        &write_output_file();
        &send_email() if $email_addr;
}

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------
sub process_data {
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);
        my $flow_key;
        my $key;
        my $epochstamp;

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
sub load_config {
        # Load config file; by default in same directory as plugin
        require "./plugins/" . __PACKAGE__ . ".cfg";
        
        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                return -1;
        }
        if ((!$flow_one2one && !$flow_one2many) || ($flow_one2one && $flow_one2many)) {
                print "\nWarning: invalid flow output type specified, defaulting to one-to-many\n";
                $flow_one2many = 1;
        }

        return 0;
}

1;
