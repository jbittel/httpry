#!/usr/bin/perl -w

#
# parse_log.pl 6/25/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN = "\t";
my $PROG_NAME = "parse_log.pl";
my $PROG_VER = "0.0.1";
my $SUMMARY_CAP = 15;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my @callbacks = ();
my @plugins = ();
my $plugin;
my %top_hosts = ();
my %top_talkers = ();
my $total_line_cnt = 0;
my $line_cnt = 0;
my $size_cnt = 0;
my $file_cnt = 0;
my $start_time; # Start tick for timing code
my $end_time;   # End tick for timing code

# Command line arguments
my %opts;
my @input_files;
my $plugin_dir;
my $convert_hex;
my $log_summary;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&init_plugins($plugin_dir);
#&parse_logfiles();
#&end_plugins();

# -----------------------------------------------------------------------------
# Load and initialize all plugins in specified directory
# -----------------------------------------------------------------------------
sub init_plugins {
        my $plugin_dir = shift;
        my $plugin;
        my $i = 0;

        if (! -d $plugin_dir) {
                die "Error: '$plugin_dir' is not a valid directory\n";
        }

        opendir PLUGINS, $plugin_dir or die "Error: cannot open directory $plugin_dir: $!\n";
                @plugins = grep { /\.pm$/ } readdir(PLUGINS);
        closedir PLUGINS;

        foreach $plugin (@plugins) {
                print "Loading $plugin_dir/$plugin...\n";
                require "$plugin_dir/$plugin";
        }

        foreach $plugin (@callbacks) {
                if (!$plugin->can('main')) {
                        print "Warning: plugin '$plugin' does not contain a required main() function...disabling\n";
                        splice @callbacks, $i, 1;
                        next;
                }

                if ($plugin->can('init')) {
                        if ($plugin->init() == 0) {
                                print "Warning: plugin '$plugin' did not initialize properly...disabling\n";
                                splice @callbacks, $i, 1;
                                next;
                        } else {
                                print "Initialized $plugin";
                        }
                }
                $i++;
        }
}

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------
sub register_plugin {
        my $plugin = shift;

        if ($plugin->can('new')) {
                push @callbacks, $plugin->new();
        } else {
                print "Warning: plugin '$plugin' does not contain a required new() function...disabling\n";
        }
}

# -----------------------------------------------------------------------------
# Core parsing engine, processes all input files based on options provided
# -----------------------------------------------------------------------------
sub parse_logfiles {
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file
        my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);

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

                        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

                        if ($log_summary) {
                                $line_cnt++;
                                $top_hosts{$hostname}++;
                                $top_talkers{$src_ip}++;
                        }

                        foreach $plugin (@callbacks) {
                                #$plugin->main("ping");
                        }
                }

                close(INFILE);
        }
        $end_time = (times)[0];
}

# -----------------------------------------------------------------------------
# Call terminate function in each loaded plugin
# -----------------------------------------------------------------------------
sub end_plugins {
        foreach $plugin (@callbacks) {
                $plugin->end() if ($plugin->can('end'));
        }
}

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $count = 0;
        my $key;

        print "\n\nSUMMARY STATS\n\n";
        print "Generated:\t".localtime()."\n";
        print "Total files:\t$file_cnt\n";
        print "Total size:\t$size_cnt MB\n";
        print "Total lines:\t$total_line_cnt\n";
        print "Total time:\t".sprintf("%.2f", $end_time - $start_time)." secs\n";

        print "\n\nTOP $SUMMARY_CAP VISITED HOSTS\n\n";
        foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                print "$key\t$top_hosts{$key}\t".percent_of($top_hosts{$key}, $line_cnt)."%\n";
                $count++;
                last if ($count == $SUMMARY_CAP);
        }

        $count = 0;
        print "\n\nTOP $SUMMARY_CAP TOP TALKERS\n\n";
        foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                print "$key\t$top_talkers{$key}\t".percent_of($top_talkers{$key}, $line_cnt)."%\n";
                $count++;
                last if ($count == $SUMMARY_CAP);
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
        getopts('p:hx', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "\nError: no input file provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $plugin_dir = "./plugins" unless ($plugin_dir = $opts{p});
        $log_summary = 0 unless ($log_summary = $opts{s});
        $convert_hex = 0 unless ($convert_hex = $opts{x});
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;

$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-hx] [-p dir]
USAGE
}
