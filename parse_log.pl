#!/usr/bin/perl -w

#
# parse_log.pl 6/25/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PROG_NAME = "parse_log.pl";
my $PROG_VER = "0.0.1";
my $VERBOSE = 1;
my $PLUGIN_DIR = "./plugins";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my @callbacks = ();
my @plugins = ();
my $plugin;

# Command line arguments
my %opts;
my @input_files;
my $plugin_dir;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&init_plugins($plugin_dir);
&process_logfiles();
&end_plugins();

# -----------------------------------------------------------------------------
# Load and initialize all plugins in specified directory
# -----------------------------------------------------------------------------
sub init_plugins {
        my $plugin_dir = shift;
        my $plugin;
        my $i = 0;

        unless (-d $plugin_dir) {
                die "Error: '$plugin_dir' is not a valid directory\n";
        }

        opendir PLUGINS, $plugin_dir or die "Error: cannot access directory $plugin_dir: $!\n";
                @plugins = grep { /\.pm$/ } readdir(PLUGINS);
        closedir PLUGINS;

        foreach $plugin (@plugins) {
                print "Loading $plugin_dir/$plugin...\n" if $VERBOSE;
                require "$plugin_dir/$plugin";
        }

        foreach $plugin (@callbacks) {
                unless ($plugin->can('main')) {
                        print "Warning: plugin '$plugin' does not contain a required main() function...disabling\n";
                        splice @callbacks, $i, 1;
                        next;
                }

                if ($plugin->can('init')) {
                        if ($plugin->init($plugin_dir) == 0) {
                                print "Warning: plugin '$plugin' did not initialize properly...disabling\n";
                                splice @callbacks, $i, 1;
                        } else {
                                print "Initialized $plugin\n" if $VERBOSE;
                                $i++;
                        }
                }
        }
}

# -----------------------------------------------------------------------------
# Create list of each plugin's callback information
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
# Process all files, passing each line to all registered plugins
# -----------------------------------------------------------------------------
sub process_logfiles {
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file

        foreach $curr_file (@input_files) {
                unless (open(INFILE, "$curr_file")) {
                        print "Error: Cannot open $curr_file - $!\n";
                        next;
                }

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        next if $curr_line eq "";

                        foreach $plugin (@callbacks) {
                                $plugin->main($curr_line);
                        }
                }

                close(INFILE);
        }
}

# -----------------------------------------------------------------------------
# Call termination function in each loaded plugin
# -----------------------------------------------------------------------------
sub end_plugins {
        foreach $plugin (@callbacks) {
                $plugin->end() if ($plugin->can('end'));
        }
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('hp:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "Error: no input file provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $plugin_dir = $PLUGIN_DIR unless ($plugin_dir = $opts{p});

        # Strip trailing slash from plugin directory path
        if ($plugin_dir =~ /(.*)\/$/) {
                $plugin_dir = $1;
        }
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-h] [-p dir] file1 [file2 ...]
  -h ... print this help information and exit
  -p ... load plugins from specified directory
USAGE
}
