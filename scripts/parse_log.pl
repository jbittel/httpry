#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.edu>
#

use strict;
use warnings;
use Getopt::Std;
use File::Basename;
use Cwd;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $VERBOSE = 0;
my $PLUGIN_DIR = "plugins";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %nameof = ();    # Stores human readable plugin names
my @callbacks = (); # List of initialized plugins
my @plugins = ();   # List of plugin files in directory
my @ignore = ("sample_plugin", "db_dump", "hostnames");
                    # List of plugins to be ignored on initialization (comma-delimited)

# Command line arguments
my %opts;
my @input_files;
my $plugin_dir;
my $custom_plugin_dir = 0;

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
        my $curr_dir;

        # If a custom plugin directory, assume the user knows what they're doing;
        # otherwise, search the current dir and script base dir for a plugin folder
        if ($custom_plugin_dir) {
                unless (-d $plugin_dir) {
                        die "Error: '$plugin_dir' is not a valid directory\n";
                }
        } else {
                if (-d "./".$plugin_dir) {
                        $plugin_dir = "./" . $plugin_dir;
                } elsif (-d dirname($0).'/'.basename($plugin_dir)) {
                        $plugin_dir = dirname($0).'/'.basename($plugin_dir);
                } else {
                        die "Error: Cannot find a '$plugin_dir' directory\n";
                }
        }

        # Extract all plugins from specified directory
        opendir PLUGINS, $plugin_dir or die "Error: Cannot access directory '$plugin_dir': $!\n";
                @plugins = grep { /\.pm$/ } readdir(PLUGINS);
        closedir PLUGINS;

        if (scalar @plugins == 0) {
                die "Error: No plugins found in specified directory\n";
        }

        # Load up each plugin, unless specifically exempted
        PLUGIN: foreach $plugin (@plugins) {
                foreach (@ignore) {
                        next PLUGIN if $plugin =~ /^$_/;
                }
                print "Loading $plugin_dir/$plugin...\n" if $VERBOSE;
                require "$plugin_dir/$plugin";
        }

        # Check for required functions and initialize each loaded plugin
        foreach $plugin (@callbacks) {
                unless ($plugin->can('main')) {
                        print "Warning: Plugin '$nameof{$plugin}' does not contain a required main() function...disabling\n";
                        splice @callbacks, $i, 1;
                        next;
                }

                if ($plugin->can('init')) {
                        if ($plugin->init($plugin_dir) == 0) {
                                print "Warning: Plugin '$nameof{$plugin}' did not initialize properly...disabling\n";
                                splice @callbacks, $i, 1;
                        } else {
                                print "Initialized plugin: $nameof{$plugin}\n" if $VERBOSE;
                                $i++;
                        }
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Create list of each plugin's callback information
# -----------------------------------------------------------------------------
sub register_plugin {
        my $plugin = shift;

        if ($plugin->can('new')) {
                push @callbacks, $plugin->new();
        } else {
                print "Warning: Plugin '$plugin' does not contain a required new() function...disabling\n";
        }

        # Save a plaintext copy of the plugin name so we can use it in output text
        $nameof{$callbacks[-1]} = $plugin;

        return;
}

# -----------------------------------------------------------------------------
# Process all files, passing each line to all registered plugins
# -----------------------------------------------------------------------------
sub process_logfiles {
        my $curr_file; # Current input file
        my $curr_line; # Current line in input file
        my $plugin;
        my @fields;
        my @headers;
        my %record;
        my $i;

        foreach $curr_file (@input_files) {
                unless (open(INFILE, "$curr_file")) {
                        print "Error: Cannot open $curr_file: $!\n";
                        next;
                }

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ tr/\x80-\xFF//d; # Strip non-printable chars
                        next if $curr_line eq "";

                        # Default header format:
                        # Fields: Timestamp,Source-IP,Dest-IP,Direction,Method,Host,Request-URI,HTTP-Version,Status-Code,Reason-Phrase
                        if ($curr_line =~ /^#/) {
                                next unless $curr_line =~ /^# Fields: (.*)$/;
                                @headers = split(/\,/, $1);
                                %record = ();
                        }

                        if (scalar(@headers) == 0) {
                                die "Error: No field description line found; cannot proceed\n";
                        }
                        @fields = split(/\t/, $curr_line);
                        next if (scalar(@fields) != scalar(@headers)); # Malformed fields count

                        for ($i = 0; $i < scalar @fields; $i++) {
                                $record{lc($headers[$i])} = $fields[$i];
                        }

                        foreach $plugin (@callbacks) {
                                $plugin->main(\%record);
                        }
                }

                close(INFILE);
        }

        return;
}

# -----------------------------------------------------------------------------
# Call termination function in each loaded plugin
# -----------------------------------------------------------------------------
sub end_plugins {
        my $plugin;

        foreach $plugin (@callbacks) {
                $plugin->end() if ($plugin->can('end'));
        }

        return;
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('hp:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "Error: No input file(s) provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $plugin_dir = $PLUGIN_DIR unless ($plugin_dir = $opts{p});
        $custom_plugin_dir = 1 if ($opts{p});

        # Strip trailing slash from plugin directory path
        if ($plugin_dir =~ /(.*)\/$/) {
                $plugin_dir = $1;
        }

        return;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
Usage: $0 [-h] [-p dir] file1 [file2 ...]
  -h   print this help information and exit
  -p   load plugins from specified directory
USAGE
}
