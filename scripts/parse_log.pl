#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>
#

use strict;
use warnings;
use Getopt::Std;
use File::Basename;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $VERBOSE = 0;
my $DEFAULT_PLUGIN_DIR = "plugins";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %nameof = ();        # Stores human readable plugin names
my @callbacks = ();     # List of initialized plugins
my @plugins = ();       # List of plugins to be loaded

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

        &search_plugin_dir if (scalar @plugins == 0);

        # Load up each plugin
        foreach $plugin (@plugins) {
                print "Loading $plugin...\n" if $VERBOSE;

                if (! -e $plugin) {
                        # Tack on an extension to see if the plugin
                        # was specified without one
                        if (-e "$plugin.pm") {
                                $plugin = "$plugin.pm"
                        } else {
                                print "Warning: Cannot locate $plugin\n";
                                next;
                        }
                }

                require $plugin;
        }

        if (scalar @callbacks == 0) {
                die "Error: No plugins loaded\n";
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
# Locate and search a directory for plugins to initialize
# -----------------------------------------------------------------------------
sub search_plugin_dir {
        my $file;

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

        # Initialize list of plugins to load
        opendir PLUGINDIR, $plugin_dir or die "Error: Cannot access directory '$plugin_dir': $!\n";
                foreach $file (readdir(PLUGINDIR)) {
                        next if ($file !~ /\.pm$/);

                        push(@plugins, "$plugin_dir/$file");
                }
        closedir PLUGINDIR;

        if (scalar @plugins == 0) {
                die "Error: No plugins loaded from $plugin_dir\n";
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
        
                # Save a readable copy of the plugin name so we can use it in output text
                $nameof{$callbacks[-1]} = $plugin;
        } else {
                print "Warning: Plugin '$plugin' does not contain a required new() function...disabling\n";
        }

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
        my @header = ();
        my %record;

        foreach $curr_file (@input_files) {
                unless (open(INFILE, "$curr_file")) {
                        print "Error: Cannot open $curr_file: $!\n";
                        next;
                }

                while ($curr_line = <INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ s/[^[:print:]\t]//g; # Strip unprintable characters
                        next if $curr_line eq "";

                        # Default header format:
                        # Fields: timestamp,source-ip,dest-ip,direction,method,host,request-uri,http-version,status-code,reason-phrase
                        if ($curr_line =~ /^#/) {
                                next unless $curr_line =~ /^# Fields: (.*)$/;
                                @header = map lc, split(/\,/, $1);
                                %record = ();
                        }

                        if (scalar(@header) == 0) {
                                die "Error: No field description line found; cannot proceed\n";
                        }
                        @fields = split(/\t/, $curr_line);
                        next if (scalar(@fields) != scalar(@header)); # Malformed fields count

                        foreach (0..$#fields) {
                                $record{$header[$_]} = $fields[$_];
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
        getopts('d:hp:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "Error: No input file(s) provided\n";
                &print_usage();
        }

        # Currently, specifying both of these causes precedence confusion,
        # so we'll disallow that behavior
        die "Error: -d and -p are mutually exclusive\n" if ($opts{d} && $opts{p});

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $plugin_dir = $DEFAULT_PLUGIN_DIR unless ($plugin_dir = $opts{d});
        $custom_plugin_dir = 1 if ($opts{d});
        @plugins = split /,/, $opts{p} if ($opts{p});

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
Usage: $0 [-h] [-d dir] [-p plugins] file1 [file2 ...]
  -d   base directory to use when searching for plugins
  -h   print this help information and exit
  -p   specify a list of plugins to load

USAGE
}
