#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>
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
my %plugins = ();

# Command line arguments
my %opts;
my @input_files;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&init_plugins();
&process_logfiles();
&end_plugins();

# -----------------------------------------------------------------------------
# Load and initialize all plugins in specified directory
# -----------------------------------------------------------------------------
sub init_plugins {
        my $p;

        foreach $p (keys %plugins) {
                print "Loading plugin: $p\n" if $VERBOSE;

                if (! -e $plugins{$p}->{'path'}) {
                        print "Warning: Cannot locate plugin '$p' at '$plugins{$p}->{'path'}'\n";
                        delete $plugins{$p};
                        next;
                }

                require $plugins{$p}->{'path'};
                if (!exists $plugins{$p}->{'callback'}) {
                        delete $plugins{$p};
                        next;
                }

                unless ($plugins{$p}->{'callback'}->can('main')) {
                        print "Warning: Plugin '$p' does not contain a required main() function...disabling\n";
                        delete $plugins{$p};
                        next;
                }

                if ($plugins{$p}->{'callback'}->can('init')) {
                        if ($plugins{$p}->{'callback'}->init($plugins{$p}->{'dir'}) == 0) {
                                print "Warning: Plugin '$p' did not initialize properly...disabling\n";
                                delete $plugins{$p};
                                next;
                        }
                }

                print "Initialized plugin: $p\n" if $VERBOSE;
        }

        die "Error: No plugins loaded\n" if (scalar keys %plugins == 0);
        print int(scalar keys %plugins) . " plugin(s) loaded\n" if $VERBOSE;

        return;
}

# -----------------------------------------------------------------------------
# Locate and search a directory for plugins to initialize
# -----------------------------------------------------------------------------
sub search_plugin_dir {
        my $custom_dir = shift;
        my $plugin_dir;
        my $p;

        # If a custom plugin directory, assume the user knows what they're doing;
        # otherwise, search the current dir and script base dir for a plugin folder
        if ($custom_dir) {
                $custom_dir =~ s/\/$//;
                $plugin_dir = $custom_dir;

                die "Error: '$plugin_dir' is not a valid directory\n" unless (-d $plugin_dir);
        } else {
                if (-d './' . $DEFAULT_PLUGIN_DIR) {
                        $plugin_dir = './' . $DEFAULT_PLUGIN_DIR;
                } elsif (-d dirname($0) . '/' . basename($DEFAULT_PLUGIN_DIR)) {
                        $plugin_dir = dirname($0) . '/' . basename($DEFAULT_PLUGIN_DIR);
                } else {
                        die "Error: Cannot find the default '$DEFAULT_PLUGIN_DIR' plugin directory\n";
                }
        }

        print "Using plugin directory: $plugin_dir\n" if $VERBOSE;

        # Extract all plugins found in directory
        opendir(PLUGINDIR, $plugin_dir) or die "Error: Cannot access directory '$plugin_dir': $!\n";

        foreach (readdir(PLUGINDIR)) {
                next if ($_ !~ /\.pm$/);
                $p = (fileparse($_, '\.pm'))[0];

                if (exists $plugins{$p}) {
                        print "Warning: Plugin '$p' already loaded...ignoring\n";
                        next;
                }

                $plugins{$p}->{'dir'} = $plugin_dir;
                $plugins{$p}->{'path'} = $plugin_dir.'/'.$_;
        }

        closedir(PLUGINDIR);

        print "Warning: No plugins found in $plugin_dir\n" if (scalar keys %plugins == 0);
        print int(scalar keys %plugins) . " plugin(s) found in '$plugin_dir'\n" if $VERBOSE;

        return;
}

# -----------------------------------------------------------------------------
# Create list of each plugin's callback information
# -----------------------------------------------------------------------------
sub register_plugin {
        my $p = shift;

        if (!exists $plugins{$p}) {
                print "Warning: Encountered unknown package name '$p'\n";

                return;
        }

        if ($p->can('new')) {
                $plugins{$p}->{'callback'} = $p->new();
        } else {
                print "Warning: Plugin '$p' does not contain a required new() function...disabling\n";
                delete $plugins{$p};
        }

        return;
}

# -----------------------------------------------------------------------------
# Process all files, passing each line to all registered plugins
# -----------------------------------------------------------------------------
sub process_logfiles {
        my $curr_file;
        my $curr_line;
        my @header;
        my %record;
        my $i;

        foreach $curr_file (@input_files) {
                unless (open(INFILE, "$curr_file")) {
                        print "Error: Cannot open $curr_file: $!\n";
                        next;
                }

                print "Processing file $curr_file\n" if $VERBOSE;

                while ($curr_line = <INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ s/[^[:print:]\t]//g; # Strip unprintable characters
                        next if $curr_line =~ /^$/;

                        # Default header format:
                        # Fields: timestamp,source-ip,dest-ip,direction,method,host,request-uri,http-version,status-code,reason-phrase
                        if ($curr_line =~ /^#/) {
                                next unless $curr_line =~ /^# Fields: (.*)$/;
                                @header = map { lc } split /\,/, $1;
                                %record = ();
                                next;
                        }
                        die "Error: No field description line found\n" if (scalar @header == 0);

                        $i = 0;
                        map { $record{$header[$i++]} = $_ } split /\t/, $curr_line, scalar @header;
                        map { $plugins{$_}->{'callback'}->main(\%record) } keys %plugins;
                }

                close(INFILE);
        }

        return;
}

# -----------------------------------------------------------------------------
# Call termination function in each loaded plugin
# -----------------------------------------------------------------------------
sub end_plugins {
        my $p;

        foreach $p (keys %plugins) {
                $plugins{$p}->{'callback'}->end() if ($plugins{$p}->{'callback'}->can('end'));
        }

        return;
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        my $p;

        getopts('d:hp:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "Error: No input file(s) provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        &search_plugin_dir($opts{d}) if ($opts{d});

        if ($opts{p}) {
                foreach (split /,/, $opts{p}) {
                        $_ =~ s/^\s+//;
                        $_ =~ s/\s+$//;
                        $p = (fileparse($_, '\.pm'))[0];

                        if (exists $plugins{$p}) {
                                print "Warning: Plugin '$p' already loaded...ignoring\n";
                                next;
                        }

                        $plugins{$p}->{'dir'} = dirname($_);
                        $plugins{$p}->{'path'} = $_;
                }
        }

        &search_plugin_dir() if (!$opts{d} && !$opts{p});

        return;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
Usage: $0 [-h] [-d dir] [-p plugins] file1 [file2 ...]
  -d  load plugins from specified directory
  -h  print this help information and exit
  -p  load plugins from comma-delimited list

USAGE
}
