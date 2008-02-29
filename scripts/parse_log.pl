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
my %callbacks = ();
my $plugin_dir;
my $plugin_list;

# Command line arguments
my %opts;
my @input_files;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();

&read_plugin_line($plugin_list) if ($plugin_list);
&read_plugin_dir($plugin_dir) if ($plugin_dir);
&read_plugin_dir() if (!$plugin_list && !$plugin_dir);

die "Error: No plugins loaded\n" if (keys %callbacks == 0);
print int(keys %callbacks) . " plugin(s) loaded\n" if $VERBOSE;

&process_logfiles();

&end_plugins();

# -----------------------------------------------------------------------------
# Parse a comma-delmited string for plugins to initialize
# -----------------------------------------------------------------------------
sub read_plugin_line {
        my $plugin_list = shift;

        foreach (split /,/, $plugin_list) {
                $_ =~ s/^\s+//;
                $_ =~ s/\s+$//;
                next if ($_ !~ /\.pm$/);
                next if ($_ =~ /^$/);

                &load_plugin($_);
        }

        return;
}

# -----------------------------------------------------------------------------
# Search a directory for plugins to initialize
# -----------------------------------------------------------------------------
sub read_plugin_dir {
        my $custom_dir = shift;
        my $plugin_dir;
        my $i = 0;

        # If a custom plugin directory, assume the user knows best; otherwise,
        # search the current dir and script base dir for a default plugin folder
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

        print "Using plugin directory '$plugin_dir'\n" if $VERBOSE;

        # Extract all plugins found in directory
        opendir(PLUGINDIR, $plugin_dir) or die "Error: Cannot find or access '$plugin_dir': $!\n";

        foreach (grep /\.pm$/, readdir(PLUGINDIR)) {
                &load_plugin($plugin_dir.'/'.$_);
                $i++;
        }

        closedir(PLUGINDIR);

        warn "Warning: No plugins found in $plugin_dir\n" if ($i == 0);
        print "$i plugin(s) found in '$plugin_dir' directory\n" if $VERBOSE;

        return;
}

# -----------------------------------------------------------------------------
# Load and initialize plugin from a file
# -----------------------------------------------------------------------------
sub load_plugin {
        my $path = shift;
        my $p = (fileparse($path, '\.pm'))[0];
        my $dir = dirname($path);

        print "Loading plugin file '$path'\n" if $VERBOSE;

        if (! -e $path) {
                warn "Warning: Cannot find or access '$path'\n";
                return;
        }

        eval 'require $path';
        if ($@) {
                warn $@ if $VERBOSE;
                warn "Warning: Plugin '$p' failed to load...disabling\n";
                delete $callbacks{$p};
                return;
        }

        unless ($callbacks{$p}->can('main')) {
                warn "Warning: Plugin '$p' does not contain a required main() function...disabling\n";
                delete $callbacks{$p};
                return;
        }

        if ($callbacks{$p}->can('init')) {
                if ($callbacks{$p}->init($dir) == 0) {
                        warn "Warning: Plugin '$p' failed to initialize...disabling\n";
                        delete $callbacks{$p};
                        return;
                }
        }

        print "Initialized plugin '$p'\n" if $VERBOSE;

        return;
}

# -----------------------------------------------------------------------------
# Create list of each plugin's callback information
# -----------------------------------------------------------------------------
sub register_plugin {
        my $package = (caller)[0];
        my $p = (fileparse((caller)[1], '\.pm'))[0];

        if ($package ne $p) {
                warn "Warning: Package '$package' does not match filename in plugin '$p'\n";
                die;
        }

        if (exists $callbacks{$p}) {
                warn "Warning: Plugin '$p' is already registered\n";
                die;
        }

        if ($package->can('new')) {
                $callbacks{$p} = $package->new();
        } else {
                warn "Warning: Plugin '$p' does not contain a required new() function\n";
                die;
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
                        warn "Error: Cannot open $curr_file: $!\n";
                        next;
                }

                print "Processing file '$curr_file'\n" if $VERBOSE;

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
                        map { $callbacks{$_}->main(\%record) } keys %callbacks;
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

        foreach $p (keys %callbacks) {
                $callbacks{$p}->end() if ($callbacks{$p}->can('end'));
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
                warn "Error: No input file(s) provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $plugin_list = $opts{p} if ($opts{p});
        $plugin_dir = $opts{d} if ($opts{d});

        return;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
Usage: $0 [ -h ] [ -d dir ] [ -p plugins ] file1 [ file2 ... ]
  -d  load plugins from specified directory
  -h  print this help information and exit
  -p  load plugins from comma-delimited list

USAGE
}
