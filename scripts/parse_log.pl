#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

use strict;
use warnings;
use Getopt::Std;
use File::Basename;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $DEFAULT_PLUGIN_DIR = "plugins";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %enabled = ();
my %disabled = ();

# Command line arguments
my %opts;
my $verbose = 0;
my $plugin_dir = "";
my $plugin_list = "";
my @input_files = ();

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
get_arguments();

read_plugin_line($plugin_list) if ($plugin_list);
read_plugin_dir($plugin_dir) if ($plugin_dir);
read_plugin_dir() if (!$plugin_list && !$plugin_dir);

die "Error: No plugins loaded\n" if (keys %enabled == 0);
print "Info: " . (keys %enabled) . " plugins loaded\n" if $verbose;

process_logfiles();

end_plugins();

# -----------------------------------------------------------------------------
# Parse a comma-delmited string for plugins to initialize
# -----------------------------------------------------------------------------
sub read_plugin_line {
        my $plugin_list = shift;
        my $i = 0;

        foreach (split /,/, $plugin_list) {
                $_ =~ s/^\s+//;
                $_ =~ s/\s+$//;
                next if ($_ =~ /^$/);

                load_plugin($_);
                $i++;
        }

        warn "Warning: No plugins found in plugin list\n" if ($i == 0);
        print "Info: $i plugins found in plugin list\n" if $verbose;

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

        print "Info: Reading plugin directory '$plugin_dir'\n" if $verbose;

        # Load all plugins found in directory
        opendir PLUGINDIR, $plugin_dir or die "Error: Cannot find or access '$plugin_dir': $!\n";

        foreach (grep /\.pm$/, readdir(PLUGINDIR)) {
                load_plugin($plugin_dir . '/' . $_);
                $i++;
        }

        closedir(PLUGINDIR);

        warn "Warning: No plugins found in $plugin_dir\n" if ($i == 0);
        print "Info: $i plugins found in '$plugin_dir' directory\n" if $verbose;

        return;
}

# -----------------------------------------------------------------------------
# Load and initialize plugin from a file
# -----------------------------------------------------------------------------
sub load_plugin {
        my $path = shift;
        my $p = (fileparse($path, '\.pm'))[0];
        my $dir = dirname($path);

        print "Info: Loading plugin file '$path'\n" if $verbose;

        if (! -e $path) {
                warn "Warning: $p: Cannot find or access '$path'\n";
                return;
        }

        if (exists $enabled{$p}) {
                warn "Warning: $p: Name already registered\n";
                return;
        }

        eval 'require $path';
        if ($@) {
                warn "Warning: $p: $@" if $verbose;
                warn "Warning: $p: Failed to load...disabling\n";
                delete $enabled{$p};
                return;
        }

        unless ($enabled{$p}->can('main')) {
                warn "Warning: $p: Cannot find a required main() function...disabling\n";
                delete $enabled{$p};
                return;
        }

        if ($enabled{$p}->can('init')) {
                eval '$enabled{$p}->init($dir)';
                if ($@) {
                        warn "Warning: $p: $@" if $verbose;
                        warn "Warning: $p: Failed to initialize...disabling\n";
                        delete $enabled{$p};
                        return;
                }
        }

        print "Info: Initialized plugin '$p'\n" if $verbose;

        return;
}

# -----------------------------------------------------------------------------
# Create list of each plugin's callback information
# -----------------------------------------------------------------------------
sub register_plugin {
        my $package = (caller)[0];
        my $p = (fileparse((caller)[1], '\.pm'))[0];

        if ($package ne $p) {
                die "Warning: $p: Package name does not match filename\n";
        }

        if ($package->can('new')) {
                $enabled{$p} = $package->new();
        } else {
                die "Warning: $p: Cannot find a required new() function\n";
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

        FILE: foreach $curr_file (@input_files) {
                unless (open INFILE, "$curr_file") {
                        warn "Error: Cannot open $curr_file: $!\n";
                        next FILE;
                }

                print "Info: Processing file '$curr_file'\n" if $verbose;

                LINE: while ($curr_line = <INFILE>) {
                        chomp $curr_line;
                        $curr_line =~ s/[^[:print:]\t]//g; # Strip unprintable characters
                        next LINE if $curr_line =~ /^$/;

                        # Handle comment lines
                        if ($curr_line =~ /^#/) {
                                # Check the comment for a field specifier line
                                next LINE unless $curr_line =~ /^# Fields: (.*)$/;
                                @header = map { s/\s//g; lc; } split /\,/, $1;

                                check_fields(@header);

                                if (keys %enabled == 0) {
                                        warn "Error: All plugins are disabled...skipping file\n";
                                        next FILE;
                                }

                                %record = ();
                                next LINE;
                        }

                        if (scalar @header == 0) {
                                warn "Error: No field description line found...skipping file\n";
                                next FILE;
                        }

                        @record{@header} = split /\t/, $curr_line;

                        foreach (keys %enabled) {
                                $enabled{$_}->main(\%record);
                        }
                }

                close INFILE or die "Error: Cannot close $curr_file: $!\n";;
        }

        return;
}

# -----------------------------------------------------------------------------
# Check required fields for each plugin against the current header fields
# -----------------------------------------------------------------------------
sub check_fields {
        my @keys = @_;
        my %fields = map { $keys[$_] => 1 } 0..$#keys;
        my $p;

        # Check active plugins to see if they have the required fields
        PLUGIN: foreach $p (keys %enabled) {
                next unless $enabled{$p}->can('list');

                foreach ($enabled{$p}->list()) {
                        next if $_ eq '';

                        if (!exists $fields{$_}) {
                                warn "Warning: $p: Required field '$_' not found...disabling\n";
                                $disabled{$p} = $enabled{$p};
                                delete $enabled{$p};
                                next PLUGIN;
                        }
                }
        }

        # Check disabled plugins to see if any should be enabled
        PLUGIN: foreach $p (keys %disabled) {
                next unless $disabled{$p}->can('list');

                foreach ($disabled{$p}->list()) {
                        next if $_ eq '';
                        next PLUGIN if (!exists $fields{$_});
                }

                print "Info: Plugin $p has been re-enabled\n" if $verbose;
                $enabled{$p} = $disabled{$p};
                delete $disabled{$p};
        }

        return;
}

# -----------------------------------------------------------------------------
# Call termination function in each loaded plugin
# -----------------------------------------------------------------------------
sub end_plugins {
        my $p;

        # Enable all disabled plugins so they can be properly ended
        foreach $p (keys %disabled) {
                $enabled{$p} = $disabled{$p};
                delete $disabled{$p};
        }

        foreach $p (keys %enabled) {
                if ($enabled{$p}->can('end')) {
                        print "Info: Ending plugin $p\n" if $verbose;
                        eval '$enabled{$p}->end()';
                        if ($@) {
                                warn "Warning: $p: $@" if $verbose;
                                warn "Warning: $p: Failed to end\n";
                        }
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('d:hp:v', \%opts) or print_usage();

        # Print help/usage information to the screen if necessary
        print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                warn "Error: No input file(s) provided\n";
                print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files = @ARGV;
        $plugin_list = $opts{p} if ($opts{p});
        $plugin_dir = $opts{d} if ($opts{d});
        $verbose = 1 if ($opts{v});

        return;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
Usage: $0 [ -hv ] [ -d dir ] [ -p plugins ] file1 [ file2 ... ]
  -d dir       load plugins from specified directory
  -h           print this help information
  -p plugins   load plugins from comma-delimited list
  -v           print verbose run-time information

USAGE
}
