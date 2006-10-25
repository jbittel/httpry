#!/usr/bin/perl -w

#
# parse_log.pl | created: 6/25/2005
#
# Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the author nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

use strict;
use Getopt::Std;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $VERBOSE    = 0;
my $PLUGIN_DIR = "./plugins";
my $PATTERN    = "\t";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %nameof    = (); # Stores human readable plugin names
my @callbacks = (); # List of initialized plugins
my @plugins   = (); # List of plugin files in directory
my @ignore    = ("sample_plugin.pm", "db_dump.pm", "client_flows.pm", "search_terms.pm");
                    # List of plugins to be ignored on initialization (comma-delimited)

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

        opendir PLUGINS, $plugin_dir or die "Error: Cannot access directory $plugin_dir: $!\n";
                @plugins = grep { /\.pm$/ } readdir(PLUGINS);
        closedir PLUGINS;

        PLUGIN: foreach $plugin (@plugins) {
                foreach (@ignore) {
                        next PLUGIN if $_ eq $plugin;
                }
                print "Loading $plugin_dir/$plugin...\n" if $VERBOSE;
                require "$plugin_dir/$plugin";
        }

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
        my $curr_line; # Current line in input file
        my $curr_file; # Current input file
        my $plugin;
        my @fields;
        my %record;
        my $is_xml_file;

        foreach $curr_file (@input_files) {
                unless (open(INFILE, "$curr_file")) {
                        print "Error: Cannot open $curr_file: $!\n";
                        next;
                }

                if (<INFILE> =~ /<\?xml version=\"1\.0\"\?>/) {
                        $is_xml_file = 1;
                } else {
                        $is_xml_file = 0;
                }
                seek INFILE, 0, 0; # Reset filehandle to start of file

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
        
                        # Strip non-printable chars
                        $curr_line =~ tr/\x80-\xFF//d;

                        if ($is_xml_file) {
                                next unless $curr_line =~ /^<step>/;

                                # Replace XML entity characters
                                $curr_line =~ s/\&amp\;/\&/g;
                                $curr_line =~ s/\&lt\;/</g;
                                $curr_line =~ s/\&gt\;/>/g;
                                $curr_line =~ s/\&apos\;/\'/g;
                                $curr_line =~ s/\&quot\;/\"/g;

                                ($record{"timestamp"})     = ($curr_line =~ /<timestamp>(.*)<\/timestamp>/);
                                ($record{"source-ip"})     = ($curr_line =~ /<source-ip>(.*)<\/source-ip>/);
                                ($record{"dest-ip"})       = ($curr_line =~ /<dest-ip>(.*)<\/dest-ip>/);
                                ($record{"direction"})     = ($curr_line =~ /<direction>(.*)<\/direction>/);
                                ($record{"method"})        = ($curr_line =~ /<method>(.*)<\/method>/);
                                ($record{"host"})          = ($curr_line =~ /<host>(.*)<\/host>/);
                                ($record{"request-uri"})   = ($curr_line =~ /<request-uri>(.*)<\/request-uri>/);
                                ($record{"http-version"})  = ($curr_line =~ /<http-version>(.*)<\/http-version>/);
                                ($record{"status-code"})   = ($curr_line =~ /<status-code>(.*)<\/status-code>/);
                                ($record{"reason-phrase"}) = ($curr_line =~ /<reason-phrase>(.*)<\/reason-phrase>/);
                        } else {
                                next if $curr_line eq "";
                        
                                @fields = split(/$PATTERN/, $curr_line);
                                next if (scalar(@fields != 10)); # Malformed number of fields

                                # Default format:
                                # "Timestamp,Source-IP,Dest-IP,Direction,Method,Host,Request-URI,HTTP-Version,Status-Code,Reason-Phrase"
                                $record{"timestamp"}     = $fields[0];
                                $record{"source-ip"}     = $fields[1];
                                $record{"dest-ip"}       = $fields[2];
                                $record{"direction"}     = $fields[3];
                                $record{"method"}        = $fields[4];
                                $record{"host"}          = $fields[5];
                                $record{"request-uri"}   = $fields[6];
                                $record{"http-version"}  = $fields[7];
                                $record{"status-code"}   = $fields[8];
                                $record{"reason-phrase"} = $fields[9];
                        }
                        
                        # Convert hex encoded chars to ASCII
                        $record{"request-uri-encoded"} = $record{"request-uri"};
                        $record{"request-uri"} =~ s/%25/%/g; # Sometimes '%' chars are double encoded
                        $record{"request-uri"} =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

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
        $plugin_dir  = $PLUGIN_DIR unless ($plugin_dir = $opts{p});

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
  -h ... print this help information and exit
  -p ... load plugins from specified directory
USAGE
}
