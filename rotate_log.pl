#!/usr/bin/perl -w

#
# rotate_log.pl 6/27/2005
#
# Copyright (c) 2005, Jason Bittel. All rights reserved.
# See included LICENSE file for specific licensing information
#

use strict;
use Getopt::Std;
use Time::Local;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PROG_NAME = "rotate_log.pl";
my $PROG_VER = "0.0.3";
my $TAR = "tar";
my $GZIP = "gzip";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %opts;
my $compress = 0;
my $del_text = 0;
my $input_file;
my $purge_limit;
my $output_dir;
my @dir_list;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();

# Read contents of directory into array
$output_dir =~ s/\/$//; # Remove trailing slash
opendir(DIR, $output_dir) || die "\nError: cannot open directory $output_dir\n";
        @dir_list = map "$output_dir/$_", grep !/^\./, readdir(DIR);
closedir(DIR);

# Process log file/directory commands
if ($compress) {
        &compress_files();
}
if ($del_text) {
        foreach (grep /\.txt$/, @dir_list) {
                unlink;
        }
}
if ($input_file) {
        &move_file();
}
if ($purge_limit) {
        &purge_dir();
}

# -----------------------------------------------------------------------------
# Iterate through log files, compressing them in tar.gz format
# -----------------------------------------------------------------------------
sub compress_files {
        my $log_file;
        my $filename;
        my $dir;

        $dir = `pwd`; # Danger, not portable
        chdir($output_dir); # Must be in local dir for relative paths in tar file

        foreach $log_file (grep /\.log$/, @dir_list) {
                # Compress log file
                $log_file =~ /.*\/(.+?)\.log$/;
                $filename = $1;

                if ((system "$TAR cf - $filename.log | $GZIP -9 > $output_dir/$filename.tar.gz") == 0) {
                        unlink $log_file;
                } else {
                        print "\nError: cannot compress log file '$log_file'\n";
                }
        }

        chdir($dir);
}

# -----------------------------------------------------------------------------
# Move current log file to archive directory and rename according to date
# -----------------------------------------------------------------------------
sub move_file {
        my $mday;
        my $mon;
        my $year;

        if (-e $input_file) {
                # Create destination filename
                $mday = (localtime)[3];
                $mon = (localtime)[4] + 1;
                $year = (localtime)[5] + 1900;

                if (! -e $output_dir) {
                        mkdir $output_dir;
                }

                rename "$input_file", "$output_dir/$mon-$mday-$year.log";
        } else {
                print "\nError: input file '$input_file' does not exist\n";
        }
}

# -----------------------------------------------------------------------------
# Remove oldest files if total file count is above specified purge limit
# -----------------------------------------------------------------------------
sub purge_dir {
        my @logs;
        my $del_count;

        # Sort all compressed archives in the directory according
        # to the date in the filename
        @logs = map { $_->[0] }
                sort { $a->[3] <=> $b->[3] # Sort by year...
                                ||
                       $a->[1] <=> $b->[1] # ...then by month...
                                ||
                       $a->[2] <=> $b->[2] # ...and finally day
                }
                map { [ $_, /(\d+)-(\d+)-(\d+)/ ] }
                grep /\.tar.gz$/, @dir_list;

        # Delete oldest archives from directory if the total
        # number of files is above the provided purge limit
        if (scalar @logs > $purge_limit) {
                $del_count = scalar @logs - $purge_limit;
                for (my $i = 0; $i < $del_count; $i++) {
                        unlink $logs[$i];
                }
        }
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('cd:hi:p:t', \%opts) or &print_usage();

        # TODO: add -m option that limits archive directory to a max size

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});

        # Copy command line arguments to internal variables
        $compress = 1 if ($opts{c});
        $del_text = 1 if ($opts{t});

        $input_file = 0 unless ($input_file = $opts{i});
        $purge_limit = 0 unless ($purge_limit = $opts{p});
        die "\nError: Need output directory\n" unless ($output_dir = $opts{d});
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
$PROG_NAME version $PROG_VER
Usage: $PROG_NAME [-ct] [-d dir] [-i file] [-p count]
USAGE
}
