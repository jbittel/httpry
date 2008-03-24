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
use Time::Local;
use IO::Compress::Gzip qw(gzip $GzipError);

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------

# Command line parameters
my %opts;
my @dir;
my $dir;
my $file;
my $purge_cnt;
my $purge_size;

my $compress = 0;
my $del_text = 0;

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
        
opendir(DIR, $dir) or die "Error: Cannot open directory '$dir'\n";
@dir = grep !/^\./, readdir(DIR);
closedir(DIR);

&move_file() if $file;

&compress_files() if $compress;
&delete_text_files() if $del_text;

&purge_dir_by_count() if $purge_cnt;
&purge_dir_by_size() if $purge_size;

# -----------------------------------------------------------------------------
# Move current log file to archive directory and rename according to date
# -----------------------------------------------------------------------------
sub move_file {
        my $mday = (localtime)[3];
        my $mon = (localtime)[4] + 1;
        my $year = (localtime)[5] + 1900;

        if (! -e "$dir/$mon-$mday-$year.log") {
                rename "$file", "$dir/$mon-$mday-$year.log";
        } else {
                warn "Error: File '$dir/$mon-$mday-$year.log' already exists\n";
        }

        return;
}

# -----------------------------------------------------------------------------
# Compress all raw log files in the target directory
# -----------------------------------------------------------------------------
sub compress_files {
        my $log_file;

        foreach $log_file (grep /\.log$/, @dir) {
                if (-e "$dir/$log_file.gz") {
                        warn "Error: File '$dir/$log_file.gz' already exists\n";
                        next;
                }

                if (gzip "$dir/$log_file" => "$dir/$log_file.gz") {
                        unlink "$dir/$log_file";
                } else {
                        warn "Error: Cannot compress log file '$log_file': $GzipError\n";
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Delete all text files in the target directory
# -----------------------------------------------------------------------------
sub delete_text_files {
        my $txt_file;

        foreach $txt_file (grep /\.txt$/, @dir) {
                unlink $dir/$txt_file;
        }

        return;
}

# -----------------------------------------------------------------------------
# Remove oldest files if total file count is above specified purge limit
# -----------------------------------------------------------------------------
sub purge_dir_by_count {
        my @logs;
        my $cnt;
 
        @logs = map { $_->[0] }
                sort {
                        $a->[3] <=> $b->[3] or # Sort by year...
                        $a->[1] <=> $b->[1] or # ...then by month...
                        $a->[2] <=> $b->[2]    # ...and finally day
                }
                map { [ $_, /^(\d+)-(\d+)-(\d+)/ ] }
                grep /^\d+-\d+-\d+.*\.(?:gz|log)$/, @dir;

        if (scalar @logs > $purge_cnt) {
                $cnt = scalar @logs - $purge_cnt;
                for (my $i = 0; $i < $cnt; $i++) {
                        unlink $logs[$i];
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Remove oldest files if total file size is above specified size limit
# -----------------------------------------------------------------------------
sub purge_dir_by_size {
        my @logs;
        my $log_file;
        my $size;
 
        @logs = map { $_->[0] }
                sort {
                        $a->[3] <=> $b->[3] or # Sort by year...
                        $a->[1] <=> $b->[1] or # ...then by month...
                        $a->[2] <=> $b->[2]    # ...and finally day
                }
                map { [ $_, /^(\d+)-(\d+)-(\d+)/ ] }
                grep /^\d+-\d+-\d+.*\.(?:gz|log)$/, @dir;

        foreach $log_file (reverse @logs) {
                $size += int((stat($log_file))[7] / 1000000);

                if ($size > $purge_size) {
                        unlink $log_file;
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('c:d:f:hs:tz', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});

        # Copy command line arguments to internal variables
        $dir = $opts{d};
        $file = $opts{f};
        $purge_cnt = $opts{c};
        $purge_size = $opts{s};

        $compress = 1 if ($opts{z});
        $del_text = 1 if ($opts{t});

        if (!$dir) {
                warn "Error: No output directory provided\n";
                &print_usage();
        }
        $dir =~ s/\/$//;

        if (! -e $dir) {
                print "Creating output directory '$dir'\n";
                mkdir $dir;
        }

        return;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
Usage: $0 [ -htz ] [ -c count ] [ -d dir ] [ -f file ] [ -s size ]
  -c count   delete oldest log files above this number
  -d dir     set output directory
  -f file    set input logfile
  -h         print this help information
  -s size    delete oldest log files above this cumulative size (in MB)
  -t         delete text files in target directory
  -z         compress log files

USAGE
}
