#!/usr/bin/perl -w

#
# process_log.pm 6/25/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

package log_summary;

use Getopt::Std;
use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PROG_NAME = "log_summary.pm";
my $PLUG_VER = "0.0.1";
my $SENDMAIL = "/usr/lib/sendmail -i -t";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %ip_hits = ();
my %host_hits = ();
my %content_hits = ();
my $total_line_cnt = 0;
my $line_cnt = 0;
my $ip_cnt = 0;
my $host_cnt = 0;
my $size_cnt = 0;
my $file_cnt = 0;
my @hits;
my @hitlist;

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

&main::register_plugin(__PACKAGE__);

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $plugin_dir = shift;
        
        if (&load_config($plugin_dir) == 0) {
                return 0;
        }

        return 1;
}

sub main {
        my $self = shift;
        my $data = shift;

        &process_data($data);
}

sub end {
        &write_output_file();
        &send_email() if $email_addr;
}

# -----------------------------------------------------------------------------
#
# -----------------------------------------------------------------------------
sub process_data {
        my $curr_line = shift;

        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);

        next if (!$hostname or !$src_ip or !$uri);
        
        # Gather statistics

        return;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $key;
        my $subkey;
        my $count = 0;

        open(OUTFILE, ">$output_file") || die "Error: Cannot open $output_file - $!\n";

        print OUTFILE "\n\nSUMMARY STATS\n\n";
        print OUTFILE "Generated:\t".localtime()."\n";
        print OUTFILE "Total files:\t$file_cnt\n";
        print OUTFILE "Total size:\t$size_cnt MB\n";
        print OUTFILE "Total lines:\t$total_line_cnt\n";

        print OUTFILE "\n\nTOP $summary_cap VISITED HOSTS\n\n";
        foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                print OUTFILE "$key\t$top_hosts{$key}\t".percent_of($top_hosts{$key}, $line_cnt)."%\n";
                $count++;
                last if ($count == $summary_cap);
        }

        $count = 0;
        print OUTFILE "\n\nTOP $summary_cap TOP TALKERS\n\n";
        foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                print OUTFILE "$key\t$top_talkers{$key}\t".percent_of($top_talkers{$key}, $line_cnt)."%\n";
                $count++;
                last if ($count == $summary_cap);
        }

        if ($filetype) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap FILE EXTENSIONS\n\n";
                foreach $key (sort { $filetypes{$b} <=> $filetypes{$a} } keys %filetypes) {
                        print OUTFILE "$key\t$filetypes{$key}\t".percent_of($filetypes{$key}, $ext_cnt)."%\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        close(OUTFILE);
        
        return;
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
# Send email to specified address and attach output file
# -----------------------------------------------------------------------------
sub send_email {
        my $msg;
        my $output_filename = basename($output_file);

        $msg = MIME::Lite->new(
                From    => 'admin@corban.edu',
                To      => "$email_addr",
                Subject => 'HTTPry Log Report - ' . localtime(),
                Type    => 'multipart/mixed'
                );

        $msg->attach(
                Type => 'TEXT',
                Data => 'HTTPry log report for ' . localtime()
                );

        $msg->attach(
                Type        => 'TEXT',
                Path        => "$output_file",
                Filename    => "$output_filename",
                Disposition => 'attachment'
                );

        $msg->send('sendmail', $SENDMAIL) || die "Error: Cannot send mail - $!\n";
        
        return;
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub load_config {
        my $plugin_dir = shift;
        
        # Load config file; by default in same directory as plugin
        require "$plugin_dir/" . __PACKAGE__ . ".cfg";

        # Check for required options and combinations
        if (!$output_file) {
                print "Error: no output file provided\n";
                return 0;
        }

        return 1;
}

1;
