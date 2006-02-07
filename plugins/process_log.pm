#!/usr/bin/perl -w

#
# process_log.pm 6/25/2005
#
# Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

package process_log;

#use strict;
use Getopt::Std;
use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PROG_NAME = "process_log.pm";
my $PROG_VER = "0.0.5";
my $SENDMAIL = "/usr/lib/sendmail -i -t";
my $PRUNE_LIMIT = 5;  # When pruning content hits tree, discard hits below this value

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

&main::register_plugin(__PACKAGE__);

sub new {
        return bless {};
}

sub init {
        if (&load_config() < 0) {
                return -1;
        }
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

        if ($check_ip && ($check_ip eq $src_ip)) {
                $ip_cnt++;
                $ip_hits{$hostname}++;
        }

        if ($check_host && ($check_host eq $hostname)) {
                $host_cnt++;
                $host_hits{$src_ip}++;
        }

        if ($hitlist_file) {
                if (&content_check($hostname, $uri)) {
                        $content_hits{$src_ip}->{$hostname}++;
                        push @hits, $curr_line;
                }
        }
}

# -----------------------------------------------------------------------------
# Search fields for specified content
# -----------------------------------------------------------------------------
sub content_check {
        my $hostname = shift;
        my $uri = shift;
        my $word;

        $hostname = quotemeta($hostname);
        $uri = quotemeta($uri);
        foreach $word (@hitlist) {
                chomp $word;
                if (($hostname =~ /$word/i) || ($uri =~ /$word/i)) {
                        return 1;
                }
        }

        return 0;
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
# Create subfile for each host tagged in content checks
# -----------------------------------------------------------------------------
sub write_host_subfiles {
        my $curr_line;
        my $ip;

        foreach $ip (keys %content_hits) {
                open(HOSTFILE, ">>$host_detail/detail_$ip.txt") || die "\nError: cannot open $host_detail/$ip.txt - $!\n";

                foreach $curr_line (@hits) {
                        my @record;

                        @record = split(/$PATTERN/, $curr_line);
                        print HOSTFILE "$curr_line\n" if ($record[1] eq $ip);
                }

                close(HOSTFILE);
        }
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $key;
        my $subkey;
        my $count = 0;

        open(OUTFILE, ">$output_file") || die "\nError: Cannot open $output_file - $!\n";

        if ($log_summary) {
                print OUTFILE "\n\nSUMMARY STATS\n\n";
                print OUTFILE "Generated:\t".localtime()."\n";
                print OUTFILE "Total files:\t$file_cnt\n";
                print OUTFILE "Total size:\t$size_cnt MB\n";
                print OUTFILE "Total lines:\t$total_line_cnt\n";
                print OUTFILE "Total time:\t".sprintf("%.2f", $end_time - $start_time)." secs\n";

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

        if ($check_host) {
                print OUTFILE "\n\nIP SUMMARY FOR $check_host\n\n";
                foreach $key (sort { $host_hits{$b} <=> $host_hits{$a} } keys %host_hits) {
                        print OUTFILE "$key\t$host_hits{$key}\t".percent_of($host_hits{$key}, $host_cnt)."%\n";
                }
        }

        if ($check_ip) {
                print OUTFILE "\n\nHOST SUMMARY FOR $check_ip\n\n";
                foreach $key (sort { $ip_hits{$b} <=> $ip_hits{$a} } keys %ip_hits) {
                        print OUTFILE "$key\t$ip_hits{$key}\t".percent_of($ip_hits{$key}, $ip_cnt)."%\n";
                }
        }

        if ($hitlist_file) {
                print OUTFILE "\n\nURI CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                &prune_content_hits();

                if (scalar(%content_hits) > 0) {
                        # Print sorted list of IP addresses and hostnames
                        foreach $key (map { inet_ntoa $_ }
                                      sort
                                      map { inet_aton $_ } keys %content_hits) {
                                print OUTFILE "$key\n";
                                foreach $subkey (sort keys %{ $content_hits{$key} }) {
                                        print OUTFILE "\t$subkey\t$content_hits{$key}->{$subkey}\n";
                                }
                                print OUTFILE "\n";
                        }

                        &write_host_subfiles() if $host_detail;
                } else {
                        print OUTFILE "No tagged records found\n";
                }
        }

        close(OUTFILE);
}

# -----------------------------------------------------------------------------
# Prune content hits hash tree to remove all small and empty values
# -----------------------------------------------------------------------------
sub prune_content_hits {
        my $key;
        my $subkey;

        foreach $key (keys %content_hits) {
                foreach $subkey (keys %{ $content_hits{$key} }) {
                        if ($content_hits{$key}->{$subkey} <= $PRUNE_LIMIT) {
                                delete $content_hits{$key}->{$subkey};
                        }
                }

                if (scalar keys(%{ $content_hits{$key} }) == 0) {
                        delete $content_hits{$key};
                }
        }
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

        $msg->send('sendmail', $SENDMAIL) || die "\nError: Cannot send mail - $!\n";
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub load_config {
        # Load config file; by default in same directory as plugin
        require "./plugins/" . __PACKAGE__ . ".cfg";

        # Check for required options and combinations
        if (!$output_file) {
                print "\nError: no output file provided\n";
                return -1;
        }
        if (!$hitlist_file && $host_detail) {
                print "\nError: cannot build host detail files without hitlist file\n";
                return -1;
        }
        if (!$log_summary && !$hitlist_file && !$check_ip && !$check_host && !$filetype) {
                print "\nError: no processing option selected\n";
                return -1;
        }

        # Read in option files
        if ($hitlist_file) {
                open(HITLIST, "$hitlist_file") || die "\nError: Cannot open $hitlist_file - $!\n";
                        @hitlist = <HITLIST>;
                close(HITLIST);
        }

        return 0;
}

1;
