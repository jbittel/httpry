#!/usr/bin/perl -w

#
# client_flows.pl | created: 2/16/2006
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
use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PATTERN      = "\t";
my $SENDMAIL     = "/usr/lib/sendmail -i -t";
my $FLOW_TIMEOUT = 300;
my $TAGGED_LIMIT = 15;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %opts        = ();
my @input_files = ();
my $tagged_detail;
my $all_detail;
my $email_addr;
my $hitlist_file;
my $output_file;
my $flows_summary;

my $start_time; # Start tick for timing code
my $end_time;   # End tick for timing code

# Counter variables
my $file_cnt               = 0;
my $size_cnt               = 0;
my $total_line_cnt         = 0;
my $flow_cnt               = 0;
my $flow_line_cnt          = 0;
my $flow_min_len           = 999999;
my $flow_max_len           = 0;
my $tagged_flows_cnt       = 0;
my $total_tagged_lines_cnt = 0;
my $max_concurrent         = 0;

# Data structures
my %flow_info       = (); # Holds metadata about each flow
my %flow_data_lines = (); # Holds actual log file lines for each flow
my %tagged_flows    = (); # Ip/flow/hostname information for tagged flows
my %output_flows    = (); # Pruned and cleaned tagged flows for display
my %history         = (); # Holds history of content checks to avoid matching
my @hitlist         = ();

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------
&get_arguments();
&delete_text_files();
&parse_flows();
&write_summary_file() if $output_file;
&send_email() if $email_addr;

# -----------------------------------------------------------------------------
# Break input log files into flows and perform content checks
# -----------------------------------------------------------------------------
sub parse_flows {
        my $curr_line;
        my $curr_file;
        my ($timestamp, $epochstamp, $src_ip, $dst_ip, $direction, $method, $hostname, $uri);

        $start_time = (times)[0];
        foreach $curr_file (@input_files) {
                unless(open(INFILE, "$curr_file")) {
                        print "Warning: Skipping $curr_file: $!\n";
                        next;
                }

                $file_cnt++;
                $size_cnt += int((stat(INFILE))[7] / 1000000);

                foreach $curr_line (<INFILE>) {
                        chomp $curr_line;
                        next if $curr_line eq "";
                        $total_line_cnt++;

                        # Convert hex characters to ASCII
                        $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
                        $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

                        if ((keys %flow_info) > $max_concurrent) {
                                $max_concurrent = keys %flow_info;
                        }

                        ($timestamp, $src_ip, $dst_ip, $direction, $method, $hostname, $uri) = split(/$PATTERN/, $curr_line);
                        next if (!$timestamp or !$src_ip);
                        next if $direction ne '>';

                        # Convert timestamp of current record to epoch seconds
                        $timestamp =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
                        $epochstamp = timelocal($6, $5, $4, $2, $1 - 1, $3);

                        if (!exists $flow_info{$src_ip}) { # No existing flow so begin a new one
                                $flow_cnt++;
                                $flow_line_cnt++;

                                $flow_info{$src_ip}->{"id"} = $flow_cnt;
                                $flow_info{$src_ip}->{"src_ip"} = $src_ip;
                                $flow_info{$src_ip}->{"start_time"} = $timestamp;
                                $flow_info{$src_ip}->{"end_time"} = $timestamp;
                                $flow_info{$src_ip}->{"start_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"end_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"length"} = 1;
                                $flow_info{$src_ip}->{"tagged_lines"} = 0;

                                push(@{$flow_data_lines{$src_ip}}, $curr_line);

                                if ($hitlist_file && &content_check($hostname, $uri)) {
                                        $tagged_flows{$src_ip}->{$flow_info{$src_ip}->{"id"}}->{$hostname}++;
                                        $flow_info{$src_ip}->{"tagged_lines"}++;
                                }
                        } else { # Existing flow found so update data as necessary
                                $flow_line_cnt++;

                                $flow_info{$src_ip}->{"end_time"} = $timestamp;
                                $flow_info{$src_ip}->{"end_epoch"} = $epochstamp;
                                $flow_info{$src_ip}->{"length"}++;

                                push(@{$flow_data_lines{$src_ip}}, $curr_line);

                                if ($hitlist_file && &content_check($hostname, $uri)) {
                                        $tagged_flows{$src_ip}->{$flow_info{$src_ip}->{"id"}}->{$hostname}++;
                                        $flow_info{$src_ip}->{"tagged_lines"}++;
                                }
                        }

                        &timeout_flows($epochstamp);
                }
        }

        $end_time = (times)[0];
        &timeout_flows(0);

        return;
}

# -----------------------------------------------------------------------------
# Search history for specified content; returns true if match occurs; store
# results of search in hash so we don't have to match the same text twice
#
# Potential hash values: -1 unmatched / 1 matched / 0 no match
# -----------------------------------------------------------------------------
sub content_check {
        my $hostname = shift;
        my $uri = shift;
        my $word;

        $hostname = quotemeta($hostname);
        $uri = quotemeta($uri);

        $history{$hostname} = -1 if (!defined $history{$hostname});
        $history{$uri} = -1 if (!defined $history{$uri});

        return 1 if (($history{$hostname} == 1) || ($history{$uri} == 1));
        return 0 if (($history{$hostname} == 0) && ($history{$uri} == 0));

        foreach $word (@hitlist) {
                if ($hostname =~ /$word/i) {
                        $history{$hostname} = 1;
                        return 1;
                }

                if ($uri =~ /$word/i) {
                        $history{$uri} = 1;
                        return 1;
                }
        }

        $history{$hostname} = 0;
        $history{$uri} = 0;

        return 0;
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: flush to disk and delete hash entries
# -----------------------------------------------------------------------------
sub timeout_flows {
        my $epochstamp = shift;
        my $flow_str;
        my $ip;
        my $hostname;

        foreach $ip (keys %flow_info) {
                if ($epochstamp) {
                        next unless (($epochstamp - $flow_info{$ip}->{"end_epoch"}) > $FLOW_TIMEOUT);
                }

                # Set minimum/maximum flow length
                $flow_min_len = $flow_info{$ip}->{"length"} if ($flow_info{$ip}->{"length"} < $flow_min_len);
                $flow_max_len = $flow_info{$ip}->{"length"} if ($flow_info{$ip}->{"length"} > $flow_max_len);

                &append_host_subfile("$all_detail/detail_$ip.txt", $ip) if $all_detail;

                # Check if we have enough hits to be interested in the flow
                if ($flow_info{$ip}->{"tagged_lines"} > $TAGGED_LIMIT) {
                        $tagged_flows_cnt++;
                        $total_tagged_lines_cnt += $flow_info{$ip}->{"tagged_lines"};

                        # Copy data to output hash so we can prune and reformat
                        $flow_str = "[$flow_info{$ip}->{'start_time'}]->[$flow_info{$ip}->{'end_time'}]";
                        foreach $hostname (keys %{$tagged_flows{$ip}->{$flow_info{$ip}->{"id"}}}) {
                                $output_flows{$ip}->{$flow_str}->{$hostname} = $tagged_flows{$ip}->{$flow_info{$ip}->{"id"}}->{$hostname};
                        }
                        delete $tagged_flows{$ip};

                        &append_host_subfile("$tagged_detail/tagged_$ip.txt", $ip) if $tagged_detail;
                } else {
                        # Not an interesting flow, so delete any tagged lines/IPs that exist
                        delete $tagged_flows{$ip}->{$flow_info{$ip}->{"id"}} if exists $tagged_flows{$ip};
                        delete $tagged_flows{$ip} if (keys %{$tagged_flows{$ip}} == 0);
                }

                delete $flow_info{$ip};
                delete $flow_data_lines{$ip};
        }

        return;
}

# -----------------------------------------------------------------------------
# Write detail subfile for specified client ip
# -----------------------------------------------------------------------------
sub append_host_subfile {
        my $path = shift;
        my $ip   = shift;
        my $line;

        open(HOSTFILE, ">>$path") or die "Error: Cannot open $path: $!\n";

        print HOSTFILE '>' x 80 . "\n";
        foreach $line (@{$flow_data_lines{$ip}}) {
                $line =~ tr/\x80-\xFF//d; # Strip non-printable chars
                print HOSTFILE $line, "\n";
        }
        print HOSTFILE '<' x 80 . "\n";

        close(HOSTFILE);

        return;
}

# -----------------------------------------------------------------------------
# Remove text detail files to ensure they don't append between runs
# -----------------------------------------------------------------------------
sub delete_text_files {
        $tagged_detail =~ s/\/$//; # Remove trailing slash
        $all_detail    =~ s/\/$//;

        if ($tagged_detail) {
                opendir(DIR, $tagged_detail) or die "Error: Cannot open directory $tagged_detail: $!\n";
                        foreach (grep /^tagged_.+\.txt$/, readdir(DIR)) {
                                unlink;
                        }
                closedir(DIR);
        }

        if ($all_detail) {
                opendir(DIR, $all_detail) or die "Error: Cannot open directory $all_detail: $!\n";
                        foreach (grep /^detail_.+\.txt$/, readdir(DIR)) {
                                unlink;
                        }
                closedir(DIR);
        }


        return;
}

# -----------------------------------------------------------------------------
# Write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $ip;
        my $flow;
        my $hostname;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nSUMMARY STATS\n\n";
        print OUTFILE "Generated:    " . localtime() . "\n";
        print OUTFILE "Total files:  $file_cnt\n";
        print OUTFILE "Total size:   $size_cnt MB\n";
        print OUTFILE "Total lines:  $total_line_cnt\n";
        print OUTFILE "Total time:   " . sprintf("%.2f", $end_time - $start_time) . " secs\n";

        print OUTFILE "\n\nFLOW STATS\n\n";
        print OUTFILE "Flow count:      $flow_cnt\n";
        print OUTFILE "Flow lines:      $flow_line_cnt\n";
        print OUTFILE "Max Concurrent:  $max_concurrent\n";
        print OUTFILE "Min/Max/Avg:     $flow_min_len/$flow_max_len/" . sprintf("%d", $flow_line_cnt / $flow_cnt) . "\n";

        if ($hitlist_file) {
                print OUTFILE "Tagged IPs:    " . (keys %output_flows) . "\n";
                print OUTFILE "Tagged flows:  $tagged_flows_cnt\n";
                print OUTFILE "Tagged lines:  $total_tagged_lines_cnt\n";
                print OUTFILE "\n\nFLOW CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                if ($total_tagged_lines_cnt > 0) {
                        foreach $ip (map { inet_ntoa $_ }
                                     sort
                                     map { inet_aton $_ } keys %output_flows) {
                                print OUTFILE "$ip\n";

                                foreach $flow (sort keys %{$output_flows{$ip}}) {
                                        print OUTFILE "\t$flow\n";

                                        foreach $hostname (sort keys %{$output_flows{$ip}->{$flow}}) {
                                                print OUTFILE "\t\t$hostname\t$output_flows{$ip}->{$flow}->{$hostname}\n";
                                        }
                                }
                                print OUTFILE "\n";
                        }
                } else {
                        print OUTFILE "*** No tagged flows found\n";
                }
        }

        close(OUTFILE);

        return;
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
                Subject => 'httpry Content Check Report - ' . localtime(),
                Type    => 'multipart/mixed'
        );

        $msg->attach(
                Type => 'TEXT',
                Data => 'httpry content check report for ' . localtime()
        );

        $msg->attach(
                Type        => 'TEXT',
                Path        => "$output_file",
                Filename    => "$output_filename",
                Disposition => 'attachment'
        );

        $msg->send('sendmail', $SENDMAIL) or die "Error: Cannot send mail: $!\n";

        return;
}

# -----------------------------------------------------------------------------
# Retrieve and process command line arguments
# -----------------------------------------------------------------------------
sub get_arguments {
        getopts('a:e:hl:o:t:', \%opts) or &print_usage();

        # Print help/usage information to the screen if necessary
        &print_usage() if ($opts{h});
        unless ($ARGV[0]) {
                print "Error: No input file(s) provided\n";
                &print_usage();
        }

        # Copy command line arguments to internal variables
        @input_files   = @ARGV;
        $all_detail    = 0 unless ($all_detail    = $opts{a});
        $email_addr    = 0 unless ($email_addr    = $opts{e});
        $hitlist_file  = 0 unless ($hitlist_file  = $opts{l});
        $output_file   = 0 unless ($output_file   = $opts{o});
        $tagged_detail = 0 unless ($tagged_detail = $opts{t});

        # Check for required options and combinations
        if (!$output_file) {
                print "Error: No output file provided\n";
                &print_usage();
        }
        if ($tagged_detail && !$hitlist_file) {
                print "Warning: -t requires -l, ignoring\n";
                $tagged_detail = 0;
        }

        # Read in option files
        if ($hitlist_file) {
                open(HITLIST, "$hitlist_file") or die "Error: Cannot open $hitlist_file: $!\n";
                        foreach (<HITLIST>) {
                                chomp;
                                next if /^#/; # Skip comments
                                push @hitlist, $_;
                        }
                close(HITLIST);
        }

        return;
}

# -----------------------------------------------------------------------------
# Print usage/help information to the screen and exit
# -----------------------------------------------------------------------------
sub print_usage {
        die <<USAGE;
Usage: $0 [-h] [-a dir] [-e email] [-l file] [-o file] [-t dir] file1 [file2 ...]
  -a ... directory for all detail records (implicit enable)
  -e ... email recipient for output file
  -h ... print this help information and exit
  -l ... hitlist file for content checks (implicit enable)
  -o ... output file for summary and content check data
  -t ... directory for tagged detail records (implicit enable)
USAGE
}
