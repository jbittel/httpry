#!/usr/bin/perl -w

#
# client_flows.pm | created: 9/20/2006
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

#
# This is an example plugin for the perl parse script parse_log.pl.  It shows
# the basic structure of a simple plugin and provides a good starting point for
# writing a custom plugin. Some of the other included plugins will also provide
# a good idea of how the different pieces work.
#

package client_flows;

use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $SENDMAIL     = "/usr/lib/sendmail -i -t";
my $FLOW_TIMEOUT = 300;
my $TAGGED_LIMIT = 15;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
# Counter variables
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
my @hitlist         = (); # List of content check keywords

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

        &delete_text_files();

        return 1;
}

sub main {
        my $self   = shift;
        my $record = shift;
        my $curr_line;

        if ((keys %flow_info) > $max_concurrent) {
                $max_concurrent = keys %flow_info;
        }

        return if $record->{"direction"} ne '>';

        $curr_line = "$record->{'timestamp'}\t$record->{'source-ip'}\t$record->{'dest-ip'}\t$record->{'host'}\t$record->{'request-uri'}";

        # Convert timestamp of current record to epoch seconds
        $record->{"timestamp"} =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
        $epochstamp = timelocal($6, $5, $4, $2, $1 - 1, $3);

        if (!exists $flow_info{$record->{"source-ip"}}) { # No existing flow so begin a new one
                $flow_cnt++;
                $flow_line_cnt++;

                $flow_info{$record->{"source-ip"}}->{"id"} = $flow_cnt;
                $flow_info{$record->{"source-ip"}}->{"src_ip"} = $record->{"source-ip"};
                $flow_info{$record->{"source-ip"}}->{"start_time"} = $record->{"timestamp"};
                $flow_info{$record->{"source-ip"}}->{"end_time"} = $record->{"timestamp"};
                $flow_info{$record->{"source-ip"}}->{"start_epoch"} = $epochstamp;
                $flow_info{$record->{"source-ip"}}->{"end_epoch"} = $epochstamp;
                $flow_info{$record->{"source-ip"}}->{"length"} = 1;
                $flow_info{$record->{"source-ip"}}->{"tagged_lines"} = 0;

                push(@{$flow_data_lines{$record->{"source-ip"}}}, $curr_line);

                if ($hitlist_file && &content_check($record->{"host"}, $record->{"request-uri"})) {
                        $tagged_flows{$record->{"source-ip"}}->{$flow_info{$record->{"source-ip"}}->{"id"}}->{$record->{"host"}}++;
                        $flow_info{$record->{"source-ip"}}->{"tagged_lines"}++;
                }
        } else { # Existing flow found so update data as necessary
                $flow_line_cnt++;

                $flow_info{$record->{"source-ip"}}->{"end_time"} = $record->{"timestamp"};
                $flow_info{$record->{"source-ip"}}->{"end_epoch"} = $epochstamp;
                $flow_info{$record->{"source-ip"}}->{"length"}++;

                push(@{$flow_data_lines{$record->{"source-ip"}}}, $curr_line);

                if ($hitlist_file && &content_check($record->{"host"}, $record->{"request-uri"})) {
                        $tagged_flows{$record->{"source-ip"}}->{$flow_info{$record->{"source-ip"}}->{"id"}}->{$record->{"host"}}++;
                        $flow_info{$record->{"source-ip"}}->{"tagged_lines"}++;
                }
        }

        &timeout_flows($epochstamp);

        return;
}

sub end {
        &timeout_flows(0);
        &write_summary_file();
        &send_email() if $email_addr;

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub load_config {
        my $plugin_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$plugin_dir/" . __PACKAGE__ . ".cfg") {
                require "$plugin_dir/" . __PACKAGE__ . ".cfg";
        }

        # Check for required options and combinations
        if (!$output_file) {
                print "Error: No output file provided\n";
                return 0;
        }
        if ($tagged_dir && !$hitlist_file) {
                print "Warning: -t requires -l, ignoring\n";
                $tagged_dir = 0;
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

        return 1;
}

# -----------------------------------------------------------------------------
# Remove text detail files to ensure they don't append between runs
# -----------------------------------------------------------------------------
sub delete_text_files {
        $tagged_dir =~ s/\/$//; # Remove trailing slash
        $all_dir    =~ s/\/$//; # ...

        if ($tagged_dir) {
                opendir(DIR, $tagged_dir) or die "Error: Cannot open directory $tagged_dir: $!\n";
                        foreach (grep /^tagged_.+\.txt$/, readdir(DIR)) {
                                unlink;
                        }
                closedir(DIR);
        }

        if ($all_dir) {
                opendir(DIR, $all_dir) or die "Error: Cannot open directory $all_dir: $!\n";
                        foreach (grep /^detail_.+\.txt$/, readdir(DIR)) {
                                unlink;
                        }
                closedir(DIR);
        }


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
# Handle end of flow duties: flush to disk and delete hash entries; pass a
# zero to force all active flows to be flushed
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

                &append_host_subfile("$all_dir/detail_$ip.txt", $ip) if $all_dir;

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

                        &append_host_subfile("$tagged_dir/tagged_$ip.txt", $ip) if $tagged_dir;
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
# Write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $ip;
        my $flow;
        my $hostname;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nCLIENT FLOWS SUMMARY\n\n";
        print OUTFILE "Generated:      " . localtime() . "\n";
        print OUTFILE "Flow count:     $flow_cnt\n";
        print OUTFILE "Flow lines:     $flow_line_cnt\n";
        print OUTFILE "Max Concurrent: $max_concurrent\n";
        print OUTFILE "Min/Max/Avg:    $flow_min_len/$flow_max_len/" . sprintf("%d", $flow_line_cnt / $flow_cnt) . "\n";

        if ($hitlist_file) {
                print OUTFILE "Tagged IPs:     " . (keys %output_flows) . "\n";
                print OUTFILE "Tagged flows:   $tagged_flows_cnt\n";
                print OUTFILE "Tagged lines:   $total_tagged_lines_cnt\n";
                print OUTFILE "\n\nCLIENT FLOWS CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                if ($total_tagged_lines_cnt > 0) {
                        foreach $ip (map { inet_ntoa $_ }
                                     sort
                                     map { inet_aton $_ } keys %output_flows) {
                                print OUTFILE "$ip\n";

                                foreach $flow (sort keys %{$output_flows{$ip}}) {
                                        print OUTFILE "\t$flow\n";

                                        foreach $hostname (sort keys %{$output_flows{$ip}->{$flow}}) {
                                                print OUTFILE "\t\t($output_flows{$ip}->{$flow}->{$hostname})\t$hostname\n";
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

1;
