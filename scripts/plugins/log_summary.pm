#!/usr/bin/perl -w

#
# log_summary.pm | created: 6/25/2005
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

package log_summary;

use File::Basename;
use MIME::Lite;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $SENDMAIL    = "/usr/lib/sendmail -i -t";
my $SUMMARY_CAP = 10;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %top_hosts      = ();
my %top_talkers    = ();
my %filetypes      = ();
my %response_codes = ();
my $total_line_cnt = 0;
my $ext_cnt        = 0;
my $srv_responses  = 0;
my $start_time;
my $end_time;


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

        $start_time = (times)[0];
        
        return 1;
}

sub main {
        my $self   = shift;
        my $record = shift;

        return unless exists $record->{"direction"};

        # Gather statistics
        $total_line_cnt++;

        if ($record->{"direction"} eq '>') {
                $top_hosts{$record->{"host"}}++ if exists $record->{"host"};
                $top_talkers{$record->{"source-ip"}}++ if exists $record->{"source-ip"};

                if ($filetype && (exists $record->{"request-uri"})) {
                        if (($record->{"request-uri"} =~ /\.([\w\d]{2,5}?)$/i) or 
                            ($record->{"request-uri"} =~ /\/.*\.([\w\d]{2,5}?)\?/i)) {
                                $ext_cnt++;
                                $filetypes{lc($1)}++;
                        }
                }
        } elsif ($record->{"direction"} eq '<') {
                $response_codes{$record->{"status-code"}}++ if exists $record->{"status-code"};
                $srv_responses++;
        }

        return;
}

sub end {
        $end_time = (times)[0];
        
        &write_output_file();
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
        $summary_cap = $SUMMARY_CAP unless ($summary_cap > 0);

        return 1;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $key;
        my $count = 0;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nLOG SUMMARY\n\n";
        print OUTFILE "Generated:       " . localtime() . "\n";
        print OUTFILE "Total lines:     " . $total_line_cnt . "\n";
        print OUTFILE "Client count:    " . keys(%top_talkers) . "\n";
        print OUTFILE "Server count:    " . keys(%top_hosts) . "\n";
        print OUTFILE "Extension count: " . keys(%filetypes) . "\n" if ($filetype);
        print OUTFILE "Total run time:  " . sprintf("%.1f", $end_time - $start_time) . " secs\n";

        if ((keys %top_hosts) > 0) {
                print OUTFILE "\n\nTOP $summary_cap VISITED HOSTS\n\n";
                foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                        print OUTFILE "$key\t$top_hosts{$key}\t" . percent_of($top_hosts{$key}, $total_line_cnt) . "%\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ((keys %top_talkers) > 0) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap TOP TALKERS\n\n";
                foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                        print OUTFILE "$key\t$top_talkers{$key}\t" . percent_of($top_talkers{$key}, $total_line_cnt) . "%\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ((keys %response_codes) > 0) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap RESPONSE CODES\n\n";
                foreach $key (sort { $response_codes{$b} <=> $response_codes{$a} } keys %response_codes) {
                        print OUTFILE "$key\t$response_codes{$key}\t" . percent_of($response_codes{$key}, $srv_responses) . "%\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ($filetype && ((keys %filetypes) > 0)) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap FILE EXTENSIONS\n\n";
                foreach $key (sort { $filetypes{$b} <=> $filetypes{$a} } keys %filetypes) {
                        print OUTFILE "$key\t$filetypes{$key}\t" . percent_of($filetypes{$key}, $ext_cnt) . "%\n";
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
                From    => 'noreply@example.com',
                To      => "$email_addr",
                Subject => 'httpry Log Summary - ' . localtime(),
                Type    => 'multipart/mixed'
        );

        $msg->attach(
                Type => 'TEXT',
                Data => 'httpry log summary for ' . localtime()
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
