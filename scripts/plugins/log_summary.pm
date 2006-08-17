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
my $PATTERN     = "\t";
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

        return;
}

sub end {
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
                print "Error: no output file provided\n";
                return 0;
        }
        $summary_cap = $SUMMARY_CAP unless ($summary_cap > 0);

        return 1;
}

# -----------------------------------------------------------------------------
# Handle each line of data
# -----------------------------------------------------------------------------
sub process_data {
        my $curr_line = shift;
        my @fields = ();

        @fields = split(/$PATTERN/, $curr_line);
        return if scalar @fields < 10; # Missing data

        # Gather statistics
        $total_line_cnt++;

        if ($fields[3] eq '>') {
                $top_hosts{$fields[5]}++;
                $top_talkers{$fields[1]}++;

                if ($filetype && ($fields[6] =~ /\.([\w\d]{2,5}?)$/i)) {
                        $ext_cnt++;
                        $filetypes{lc($1)}++;
                }
        } elsif ($fields[3] eq '<') {
                $response_codes{$fields[8]}++;
                $srv_responses++;
        }

        return;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $key;
        my $count = 0;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nSUMMARY STATS\n\n";
        print OUTFILE "Generated:        " . localtime() . "\n";
        print OUTFILE "Total lines:      " . $total_line_cnt . "\n";
        print OUTFILE "Client count:     " . keys(%top_talkers) . "\n";
        print OUTFILE "Server count:     " . keys(%top_hosts) . "\n";
        print OUTFILE "Extension count:  " . keys(%filetypes) . "\n" if ($filetype);

        print OUTFILE "\n\nTOP $summary_cap VISITED HOSTS\n\n";
        foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                print OUTFILE "$key\t$top_hosts{$key}\t" . percent_of($top_hosts{$key}, $total_line_cnt) . "%\n";
                $count++;
                last if ($count == $summary_cap);
        }

        $count = 0;
        print OUTFILE "\n\nTOP $summary_cap TOP TALKERS\n\n";
        foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                print OUTFILE "$key\t$top_talkers{$key}\t" . percent_of($top_talkers{$key}, $total_line_cnt) . "%\n";
                $count++;
                last if ($count == $summary_cap);
        }

        $count = 0;
        print OUTFILE "\n\nTOP $summary_cap RESPONSE CODES\n\n";
        foreach $key (sort { $response_codes{$b} <=> $response_codes{$a} } keys %response_codes) {
                print OUTFILE "$key\t$response_codes{$key}\t" . percent_of($response_codes{$key}, $srv_responses) . "%\n";
                $count++;
                last if ($count == $summary_cap);
        }

        if ($filetype) {
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
                From    => 'admin@corban.edu',
                To      => "$email_addr",
                Subject => 'HTTPry Log Summary - ' . localtime(),
                Type    => 'multipart/mixed'
        );

        $msg->attach(
                Type => 'TEXT',
                Data => 'HTTPry log summary for ' . localtime()
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
