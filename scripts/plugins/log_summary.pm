#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>
#

package log_summary;

use warnings;
use File::Basename;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
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
        print OUTFILE "Generated:        " . localtime() . "\n";
        print OUTFILE "Total lines:      " . $total_line_cnt . "\n";
        print OUTFILE "Client count:     " . keys(%top_talkers) . "\n";
        print OUTFILE "Server count:     " . keys(%top_hosts) . "\n";
        print OUTFILE "Unique filetypes: " . keys(%filetypes) . "\n" if ($filetype);
        print OUTFILE "Total run time:   " . sprintf("%.1f", $end_time - $start_time) . " secs\n";

        if ((keys %top_hosts) > 0) {
                print OUTFILE "\n\nTOP $summary_cap VISITED HOSTS\n\n";
                foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                        print OUTFILE "$top_hosts{$key}\t" . percent_of($top_hosts{$key}, $total_line_cnt) . "%\t$key\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ((keys %top_talkers) > 0) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap TOP TALKERS\n\n";
                foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                        print OUTFILE "$top_talkers{$key}\t" . percent_of($top_talkers{$key}, $total_line_cnt) . "%\t$key\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ((keys %response_codes) > 0) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap RESPONSE CODES\n\n";
                foreach $key (sort { $response_codes{$b} <=> $response_codes{$a} } keys %response_codes) {
                        print OUTFILE "$response_codes{$key}\t" . percent_of($response_codes{$key}, $srv_responses) . "%\t$key\n";
                        $count++;
                        last if ($count == $summary_cap);
                }
        }

        if ($filetype && ((keys %filetypes) > 0)) {
                $count = 0;
                print OUTFILE "\n\nTOP $summary_cap FILE EXTENSIONS\n\n";
                foreach $key (sort { $filetypes{$b} <=> $filetypes{$a} } keys %filetypes) {
                        print OUTFILE "$filetypes{$key}\t" . percent_of($filetypes{$key}, $ext_cnt) . "%\t$key\n";
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

1;
