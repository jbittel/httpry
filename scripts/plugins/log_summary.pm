#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>
#

package log_summary;

use warnings;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $SUMMARY_CAP = 10;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %top_hosts = ();
my %top_talkers = ();
my %filetypes = ();
my %response_codes = ();
my $total_line_cnt = 0;
my $ext_cnt = 0;
my $srv_responses = 0;
my $start_time;
my $end_time;

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

&main::register_plugin();

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $cfg_dir = shift;

        if (&load_config($cfg_dir)) {
                return 1;
        }

        $start_time = (times)[0];
        
        return 0;
}

sub main {
        my $self = shift;
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

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub load_config {
        my $cfg_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$cfg_dir/" . __PACKAGE__ . ".cfg") {
                require "$cfg_dir/" . __PACKAGE__ . ".cfg";
        } else {
                warn "Error: No config file found\n";
                return 1;
        }

        # Check for required options and combinations
        if (!$output_file) {
                warn "Error: No output file provided\n";
                return 1;
        }
        $summary_cap = $SUMMARY_CAP unless ($summary_cap > 0);

        return 0;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $key;
        my $count = 0;

        my $num_top_hosts = keys %top_hosts;
        my $num_top_talkers = keys %top_talkers;
        my $num_response_codes = keys %response_codes;
        my $num_filetypes = keys %filetypes;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nLOG SUMMARY\n\n";
        print OUTFILE "Generated:      " . localtime() . "\n";
        print OUTFILE "Total lines:    " . $total_line_cnt . "\n";
        print OUTFILE "Total run time: " . sprintf("%.1f", $end_time - $start_time) . " secs\n";

        if ($num_top_hosts) {
                print OUTFILE "\n\n$summary_cap/$num_top_hosts VISITED HOSTS\n\n";
                foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                        print OUTFILE "$top_hosts{$key}\t" . &percent_of($top_hosts{$key}, $total_line_cnt) . "%\t$key\n";
                        last if (++$count == $summary_cap);
                }
        }

        if ($num_top_talkers) {
                $count = 0;
                print OUTFILE "\n\n$summary_cap/$num_top_talkers TOP TALKERS\n\n";
                foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                        print OUTFILE "$top_talkers{$key}\t" . &percent_of($top_talkers{$key}, $total_line_cnt) . "%\t$key\n";
                        last if (++$count == $summary_cap);
                }
        }

        if ($num_response_codes) {
                $count = 0;
                print OUTFILE "\n\n$summary_cap/$num_response_codes RESPONSE CODES\n\n";
                foreach $key (sort { $response_codes{$b} <=> $response_codes{$a} } keys %response_codes) {
                        print OUTFILE "$response_codes{$key}\t" . &percent_of($response_codes{$key}, $srv_responses) . "%\t$key\n";
                        last if (++$count == $summary_cap);
                }
        }

        if ($num_filetypes) {
                $count = 0;
                print OUTFILE "\n\n$summary_cap/$num_filetypes FILE EXTENSIONS\n\n";
                foreach $key (sort { $filetypes{$b} <=> $filetypes{$a} } keys %filetypes) {
                        print OUTFILE "$filetypes{$key}\t" . &percent_of($filetypes{$key}, $ext_cnt) . "%\t$key\n";
                        last if (++$count == $summary_cap);
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
