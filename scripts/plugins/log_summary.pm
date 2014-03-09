#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
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
my %requests_hour = ();
my $total_line_cnt = 0;
my $ext_cnt = 0;
my $requests = 0;
my $responses = 0;
my $start_time;
my $end_time;

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

main::register_plugin();

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $cfg_dir = shift;

        _load_config($cfg_dir);

        $start_time = (times)[0];

        return;
}

sub list {
        return qw(direction);
}

sub main {
        my $self = shift;
        my $record = shift;

        $total_line_cnt++;

        if ($record->{"direction"} eq '>') {
                $requests++;

                $top_hosts{$record->{"host"}}++ if exists $record->{"host"};
                $top_talkers{$record->{"source-ip"}}++ if exists $record->{"source-ip"};

                if (exists $record->{"request-uri"}) {
                        if (($record->{"request-uri"} =~ /\.(\w{2,5})$/) or
                            ($record->{"request-uri"} =~ /\.(\w{2,5})\?/)) {
                                $filetypes{lc($1)}++;
                                $ext_cnt++;
                        }
                }

                if (exists $record->{"timestamp"}) {
                        $record->{"timestamp"} =~ /(\d\d):\d\d:\d\d$/;
                        $requests_hour{int $1}++;
                }
        } elsif ($record->{"direction"} eq '<') {
                $responses++;

                $response_codes{$record->{"status-code"}}++ if exists $record->{"status-code"};
        }

        return;
}

sub end {
        $end_time = (times)[0];

        _write_output_file();

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub _load_config {
        my $cfg_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$cfg_dir/" . __PACKAGE__ . ".cfg") {
                require "$cfg_dir/" . __PACKAGE__ . ".cfg";
        } else {
                die "No config file found\n";
        }

        # Check for required options and combinations
        if (!$output_file) {
                die "No output file provided\n";
        }
        $summary_cap = $SUMMARY_CAP unless ($summary_cap > 0);

        return;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub _write_output_file {
        my $key;
        my $count = 0;
        my $hour;

        my $num_top_hosts = keys %top_hosts;
        my $num_top_talkers = keys %top_talkers;
        my $num_response_codes = keys %response_codes;
        my $num_filetypes = keys %filetypes;

        open OUTFILE, ">$output_file" or die "Cannot open $output_file: $!\n";

        print OUTFILE "\n\nLOG SUMMARY\n\n";
        print OUTFILE "Generated:      " . localtime() . "\n";
        print OUTFILE "Total lines:    " . $total_line_cnt . "\n";
        print OUTFILE "Total run time: " . sprintf("%.1f", $end_time - $start_time) . " secs\n";

        if (keys %requests_hour) {
                print OUTFILE "\n\nREQUESTS BY HOUR\n";

                print OUTFILE _get_request_hours(0, 11);
                print OUTFILE _get_request_hours(12, 23);
        }

        if ($num_top_hosts) {
                print OUTFILE "\n\n$summary_cap/$num_top_hosts VISITED HOSTS\n\n";
                foreach $key (sort { $top_hosts{$b} <=> $top_hosts{$a} } keys %top_hosts) {
                        print OUTFILE "$top_hosts{$key}\t" . _percent_of($top_hosts{$key}, $requests) . "%\t$key\n";
                        last if (++$count == $summary_cap);
                }
        }

        if ($num_top_talkers) {
                $count = 0;
                print OUTFILE "\n\n$summary_cap/$num_top_talkers TOP TALKERS\n\n";
                foreach $key (sort { $top_talkers{$b} <=> $top_talkers{$a} } keys %top_talkers) {
                        print OUTFILE "$top_talkers{$key}\t" . _percent_of($top_talkers{$key}, $requests) . "%\t$key\n";
                        last if (++$count == $summary_cap);
                }
        }

        if ($num_response_codes) {
                $count = 0;
                print OUTFILE "\n\n$summary_cap/$num_response_codes RESPONSE CODES\n\n";
                foreach $key (sort { $response_codes{$b} <=> $response_codes{$a} } keys %response_codes) {
                        print OUTFILE "$response_codes{$key}\t" . _percent_of($response_codes{$key}, $responses) . "%\t$key\n";
                        last if (++$count == $summary_cap);
                }
        }

        if ($num_filetypes) {
                $count = 0;
                print OUTFILE "\n\n$summary_cap/$num_filetypes FILE EXTENSIONS\n\n";
                foreach $key (sort { $filetypes{$b} <=> $filetypes{$a} } keys %filetypes) {
                        print OUTFILE "$filetypes{$key}\t" . _percent_of($filetypes{$key}, $ext_cnt) . "%\t$key\n";
                        last if (++$count == $summary_cap);
                }
        }

        close OUTFILE or die "Cannot close $output_file: $!\n";

        return;
}

# -----------------------------------------------------------------------------
# Build a string with request percentages per hour
# -----------------------------------------------------------------------------
sub _get_request_hours {
        my $begin = shift;
        my $end = shift;
        my $str;

        $str = "\n";
        for ($begin..$end) {
                if (exists $requests_hour{$_}) {
                        $str .= sprintf("%3d%% ", _percent_of($requests_hour{$_}, $requests));
                } else {
                        $str .= "  0% ";
                }
        }
        $str .= "\n  ";

        for ($begin..$end - 1) {
                $str .= "|----";
        }
        $str .= "|\n";

        for ($begin..$end) {
                $str .= sprintf(" %02d  ", $_);
        }
        $str .= "\n";

        return $str;
}

# -----------------------------------------------------------------------------
# Calculate ratio information
# -----------------------------------------------------------------------------
sub _percent_of {
        my $subset = shift;
        my $total = shift;

        return sprintf "%.1f", ($subset / $total) * 100;
}

1;
