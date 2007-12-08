#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>
#

package client_flows;

use warnings;
use Socket qw(inet_ntoa inet_aton);
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $FLOW_TIMEOUT = 300;
#my $TAGGED_LIMIT = 15;

my $HOST_WEIGHT = 0.0;
my $PATH_WEIGHT = 0.50;
my $QUERY_WEIGHT = 0.75;

my $SCORE_THRESHOLD = 10.00;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
# Counter variables
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 999999;
my $flow_max_len = 0;
my $tagged_flows_cnt = 0;
#my $total_tagged_lines_cnt = 0;
my $max_concurrent = 0;

# Data structures
my %active_flows = ();       # Holds data about each active flow
#my %flow_data_lines = (); # Holds actual log file lines for each flow
#my %tagged_terms = ();
my %tagged_flows = ();    # Pruned and cleaned tagged flows for output
#my %history = ();         # Holds cache of content checks to avoid matching
my %terms = ();           # Dictionary of terms and corresponding weights

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
        my $term;
        my $weight;

        if (&load_config($plugin_dir) == 0) {
                return 0;
        }

        # Read in query terms to search for
        # TODO: add more error checking
        open(TERMS, "$terms_file") or die "Error: Cannot open $terms_file: $!\n";
                foreach (<TERMS>) {
                        chomp;
                        next if /^#/; # Skip comments

                        ($term, $weight) = split / /, $_;
                        $terms{$term} = $weight;
                }
        close(TERMS);

        # Remove any existing text files so they don't accumulate
        opendir(DIR, $output_dir) or die "Error: Cannot open directory $output_dir: $!\n";
                foreach (grep /^tagged_.+\.txt$/, readdir(DIR)) {
                        unlink;
                }
        closedir(DIR);

        return 1;
}

sub main {
        my $self = shift;
        my $record = shift;
        my $curr_line;
        my $decoded_uri;

        # Retain this variable across function calls
        BEGIN {
                my $epoch_boundary = 0;

                sub get_epoch_boundary { return $epoch_boundary; }
                sub set_epoch_boundary { $epoch_boundary = shift; }
        }

        # Make sure we really want to be here
        return unless (exists $record->{"direction"} && ($record->{"direction"} eq '>'));
        return unless exists $record->{"timestamp"};
        return unless exists $record->{"source-ip"};
        return unless exists $record->{"host"};
        return unless exists $record->{"request-uri"};

        $decoded_uri = $record->{"request-uri"};
        $decoded_uri =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $decoded_uri =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        $curr_line = "$record->{'timestamp'}\t$record->{'dest-ip'}\t$record->{'host'}\t$decoded_uri";

        # Convert timestamp of current record to epoch seconds
        $record->{"timestamp"} =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
        $epochstamp = timelocal($6, $5, $4, $2, $1 - 1, $3);

        if ((keys %active_flows) > $max_concurrent) {
                $max_concurrent = keys %active_flows;
        }

        # Only call timeout_flows() if we've crossed a time boundary; i.e., 
        # if there's actually a chance for a flow to end
        if (&get_epoch_boundary() <= $epochstamp) {
                &set_epoch_boundary(&timeout_flows($epochstamp));
        }

        # Begin a new flow if one doesn't exist
        if (!exists $active_flows{$record->{"source-ip"}}) {
                $flow_cnt++;

                $active_flows{$record->{"source-ip"}}->{"start_time"} = $record->{"timestamp"};
                $active_flows{$record->{"source-ip"}}->{"length"} = 0;
                $active_flows{$record->{"source-ip"}}->{"score"} = 0;
        }

        $active_flows{$record->{"source-ip"}}->{"end_time"} = $record->{"timestamp"};
        $active_flows{$record->{"source-ip"}}->{"end_epoch"} = $epochstamp;
        $active_flows{$record->{"source-ip"}}->{"length"}++;

        push(@{ $active_flows{$record->{"source-ip"}}->{"data"} }, $curr_line);

        &content_check("$record->{'host'}$record->{'request-uri'}", $record->{"source-ip"});

        return;
}

sub end {
        &timeout_flows(0);
        &write_summary_file();

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

        if (!$terms_file) {
                print "Error: No terms file provided\n";
                return 0;
        }

        $output_dir = "." if (!$output_dir);
        $output_dir =~ s/\/$//; # Remove trailing slash

        return 1;
}

# -----------------------------------------------------------------------------
# Search for specified content in the hostname and URI and return true if
# match occurs; store results of search in a (rudimentary) cache so we don't
# have to match the same text twice
#
# Potential hash values: -1 unmatched / 1 matched / 0 no match
# -----------------------------------------------------------------------------
sub content_check {
#        my $hostname = shift;
#        my $uri = shift;
#        my $ip = shift;
#        my $term;
        my $uri = shift;
        my $ip = shift;
        my $term;

        $uri =~ /^([^\/?#]*)?([^?#]*)(\?([^#]*))?(#(.*))?/;

        my $host = $1;
        my $path = $2;
        my $query = $4;

        # TODO: $host may not always be set here
        foreach $term (keys %terms) {
                if ($host && index($host, $term) >= 0) {
                        $active_flows{$ip}->{"score"} += $terms{$term} * $HOST_WEIGHT;
                        $active_flows{$ip}->{"terms"}->{$term}++;
                        $active_flows{$ip}->{"hosts"}->{$host}++;
                }

                if ($path && index($path, $term) >= 0) {
                        $active_flows{$ip}->{"score"} += $terms{$term} * $PATH_WEIGHT;
                        $active_flows{$ip}->{"terms"}->{$term}++;
                        $active_flows{$ip}->{"hosts"}->{$host}++;
                }

                if ($query && index($query, $term) >= 0) {
                        $active_flows{$ip}->{"score"} += $terms{$term} * $QUERY_WEIGHT;
                        $active_flows{$ip}->{"terms"}->{$term}++;
                        $active_flows{$ip}->{"hosts"}->{$host}++;
                }
        }

#        $history{$hostname} = -1 if (!defined $history{$hostname});
#        $history{$uri} = -1 if (!defined $history{$uri});
#
#        return 1 if (($history{$hostname} == 1) || ($history{$uri} == 1));
#        return 0 if (($history{$hostname} == 0) && ($history{$uri} == 0));
#
#        foreach $term (@terms) {
#                if (index($hostname, $term) >= 0) {
#                        $history{$hostname} = 1;
#                        $tagged_terms{$ip}->{$term}++;
#                        return 1;
#                }
#
#                if (index($uri, $term) >= 0) {
#                        $history{$uri} = 1;
#                        $tagged_terms{$ip}->{$term}++;
#                        return 1;
#                }
#        }
#
#        $history{$hostname} = 0;
#        $history{$uri} = 0;

        return;
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: flush to disk and delete hash entries; passing an
# epochstamp value causes all flows inactive longer than $FLOW_TIMEOUT to be
# flushed, while passing a zero forces all active flows to be flushed.
#
# Return the next potential epoch boundary at which flows could time out.
# -----------------------------------------------------------------------------
sub timeout_flows {
        my $epochstamp = shift;
        my $flow_str;
        my $epoch_diff;
        my $max_epoch_diff = 0;
        my $ip;

        foreach $ip (keys %active_flows) {
                if ($epochstamp) {
                        $epoch_diff = $epochstamp - $active_flows{$ip}->{"end_epoch"};
                        if ($epoch_diff <= $FLOW_TIMEOUT) {
                                $max_epoch_diff = $epoch_diff if ($epoch_diff > $max_epoch_diff);

                                next;
                        }
                }

                # Update minimum/maximum flow length as necessary
                $flow_min_len = $active_flows{$ip}->{"length"} if ($active_flows{$ip}->{"length"} < $flow_min_len);
                $flow_max_len = $active_flows{$ip}->{"length"} if ($active_flows{$ip}->{"length"} > $flow_max_len);

                $flow_line_cnt += $active_flows{$ip}->{"length"};

                # Check if we have enough hits to be interested in the flow
                if ($active_flows{$ip}->{"score"} > $SCORE_THRESHOLD) {
                        $tagged_flows_cnt++;
#                        $total_tagged_lines_cnt += $active_flows{$ip}->{"tagged_lines"};

                        # Copy data to output hash so we can prune and reformat
                        $flow_str = "[$active_flows{$ip}->{'start_time'}]->[$active_flows{$ip}->{'end_time'}]";
#                        $flow_str .= " (" . sprintf("%.2f", $active_flows{$ip}->{"score"}) . ")";
                        $tagged_flows{$ip}->{"flows"}->{$flow_str} = $active_flows{$ip}->{"hosts"};
                        $tagged_flows{$ip}->{"score"} = $active_flows{$ip}->{"score"};
                        $tagged_flows{$ip}->{"terms"} = $active_flows{$ip}->{"terms"};

                        &append_tagged_file($ip);
                }

                delete $active_flows{$ip};
        }

        return $epochstamp + ($FLOW_TIMEOUT - $max_epoch_diff);
}

# -----------------------------------------------------------------------------
# Append flow data to a detail file based on client IP
# -----------------------------------------------------------------------------
sub append_tagged_file {
        my $ip = shift;
        my $line;

        open(HOSTFILE, ">>$output_dir/tagged_$ip.txt") or die "Error: Cannot open $output_dir/tagged_$ip.txt: $!\n";

        print HOSTFILE '>' x 80 . "\n";
        foreach $line (@{ $active_flows{$ip}->{"data"} }) {
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
        my $term;
        my $hostname;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nCLIENT FLOWS SUMMARY\n\n";
        print OUTFILE "Generated:      " . localtime() . "\n";
        print OUTFILE "Flow count:     $flow_cnt\n";
        print OUTFILE "Flow lines:     $flow_line_cnt\n";
        print OUTFILE "Max Concurrent: $max_concurrent\n";
        print OUTFILE "Min/Max/Avg:    ";
        if ($flow_cnt > 0) {
                print OUTFILE "$flow_min_len/$flow_max_len/" . sprintf("%d", $flow_line_cnt / $flow_cnt) . "\n";
        } else {
                print OUTFILE "0/0/0\n";
        }

        print OUTFILE "Tagged IPs:     " . (keys %tagged_flows) . "\n";
        print OUTFILE "Tagged flows:   $tagged_flows_cnt\n";
#        print OUTFILE "Tagged lines:   $total_tagged_lines_cnt\n";
        print OUTFILE "\n\nCLIENT SCORES\n";
        print OUTFILE "FILTER FILE: $terms_file\n\n";

        if ($tagged_flows_cnt == 0) {
                print OUTFILE "*** No tagged flows found\n";
                close(OUTFILE);
                
                return;
        }

        foreach $ip (map { inet_ntoa $_ }
                     sort
                     map { inet_aton $_ } keys %tagged_flows) {
#        foreach $ip (sort { $client_scores{$b} <=> $tagged_flows{$a} } keys %tagged_flows) {
                print OUTFILE "$ip\n";

                foreach $flow (sort keys %{ $tagged_flows{$ip}->{"flows"} }) {
                        print OUTFILE "\t$flow\t$tagged_flows{$ip}->{'score'}\n\t\t";

                        foreach $term (sort keys %{ $tagged_flows{$ip}->{"terms"} }) {
                                print OUTFILE "$term ($tagged_flows{$ip}->{'terms'}->{$term}) ";
                        }
                        print OUTFILE "\n\n";

                        foreach $hostname (sort keys %{ $tagged_flows{$ip}->{"flows"}->{$flow} }) {
                                print OUTFILE "\t\t($tagged_flows{$ip}->{'flows'}->{$flow}->{$hostname})\t$hostname\n";
                        }

                        print OUTFILE "\n";
                }
        }

        close(OUTFILE);

        return;
}

1;
