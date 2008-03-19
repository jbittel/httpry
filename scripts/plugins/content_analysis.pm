#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>
#

package content_analysis;

use warnings;
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $FLOW_TIMEOUT = 300; # In seconds

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
# Counter variables
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 999999;
my $flow_max_len = 0;
my $max_concurrent = 0;

# Data structures
my %active_flow = ();       # Metadata about each active flow
my %active_flow_data = ();  # Individual flow data lines
my %scored_flow = ();
my %terms = ();             # Terms and corresponding weights

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

        if (&load_terms()) {
                return 1;
        }

        # Remove any existing text files so they don't accumulate
        opendir(DIR, $output_dir) or die "Error: Cannot open directory $output_dir: $!\n";
                foreach (grep /^scored_[\d\.]+\.txt$/, readdir(DIR)) {
                        unlink;
                }
        closedir(DIR);

        return 0;
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

        if ((keys %active_flow) > $max_concurrent) {
                $max_concurrent = keys %active_flow;
        }

        # Only call timeout_flows() if we've crossed a time boundary; i.e., 
        # if there's actually a chance for a flow to end
        if (&get_epoch_boundary() <= $epochstamp) {
                &set_epoch_boundary(&timeout_flows($epochstamp));
        }

        # Begin a new flow if one doesn't exist
        if (!exists $active_flow{$record->{"source-ip"}}) {
                $flow_cnt++;

                $active_flow{$record->{"source-ip"}}->{"length"} = 0;
                $active_flow{$record->{"source-ip"}}->{"score"} = 0;
                $active_flow{$record->{"source-ip"}}->{"streak"} = 0;
        }

        $active_flow{$record->{"source-ip"}}->{"end_epoch"} = $epochstamp;
        $active_flow{$record->{"source-ip"}}->{"length"}++;

        push(@{ $active_flow_data{$record->{"source-ip"}} }, $curr_line);

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

        if (!$terms_file) {
                warn "Error: No terms file provided\n";
                return 1;
        }

        $output_dir = "." if (!$output_dir);
        $output_dir =~ s/\/$//; # Remove trailing slash

        return 0;
}

# -----------------------------------------------------------------------------
# Read in query terms and weights from input file
# -----------------------------------------------------------------------------
sub load_terms {
        my $line;
        my $line_num;
        my $term;
        my $weight;

        unless (open(TERMS, "$terms_file")) {
                warn "Error: Cannot open $terms_file: $!\n";
                return 1;
        }

        while ($line = <TERMS>) {
                $line_num++;
                chomp $line;

                $line =~ s/\#.*$//; # Remove comments
                $line =~ s/^\s+//;  # Remove leading whitespace
                $line =~ s/\s+$//;  # Remove trailing whitespace
                $line =~ s/\s+/ /;  # Remove sequential whitespace
                next if $line =~ /^$/;

                ($term, $weight) = split /[ \t]/, $line;
                $term = lc $term;

                # Basic validation and error checking
                if (!$term || !$weight) {
                        warn "Warning: Invalid data found in $terms_file, line $line_num\n";
                        next;
                }

                if ($weight !~ /\d+/) {
                        warn "Warning: '$term' assigned non-numeric weight '$weight', ignoring\n";
                        next;
                }

                if ($weight < 0) {
                        warn "Warning: '$term' assigned out of range weight '$weight', clamping to 0\n";
                        $weight = 0;
                }

                if ($weight > 1) {
                        warn "Warning: '$term' assigned out of range weight '$weight', clamping to 1\n";
                        $weight = 1;
                }

                $terms{$term} = $weight;
        }

        close(TERMS);

        return 0;
}

# -----------------------------------------------------------------------------
# Search for specified terms in each URI, scoring terms according to rules
# based on their position and context
# -----------------------------------------------------------------------------
sub content_check {
        my $uri = lc shift;
        my $ip = shift;
        my $term;

        my $path_offset = index($uri, '/');
        my $query_offset = index($uri, '?', $path_offset);
        my $term_offset;
        my $num_terms = 0;
        my $score = 0;
        my $pos;

        foreach $term (keys %terms) {
                $pos = 0;
                while (($term_offset = index($uri, $term, $pos)) > -1) {
                        $num_terms++;
                        $active_flow{$ip}->{'terms'}->{$term}++;

                        # Term found, so apply scoring rules
                        # Rule 1: Apply a base score of 1 + term weight
                        $score += 1 + $terms{$term};

                        # Rule 2: If found in query, add 2
                        #         If found in path, add 1
                        #         If found in hostname, add 0
                        if (($query_offset > 0) && ($term_offset > $query_offset)) {
                                $score += 2;
                        } elsif (($path_offset > 0) && ($term_offset > $path_offset)) {
                                $score += 1;
                        } else {
                                $score += 0;
                        }

                        # Rule 3: If stand-alone word (bracketed by non-alpha chars), add 1
                        if ((substr($uri, $term_offset-1, 1) !~ /[A-Za-z]/) &&
                            (substr($uri, $term_offset+length($term), 1) !~ /[A-Za-z]/)) {
                                $score += 1;
                        }

                        $pos = $term_offset + length($term);
                }
        }

        # Rule 4: If more than one term found, add 1
        $score += 1 if ($num_terms > 1);

        # Rule 5: If a streak (more than 3 successive lines containing
        #         terms) is found, add the length of the streak
        if ($num_terms == 0) {
                if ($active_flow{$ip}->{'streak'} > 3) {
                        $score += $active_flow{$ip}->{'streak'};
                }

                $active_flow{$ip}->{'streak'} = 0;
        } else {
                $active_flow{$ip}->{'streak'}++;
        }

        $active_flow{$ip}->{'score'} += $score;

        return;
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: flush to disk and delete hash entries; passing an
# epochstamp value causes all flows inactive longer than $FLOW_TIMEOUT to be
# flushed, while passing a zero forces all active flows to be flushed
#
# Returns the next potential epoch value at which flows could time out
# -----------------------------------------------------------------------------
sub timeout_flows {
        my $epochstamp = shift;
        my $flow_str;
        my $epoch_diff;
        my $max_epoch_diff = 0;
        my $ip;

        foreach $ip (keys %active_flow) {
                if ($epochstamp) {
                        $epoch_diff = $epochstamp - $active_flow{$ip}->{"end_epoch"};
                        if ($epoch_diff <= $FLOW_TIMEOUT) {
                                $max_epoch_diff = $epoch_diff if ($epoch_diff > $max_epoch_diff);

                                next;
                        }
                }

                # Update flow statistics
                $flow_min_len = $active_flow{$ip}->{"length"} if ($active_flow{$ip}->{"length"} < $flow_min_len);
                $flow_max_len = $active_flow{$ip}->{"length"} if ($active_flow{$ip}->{"length"} > $flow_max_len);
                $flow_line_cnt += $active_flow{$ip}->{"length"};

                # Save score information only if a score has been applied
                if ($active_flow{$ip}->{'score'} > 0) {
                        $scored_flow{$ip}->{'num_flows'}++;
                        $scored_flow{$ip}->{'score'} += $active_flow{$ip}->{'score'};
                        foreach (keys %{ $active_flow{$ip}->{"terms"} }) {
                                $scored_flow{$ip}->{"terms"}->{$_} += $active_flow{$ip}->{"terms"}->{$_};
                        }

                        &append_scored_file($ip);
                }

                delete $active_flow{$ip};
                delete $active_flow_data{$ip};
        }

        return $epochstamp + ($FLOW_TIMEOUT - $max_epoch_diff);
}

# -----------------------------------------------------------------------------
# Append flow data to a detail file based on client IP
# -----------------------------------------------------------------------------
sub append_scored_file {
        my $ip = shift;
        my $line;

        open(HOSTFILE, ">>$output_dir/scored_$ip.txt") or die "Error: Cannot open $output_dir/scored_$ip.txt: $!\n";

        print HOSTFILE '>' x 80 . "\n";
        foreach $line (@{ $active_flow_data{$ip} }) {
                print HOSTFILE $line, "\n";
        }
        print HOSTFILE '<' x 80 . "\n";

        close(HOSTFILE);

        return;
}

# -----------------------------------------------------------------------------
# Format and write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $ip;
        my $term;
        my $term_cnt;
        my $scored_flow_cnt = 0;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nCLIENT FLOWS SUMMARY\n\n";
        print OUTFILE "Generated:      " . localtime() . "\n";
        print OUTFILE "Flow count:     $flow_cnt\n";
        print OUTFILE "Flow lines:     $flow_line_cnt\n";
        print OUTFILE "Max concurrent: $max_concurrent\n";
        print OUTFILE "Min/max/avg:    ";
        if ($flow_cnt > 0) {
                print OUTFILE "$flow_min_len/$flow_max_len/" . sprintf("%d", $flow_line_cnt / $flow_cnt) . "\n";
        } else {
                print OUTFILE "0/0/0\n";
        }

        if (scalar keys %scored_flow == 0) {
                print OUTFILE "\n\n*** No scored flows found\n";
                close(OUTFILE);

                return;
        }

        &partition_scores();

        # Delete flows and associated files from the lower partition
        foreach $ip (keys %scored_flow) {
                if ($scored_flow{$ip}->{"cluster"} == 0) {
                        delete $scored_flow{$ip};
                        unlink "$output_dir/scored_$ip.txt";
                }
        }

        foreach (keys %scored_flow) {
                $scored_flows_cnt += $scored_flow{$_}->{"num_flows"};
        }

        print OUTFILE "\nTerms file:     $terms_file\n";
        print OUTFILE "Scored IPs:     " . (keys %scored_flow) . "\n";
        print OUTFILE "Scored flows:   $scored_flows_cnt\n\n";

        foreach $ip (sort { $scored_flow{$b}->{"score"} <=> $scored_flow{$a}->{"score"} } keys %scored_flow) {
                $term_cnt = 0;

                foreach (keys %{ $scored_flow{$ip}->{"terms"} }) {
                        $term_cnt += $scored_flow{$ip}->{"terms"}->{$_};
                }

                print OUTFILE sprintf("%.1f", $scored_flow{$ip}->{"score"}) . "\t$ip\t$scored_flow{$ip}->{'num_flows'}\t$term_cnt\t";
                foreach $term (sort keys %{ $scored_flow{$ip}->{"terms"} } ) {
                        print OUTFILE "$term ";
                }
                print OUTFILE "\n";
        }

        close(OUTFILE);

        return;
}

# -----------------------------------------------------------------------------
# Dynamically partition scored flows into sets using the k-means clustering
# algorithm; this allows us to trim the low scoring flows off the bottom
# without setting arbitrary thresholds or levels 
#
# K-means code originally taken from: http://www.perlmonks.org/?node_id=541000
# Many subsequent modifications and changes have been made
# -----------------------------------------------------------------------------
sub partition_scores() {
        my $OUTLIER_THRESHOLD = 3;
        my $MAX_ITERS = 30;

        my $mean = 0;
        my $std_dev = 0;
        my %temp_flow = ();

        my $ip;
        my $diff;
        my $closest;
        my $dist;
        my $max_score = 0;
        my $new_center;
        my $num_iters = 0;
        my $sum;
        my $centroid;
        my @center;
        my @members;

        # Calculate mean and standard deviation
        foreach (keys %scored_flow) {
                $mean += $scored_flow{$_}->{'score'};
        }
        $mean = $mean / (scalar keys %scored_flow);

        foreach (keys %scored_flow) {
                $std_dev += $scored_flow{$_}->{'score'} * $scored_flow{$_}->{'score'};
        }
        $std_dev = sqrt($std_dev / (scalar keys %scored_flow));

        # Build hash of scores to partition, pruning set outliers that are more than
        # $OUTLIER_THRESHOLD standard deviations from the mean
        foreach (keys %scored_flow) {
                if ($scored_flow{$_}->{'score'} > ($mean + ($std_dev * $OUTLIER_THRESHOLD))) {
                        $scored_flow{$_}->{'cluster'} = 1;
                } elsif ($scored_flow{$_}->{'score'} < ($mean - ($std_dev * $OUTLIER_THRESHOLD))) {
                        $scored_flow{$_}->{'cluster'} = 0;
                } else {
                        $temp_flow{$_}->{'score'} = $scored_flow{$_}->{'score'};
                        $max_score = $temp_flow{$_}->{'score'} if ($temp_flow{$_}->{'score'} > $max_score);
                }
        }

        # Use two centers, starting one at each end of the scores range
        @center = (0.0, $max_score);

        do {
                $diff = 0;

                # Assign points to nearest center
                foreach $ip (keys %temp_flow) {
                        $closest = 0;
                        $dist = abs $temp_flow{$ip}->{'score'} - $center[$closest];
 
                        foreach (1..$#center) {
                                if (abs $temp_flow{$ip}->{'score'} - $center[$_] < $dist) {
                                        $dist = abs $temp_flow{$ip}->{'score'} - $center[$_];
                                        $closest = $_;
                                }
                        }

                        $temp_flow{$ip}->{'cluster'} = $closest;
                }

                # Compute new centers based on mean
                foreach $centroid (0..$#center) {
                        @members = sort map { $temp_flow{$_}->{'score'} }
                                   grep { $temp_flow{$_}->{'cluster'} == $centroid } keys %temp_flow;

                        $sum = 0;
                        foreach (@members) {
                                $sum += $_;
                        }
                        $new_center = @members ? $sum / @members : $center[$centroid];

                        $diff += abs $center[$centroid] - $new_center;
                        $center[$centroid] = $new_center;
                }

                $num_iters++;
        } while (($diff > 0.01) && ($num_iters <= $MAX_ITERS));

        # Update cluster membership in scored flows
        foreach (keys %temp_flow) {
                $scored_flow{$_}->{'cluster'} = $temp_flow{$_}->{'cluster'};
        }

        return;
}

1;
