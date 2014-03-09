#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

package content_analysis;

use warnings;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
# Counter variables
my $line_cnt = 0;
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 999999;
my $flow_max_len = 0;

# Data structures
my %flow = ();         # Metadata about active flows
my %flow_buffer = ();  # Individual flow data lines
my %scored_flow = ();
my @terms = ();

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
        my $file;

        _load_config($cfg_dir);
        _load_terms();

        # Remove any existing text files so they don't accumulate
        opendir DIR, $output_dir or die "Cannot open directory $output_dir: $!\n";
        foreach $file (grep /^$file_prefix[\d\.]+\.txt$/, readdir(DIR)) {
                unlink "$output_dir/$file";
        }
        closedir(DIR);

        return;
}

sub list {
        return qw(direction timestamp source-ip host request-uri);
}

sub main {
        my $self = shift;
        my $record = shift;
        my $curr_line;
        my $decoded_uri;

        return unless $record->{"direction"} eq '>';

        $decoded_uri = $record->{"request-uri"};
        $decoded_uri =~ s/%(?:25)+/%/g;
        $decoded_uri =~ s/%(?:0A|0D)/\./ig;
        $decoded_uri =~ s/%([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;

        $line_cnt++;
        $curr_line = "$record->{'timestamp'}\t$record->{'host'}\t$decoded_uri\t$record->{'source-ip'}\t$record->{'dest-ip'}\t>";

        # Begin a new flow if one doesn't exist
        if (!exists $flow{$record->{"source-ip"}}) {
                $flow_cnt++;

                $flow{$record->{"source-ip"}}->{"length"} = 0;
                $flow{$record->{"source-ip"}}->{"score"} = 0;
                $flow{$record->{"source-ip"}}->{"num_terms"} = 0;
                $flow{$record->{"source-ip"}}->{"streak"} = 0;
                $flow{$record->{"source-ip"}}->{"dirty"} = 0;
                $flow{$record->{"source-ip"}}->{"count"} = 0;
        }

        # Insert the current line into the buffer
        $flow{$record->{"source-ip"}}->{"length"}++;
        push @{ $flow_buffer{$record->{"source-ip"}} }, $curr_line;

        # If a term is found, flag the buffer as dirty
        if (_content_check("$record->{'host'}$decoded_uri", $record->{"source-ip"}) > 0) {
                $flow{$record->{"source-ip"}}->{"dirty"} = 1;
                $flow{$record->{"source-ip"}}->{"count"} = $window_size;
        } else {
                # Term not found, so if buffer is dirty decrement the window count
                if ($flow{$record->{"source-ip"}}->{"dirty"} == 1) {
                        $flow{$record->{"source-ip"}}->{"count"}--;
                }
        }

        # If buffer is clean and full, drop the oldest line
        if (($flow{$record->{"source-ip"}}->{"dirty"} == 0) &&
            ($flow{$record->{"source-ip"}}->{"length"} > $window_size)) {
                $flow{$record->{"source-ip"}}->{"length"}--;
                shift @{ $flow_buffer{$record->{"source-ip"}} };
        }

        # If buffer is dirty and the window count is 0, flush it
        if (($flow{$record->{"source-ip"}}->{"dirty"} == 1) &&
            ($flow{$record->{"source-ip"}}->{"count"} == 0)) {
                _flush_buffer($record->{"source-ip"});
        }

        return;
}

sub end {
        my $ip;

        foreach $ip (keys %flow) {
                _flush_buffer($ip);
        }

        _write_summary_file();

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

        if (!$terms_file) {
                die "No terms file provided\n";
        }

        $output_dir = "." if (!$output_dir);
        $output_dir =~ s/\/$//; # Remove trailing slash

        return;
}

# -----------------------------------------------------------------------------
# Read in query terms from input file
# -----------------------------------------------------------------------------
sub _load_terms {
        my $line;
        my $term;

        unless (open TERMS, "$terms_file") {
                die "Cannot open $terms_file: $!\n";
        }

        while ($line = <TERMS>) {
                chomp $line;

                $line =~ s/\#.*$//; # Remove comments
                $line =~ s/^\s+//;  # Remove leading whitespace
                $line =~ s/\s+$//;  # Remove trailing whitespace
                $line =~ s/\s+/ /;  # Remove sequential whitespace
                next if $line =~ /^$/;

                foreach $term (split /\s/, $line) {
                        push(@terms, lc $term) if $term;
                }
        }

        close TERMS or die "Cannot close $terms_file: $!\n";

        return;
}

# -----------------------------------------------------------------------------
# Search for specified terms in each URI, scoring terms according to rules
# based on their position and context
# -----------------------------------------------------------------------------
sub _content_check {
        my $uri = lc shift;
        my $ip = shift;
        my $term;

        my $path_offset = index($uri, '/');
        my $query_offset = index($uri, '?', $path_offset);
        my $term_offset;
        my $num_terms = 0;
        my $score = 0;
        my $pos;

        foreach $term (@terms) {
                $pos = 0;
                while (($term_offset = index($uri, $term, $pos)) > -1) {
                        $num_terms++;
                        $flow{$ip}->{"terms"}->{$term}++;

                        # Term found, so apply scoring rules
                        # Rule 1: Apply a base score of 1
                        $score += 1;

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
                        if ((substr($uri, $term_offset-1, 1) !~ /[a-z]/) &&
                            (substr($uri, $term_offset+length($term), 1) !~ /[a-z]/)) {
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
                if ($flow{$ip}->{"streak"} > 3) {
                        $score += $flow{$ip}->{"streak"};
                }

                $flow{$ip}->{"streak"} = 0;
        } else {
                $flow{$ip}->{"streak"}++;
        }

        $flow{$ip}->{"score"} += $score;
        $flow{$ip}->{"num_terms"} += $num_terms;

        return $num_terms;
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: update statistics, save flow scoring data as
# necessary and delete the associated data structures
# -----------------------------------------------------------------------------
sub _flush_buffer {
        my $ip = shift;

        # Update flow statistics
        $flow_min_len = $flow{$ip}->{"length"} if ($flow{$ip}->{"length"} < $flow_min_len);
        $flow_max_len = $flow{$ip}->{"length"} if ($flow{$ip}->{"length"} > $flow_max_len);
        $flow_line_cnt += $flow{$ip}->{"length"};

        # We're only interested if the score meets the thresholds
        if (($flow{$ip}->{"score"} >= $score_threshold) &&
            ($flow{$ip}->{"num_terms"} >= $terms_threshold)) {
                $scored_flow{$ip}->{"num_flows"}++;
                $scored_flow{$ip}->{"score"} += $flow{$ip}->{"score"};
                $scored_flow{$ip}->{"num_terms"} += $flow{$ip}->{"num_terms"};
                foreach (keys %{ $flow{$ip}->{"terms"} }) {
                        $scored_flow{$ip}->{"terms"}->{$_} += $flow{$ip}->{"terms"}->{$_};
                }

                _write_file($ip);
        }

        delete $flow{$ip};
        delete $flow_buffer{$ip};

        return;
}

# -----------------------------------------------------------------------------
# Append flow data to a detail file based on client IP
# -----------------------------------------------------------------------------
sub _write_file {
        my $ip = shift;
        my $term;
        my $line;

        unless (open OUTFILE, ">>$output_dir/$file_prefix$ip.txt") {
                warn "Cannot open $output_dir/$file_prefix$ip.txt: $!\n";
                return;
        }

        print OUTFILE '#' x 80 . "\n";
        print OUTFILE "# Fields: timestamp,host,request-uri,source-ip,dest-ip,direction\n";
        print OUTFILE "# Length: $flow{$ip}->{'length'} lines (window size: $window_size)\n";
        print OUTFILE "# Score: $flow{$ip}->{'score'}\n";

        print OUTFILE "# Terms: ";
        foreach $term (keys %{ $flow{$ip}->{"terms"} }) {
                print OUTFILE "$term (" . $flow{$ip}->{"terms"}->{$term} . ") ";
        }
        print OUTFILE "\n";

        foreach $line (@{ $flow_buffer{$ip} }) {
                print OUTFILE $line, "\n";
        }
        print OUTFILE "\n";

        close OUTFILE or die "Cannot close $output_file: $!\n";

        return;
}

# -----------------------------------------------------------------------------
# Format and write summary information to specified output file
# -----------------------------------------------------------------------------
sub _write_summary_file {
        my $ip;
        my $term;
        my $scored_flow_cnt = 0;

        open OUTFILE, ">$output_file" or die "Cannot open $output_file: $!\n";

        print OUTFILE "\n\nCONTENT ANALYSIS SUMMARY\n\n";
        print OUTFILE "Generated:    " . localtime() . "\n";
        print OUTFILE "Total lines:  $line_cnt\n";
        print OUTFILE "Flow lines:   $flow_line_cnt\n";
        print OUTFILE "Flow count:   $flow_cnt\n";
        print OUTFILE "Flow length:  " . ($flow_cnt > 0 ? "$flow_min_len/$flow_max_len" : "0/0") . " (min/max)\n\n";

        if (scalar keys %scored_flow == 0) {
                print OUTFILE "*** No scored flows found\n";
                close OUTFILE or die "Cannot close $output_file: $!\n";

                return;
        }

        if ($cluster_flows) {
                _partition_scores();

                # Delete flows and associated files from the lower partition
                foreach $ip (keys %scored_flow) {
                        if ($scored_flow{$ip}->{"cluster"} == 0) {
                                delete $scored_flow{$ip};
                                unlink "$output_dir/$file_prefix$ip.txt";
                        }
                }
        }

        foreach (keys %scored_flow) {
                $scored_flows_cnt += $scored_flow{$_}->{"num_flows"};
        }

        print OUTFILE "Terms file:   $terms_file\n";
        print OUTFILE "Scored IPs:   " . (keys %scored_flow) . "\n";
        print OUTFILE "Scored flows: $scored_flows_cnt\n\n";

        print OUTFILE "Score\tIP\t\tFlows\tTerms\tTerm List\n";
        print OUTFILE "-----\t--\t\t-----\t-----\t---------\n";
        foreach $ip (sort { $scored_flow{$b}->{"score"} <=> $scored_flow{$a}->{"score"} } keys %scored_flow) {
                print OUTFILE "$scored_flow{$ip}->{'score'}\t$ip\t$scored_flow{$ip}->{'num_flows'}\t$scored_flow{$ip}->{'num_terms'}\t";
                print OUTFILE join(" ", sort keys %{ $scored_flow{$ip}->{"terms"} }) . "\n";
        }

        close OUTFILE or die "Cannot close $output_file: $!\n";

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
sub _partition_scores() {
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
                $mean += $scored_flow{$_}->{"score"};
        }
        $mean = $mean / (scalar keys %scored_flow);

        foreach (keys %scored_flow) {
                $std_dev += $scored_flow{$_}->{"score"} * $scored_flow{$_}->{"score"};
        }
        $std_dev = sqrt($std_dev / (scalar keys %scored_flow));

        # Build hash of scores to partition, pruning set outliers that are more than
        # $OUTLIER_THRESHOLD standard deviations from the mean
        foreach (keys %scored_flow) {
                if ($scored_flow{$_}->{"score"} > ($mean + ($std_dev * $OUTLIER_THRESHOLD))) {
                        $scored_flow{$_}->{"cluster"} = 1;
                } elsif ($scored_flow{$_}->{"score"} < ($mean - ($std_dev * $OUTLIER_THRESHOLD))) {
                        $scored_flow{$_}->{"cluster"} = 0;
                } else {
                        $temp_flow{$_}->{"score"} = $scored_flow{$_}->{"score"};
                        $max_score = $temp_flow{$_}->{"score"} if ($temp_flow{$_}->{"score"} > $max_score);
                }
        }

        # Use two centers, starting one at each end of the scores range
        @center = (0.0, $max_score);

        do {
                $diff = 0;

                # Assign points to nearest center
                foreach $ip (keys %temp_flow) {
                        $closest = 0;
                        $dist = abs $temp_flow{$ip}->{"score"} - $center[$closest];

                        foreach (1..$#center) {
                                if (abs $temp_flow{$ip}->{"score"} - $center[$_] < $dist) {
                                        $dist = abs $temp_flow{$ip}->{"score"} - $center[$_];
                                        $closest = $_;
                                }
                        }

                        $temp_flow{$ip}->{"cluster"} = $closest;
                }

                # Compute new centers based on mean
                foreach $centroid (0..$#center) {
                        @members = sort map { $temp_flow{$_}->{"score"} }
                                   grep { $temp_flow{$_}->{"cluster"} == $centroid } keys %temp_flow;

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
                $scored_flow{$_}->{"cluster"} = $temp_flow{$_}->{"cluster"};
        }

        return;
}

1;
