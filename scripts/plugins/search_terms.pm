#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

package search_terms;

use warnings;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %search_terms = ();
my $num_terms = 0;
my $num_queries = 0;

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

        return;
}

sub list {
        return qw(direction host request-uri source-ip);
}

sub main {
        my $self = shift;
        my $record = shift;
        my $search_term;
        my $domain;
        my $name;
        my $pattern;

        return unless $record->{"direction"} eq '>';

        # These results can end up being a little messy, but it seems
        # most useful to simply dump out all search terms and let the user
        # sift through what they deem interesting
        foreach $domain (keys %domains) {
                if (rindex($record->{"host"}, $domain) > -1) {
                        $name = $domains{$domain};
                        return unless $record->{"request-uri"} =~ /[\?\&]$name=([^\&]+)/;
                        $search_term = $1;
                        last;
                }
        }
        return unless $search_term;

        # Decode hex characters in the search term
        $search_term =~ s/%(?:25)+/%/g;
        $search_term =~ s/%(?:0A|0D)/\./ig;
        $search_term =~ s/%([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;

        # Clean up spaces in search term
        $search_term =~ s/\+/ /g;
        $search_term =~ s/^\s+//;
        $search_term =~ s/\s+$//;
        $search_term =~ s/\s+/ /g;

        # Apply rules to ignore unwanted hits
        foreach $domain (keys %ignore) {
                if (rindex($record->{"host"}, $domain) > -1) {
                        foreach $pattern (@{ $ignore{$domain} }) {
                                return if $search_term =~ /$pattern/;
                        }
                }
        }

        $search_terms{$record->{"source-ip"}}->{$record->{"host"}}->{$search_term}++;

        # Count the number of terms in the query, treating quoted strings as a single term
        $num_terms += ($search_term =~ s/\".*?\"//g);
        $search_term =~ s/^\s+//; # Strip leading/trailing spaces potentially introduced above
        $search_term =~ s/\s+$//; # ...
        $num_terms += ($search_term =~ s/\s+//g);
        $num_terms++ if ($search_term);
        $num_queries++;

        return;
}

sub end {
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
                die "Error: No config file found\n";
        }

        # Check for required options and combinations
        if (!$output_file) {
                die "No output file provided\n";
        }

        return;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub _write_output_file {
        my $ip;
        my $hostname;
        my $term;

        open OUTFILE, ">$output_file" or die "Cannot open $output_file: $!\n";

        print OUTFILE "\n\nSEARCH TERMS SUMMARY\n\n";
        print OUTFILE "Generated:       " . localtime() . "\n";

        if ((keys %search_terms) == 0) {
                print OUTFILE "\n\n*** No search terms found\n";
                close OUTFILE or die "Cannot close $output_file: $!\n";

                return;
        }

        print OUTFILE "Terms:           $num_terms\n";
        print OUTFILE "Queries:         $num_queries\n";
        print OUTFILE "Avg terms/query: " . sprintf("%.1f", ($num_terms / $num_queries)) . "\n\n\n";

        foreach $ip (sort keys %search_terms) {
                print OUTFILE "$ip\n";
                foreach $hostname (keys %{ $search_terms{$ip} }) {
                        print OUTFILE "\t$hostname\n";
                        foreach $term (sort keys %{ $search_terms{$ip}->{$hostname} }) {
                                print OUTFILE "\t\t$search_terms{$ip}->{$hostname}->{$term}\t$term\n";
                        }
                        print OUTFILE "\n";
                }
        }

        close OUTFILE or die "Cannot close $output_file: $!\n";

        return;
}

1;
