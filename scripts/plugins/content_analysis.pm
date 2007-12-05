#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>
#

# This is an example plugin for the perl parse script parse_log.pl.  It shows
# the basic structure of a simple plugin and provides a good starting point for
# writing a custom plugin. Some of the other included plugins will also provide
# a good idea of how the different pieces work.

package content_analysis;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $HOST_WEIGHT = 0.0;
my $PATH_WEIGHT = 0.50;
my $QUERY_WEIGHT = 0.75;

my $SCORE_THRESHOLD = 3.00;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %client_scores = ();
my %terms = ();
my %client_terms = ();

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
        my $self   = shift;
        my $record = shift;
        my $uri;
        my $term;

        return unless exists $record->{"host"};
        return unless exists $record->{"request-uri"};

        # URI regexp as given in RFC2396
        #
        # ^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
        #  12            3  4          5       6  7        8 9
        #
        # scheme    = $2
        # authority = $4
        # path      = $5
        # query     = $7
        # fragment  = $9

        $uri = "$record->{'host'}$record->{'request-uri'}";
#        print "$uri -> ";


#        $uri =~ /^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/;
        $uri =~ /^([^\/?#]*)?([^?#]*)(\?([^#]*))?(#(.*))?/;

#        my $scheme = $2;
        my $host = $1;
        my $path = $2;
        my $query = $4;
#        my $frag = $6;

        foreach $term (keys %terms) {
                if ($host && index($host, $term) >= 0) {
                        $client_scores{$record->{"source-ip"}} += $terms{$term} * $HOST_WEIGHT;
                        $client_terms{$record->{"source-ip"}}->{$term}++;
                }

                if ($path && index($path, $term) >= 0) {
                        $client_scores{$record->{"source-ip"}} += $terms{$term} * $PATH_WEIGHT;
                        $client_terms{$record->{"source-ip"}}->{$term}++;
                }

                if ($query && index($query, $term) >= 0) {
                        $client_scores{$record->{"source-ip"}} += $terms{$term} * $QUERY_WEIGHT;
                        $client_terms{$record->{"source-ip"}}->{$term}++;
                }
        }

        return;
}

sub end {
        my $client;

        foreach $client (keys %client_scores) {
                if ($client_scores{$client} < $SCORE_THRESHOLD) {
                        delete $client_scores{$client};
                }
        }

        &write_summary_file();

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub load_config {
        my $plugin_dir = shift;
        my $term;
        my $weight;

        # Load config file; by default in same directory as plugin
        if (-e "$plugin_dir/" . __PACKAGE__ . ".cfg") {
                require "$plugin_dir/" . __PACKAGE__ . ".cfg";
        }

        # Check for required options and combinations
        if (!$terms_file) {
                print "Error: No terms file provided\n";
                return 0;
        }

        if (!$output_file) {
                print "Error: No output file provided\n";
                return 0;
        }

        # Read in query terms and associated weights
        open(TERMS, "$terms_file") or die "Error: Cannot open $terms_file: $!\n";
                foreach (<TERMS>) {
                        chomp;
                        next if /^#/; # Skip comments

                        ($term, $weight) = split / /, $_;
                        $terms{$term} = $weight;
                }
        close(TERMS);

        return 1;
}

# -----------------------------------------------------------------------------
# Write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $client;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nCONTENT ANALYSIS SUMMARY\n\n";
        print OUTFILE "Generated:      " . localtime() . "\n";
        print OUTFILE "Num Clients:    " . (keys %client_scores) . "\n";
        print OUTFILE "\n\n";

        if (keys %client_scores == 0) {
                print OUTFILE "*** No scored clients found\n";
                close(OUTFILE);
                
                return;
        }

        print OUTFILE "CLIENT SCORES\n\n";
        foreach $client (sort { $client_scores{$b} <=> $client_scores{$a} } keys %client_scores) {
                print OUTFILE "$client\t" . sprintf("%.2f", $client_scores{$client}) . "\n";
                print OUTFILE "\tTerms: ";
                foreach $term (sort keys %{$client_terms{$client}}) {
                        print OUTFILE "$term*$client_terms{$client}->{$term} ";
                }
                print OUTFILE "\n\n";
        }

        close(OUTFILE);

        return;
}

1;
