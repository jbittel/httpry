#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.edu>
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
        my $search_term;
        my $domain;
        my $name;
        
        # Make sure we really want to be here
        return unless (exists $record->{"direction"} && ($record->{"direction"} eq '>'));
        return unless exists $record->{"request-uri"};
        return unless exists $record->{"host"};

        # These results can end up being a little messy, but it seems
        # most useful to simply dump out all search terms and let the user
        # parse through what they find interesting. It's hard to strike a
        # balance that cleans up the results and applies to all users. If
        # you can do it better, knock yourself out (oh, and send me the code).
        foreach $domain (keys %domains) {
                $name   = quotemeta($domains{$domain});
                $domain = quotemeta($domain);

                if ($record->{"host"} =~ /$domain$/) {
                        # Here we use the encoded URI to ensure that '&' chars in the search term
                        # don't break the regexp; we'll clean them out if we have a valid search term
                        return unless $record->{"request-uri"} =~ /[\?\&]$name=([^\&]+?)(?:\&|\Z)/;
                        $search_term = $1;
                        last;
                }
        }
        return unless $search_term;

        # Clean up search term
        $search_term =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $search_term =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
        $search_term =~ s/\+/ /g;

        # Custom cleanup rules; would be nice to generalize this better, but
        # this will work for now
        return if ($search_term =~ /^tbn:/);  # Let's ignore messy Google hits, shall we?
        return if ($search_term =~ /^info:/); # ...
        return if ($search_term =~ /^http:/); # ...
        return if ($search_term =~ /^music\/image/);   # Unnecessary Froogle hits

        $search_terms{$record->{"host"}}->{$search_term}++;

        # Count the number of terms in the query, treating quoted strings as a single term
        $num_terms += ($search_term =~ s/\".*?\"//g);
        $search_term =~ s/^\s+//;
        $search_term =~ s/\s+$//;
        $num_terms += ($search_term =~ s/\s+//g);
        $num_terms++ if ($search_term);
        $num_queries++;

        return;
}

sub end {
        &write_output_file();

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

        return 1;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $hostname;
        my $term;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nSEARCH TERMS SUMMARY\n\n";
        print OUTFILE "Generated: " . localtime() . "\n";

        if ((keys %search_terms) == 0) {
                print OUTFILE "\n\n*** No search terms found\n";
                close(OUTFILE);

                return;
        }

        print OUTFILE "Num of queries: $num_queries\n";
        print OUTFILE "Avg terms per query: " . sprintf("%.1f", ($num_terms / $num_queries)) . "\n\n\n";
        
        foreach $hostname (sort keys %search_terms) {
                print OUTFILE "$hostname\n";
                foreach $term (sort keys %{$search_terms{$hostname}}) {
                        print OUTFILE "\t($search_terms{$hostname}->{$term})\t$term\n";
                }
                print OUTFILE "\n";
        }

        close(OUTFILE);

        return;
}

1;
