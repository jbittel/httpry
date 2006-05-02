#!/usr/bin/perl -w

#
# search_terms.pm 4/4/2006
#
# Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

package search_terms;

use CGI qw(standard);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PROG_NAME = "search_terms.pm";
my $PLUG_VER = "0.0.1";
my $PATTERN = "\t";

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %search_terms = ();

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
}

sub end {
        &write_output_file();
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

        return 1;
}

# -----------------------------------------------------------------------------
# Handle each line of data
# -----------------------------------------------------------------------------
sub process_data {
        my $curr_line = shift;
        my $term;
        my $query;
        
        # Strip non-printable chars
        $curr_line =~ tr/\x80-\xFF//d;

        # Convert hex characters to ASCII
        $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        ($timestamp, $src_ip, $dst_ip, $hostname, $uri) = split(/$PATTERN/, $curr_line);
        return if (!$hostname or !$uri); # Malformed line

        # These results can end up being a little messy, but it seems
        # most useful to simply dump out all search terms and let the user
        # parse through what they find interesting. It's hard to strike a
        # balance that cleans up the results and applies to all users.

        # Parse Google services
        if ($hostname =~ /google\.com$/) {
                $query = new CGI($uri);

                if ($term = $query->param('q')) {
                        # Clean up search term
                        $term =~ s/"//g;
                        $term =~ s/\+/ /g;

                        # Discard hits we know aren't useful
                        return unless $term;
                        return if ($term =~ /^tbn:/);
                        return if ($term =~ /^info:/);
                        return if ($term =~ /^http:/);
                        
                        $search_terms{$hostname}->{$term}++;
                }

                return;
        }

        # Parse YouTube searches
        if ($hostname =~ /youtube\.com$/) {
                $query = new CGI($uri);

                if ($term = $query->param('search')) {
                        $search_terms{$hostname}->{$term}++;
                } elsif ($term = $query->param('tag')) {
                        $search_terms{$hostname}->{$term}++;
                } elsif ($term = $query->param('related')) {
                        $search_terms{$hostname}->{$term}++;
                }

                return;
        }

        # Parse Yahoo services
        if ($hostname =~ /yahoo\.com$/) {
                $query = new CGI($uri);

                if ($term = $query->param('p')) {
                        $search_terms{$hostname}->{$term}++;
                }

                return;
        }

        # Parse MSN services
        if ($hostname =~ /msn\.com$/) {
                $query = new CGI($uri);

                if ($term = $query->param('q')) {
                        # Clean up search term
                        $term =~ s/"//g;
                        $term =~ s/\+/ /g;

                        $search_terms{$hostname}->{$term}++;
                }

                return;
        }
                
        return;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $hostname;
        my $term;
        my $count = 0;

        open(OUTFILE, ">$output_file") || die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nSUMMARY STATS\n\n";
        print OUTFILE "Generated:\t" . localtime() . "\n";
        print OUTFILE "\n\n";

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
