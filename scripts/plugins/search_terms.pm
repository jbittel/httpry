#!/usr/bin/perl -w

#
# search_terms.pm | created: 4/4/2006
#
# Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the author nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

package search_terms;

use CGI qw(standard);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
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
# Handle each line of data
# -----------------------------------------------------------------------------
sub process_data {
        my $curr_line = shift;
        my ($timestamp, $src_ip, $dst_ip, $direction, $method, $hostname, $uri);
        my $term;
        my $query;

        # Strip non-printable chars
        $curr_line =~ tr/\x80-\xFF//d;

        # Convert hex characters to ASCII
        $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        ($timestamp, $src_ip, $dst_ip, $direction, $method, $hostname, $uri) = split(/$PATTERN/, $curr_line);
        return if $direction ne '>';
        return if (!$hostname or !$uri); # Malformed line

        # These results can end up being a little messy, but it seems
        # most useful to simply dump out all search terms and let the user
        # parse through what they find interesting. It's hard to strike a
        # balance that cleans up the results and applies to all users.

        # I'd like to find a more generic solution, but for now we need custom
        # cleanup code for some of these hostnames.

        # TODO: Parse Google services
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

        # Parse Ask.com searches
        if ($hostname =~ /ask\.com$/) {
                $query = new CGI($uri);

                if ($term = $query->param('q')) {
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

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nSEARCH TERMS\n\n";
        print OUTFILE "Generated: " . localtime() . "\n\n\n";

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
