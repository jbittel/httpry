#!/usr/bin/perl -w

#
# Copyright (c) 2005-2007, Jason Bittel <jason.bittel@gmail.com>. All rights reserved.
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
                        # don't break the regexp; we'll clean them out if we have a valid search
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
        return if ($search_term =~ /^mail_candygram/); # Spammy Yahoo! mail hits

        $search_terms{$record->{"host"}}->{$search_term}++;

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
        print OUTFILE "Generated: " . localtime() . "\n\n\n";

        if ((keys %search_terms) == 0) {
                print OUTFILE "*** No search terms found\n";
                close(OUTFILE);

                return;
        }
        
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
