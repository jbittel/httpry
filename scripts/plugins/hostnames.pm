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

package hostnames;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %hostnames = ();

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
        my $record = shift; # Reference to hash containing record data
        my $hostname;

        # Make sure we really want to be here
        return unless (exists $record->{"direction"} && ($record->{"direction"} eq '>'));
        return unless exists $record->{"host"};

        $hostname = $record->{"host"};
        $hostname =~ s/[^\-\.0-9A-Za-z]//g;
 
        # Eliminate invalid hostnames and online services
        return if ($hostname eq "");
        return if ($hostname eq "-");
        return if ($hostname =~ /^ads?\./);
        return if ($hostname =~ /^proxy/);
        return if ($hostname =~ /^redir/);
        return if ($hostname =~ /^liveupdate/);
        return if ($hostname =~ /^anti-phishing/);
        return if ($hostname =~ /^stats/);
        return if ($hostname =~ /^photos/);
        return if ($hostname =~ /^images/);
        return if ($hostname =~ /^myspace/);

        # Only allow hostnames of the forms: a.b, a.b.c, a.b.c.d
        return unless ($hostname =~ /^([\-\w]+?\.){1,3}[\-\w]+?$/);

        $hostnames{$record->{"host"}} = "" unless exists($hostnames{$record->{"host"}});

        return;
}

sub end {
        my $host;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";
        
        foreach $host (keys %hostnames) {
                print OUTFILE "$host\n";
        }

        close(OUTFILE);

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

1;
