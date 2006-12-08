#!/usr/bin/perl -w

#
# xml_output.pm | created: 12/3/2006
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

package xml_output;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my $fh;

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

        if (-e $output_file) {
                open(OUTFILE, ">>$output_file") or die "Error: Cannot open $output_file: $!\n";
                print OUTFILE "<flow version=\"$flow_version\" xmlversion=\"$xml_version\">\n";
        } else {
                open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";
                print OUTFILE "<?xml version=\"1.0\"?>\n";
                print OUTFILE "<?xml-stylesheet href=\"xml_output.css\" type=\"text/css\"?>\n";
                print OUTFILE "<flow version=\"$flow_version\" xmlversion=\"$xml_version\">\n";
        }

        $fh = *OUTFILE;

        return 1;
}

sub main {
        my $self   = shift;
        my $record = shift;
        my $direction;
        my $request_uri;

        foreach my $field (keys %$record) {
                my $data = $record->{$field};

                $data =~ s/&/\&amp\;/g;
                $data =~ s/</\&lt\;/g;
                $data =~ s/>/\&gt\;/g;
                $data =~ s/\'/\&apos\;/g;
                $data =~ s/\"/\&quot\;/g;
                
                print $fh "<$field>$data</$field>";
        }
        print $fh "\n";

        return;
}

sub end {

        print $fh "</flow>\n";
        close($fh);

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
