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
                print OUTFILE "<?xml-stylesheet href=\"httpry.css\" type=\"text/css\"?>\n";
                print OUTFILE "<flow version=\"$flow_version\" xmlversion=\"$xml_version\">\n";
        }

        $fh = *OUTFILE;

        return 1;
}

sub main {
        my $self   = shift;
        my $record = shift; # Reference to hash containing record data
        my $direction;
        my $request_uri;

        # Replace XML entity characters
        if (exists $record->{"direction"}) {
                $direction = "&lt;" if ($record->{"direction"} eq '<');
                $direction = "&gt;" if ($record->{"direction"} eq '>');
        }
        if (exists $record->{"request-uri"}) {
                $request_uri = $record->{"request-uri"};
        
                $request_uri =~ s/&/\&amp\;/g;
                $request_uri =~ s/</\&lt\;/g;
                $request_uri =~ s/>/\&gt\;/g;
                $request_uri =~ s/\'/\&apos\;/g;
                $request_uri =~ s/\"/\&quot\;/g;
        }
        
        print $fh "<timestamp>$record->{'timestamp'}</timestamp>" if exists $record->{"timestamp"};
        print $fh "<source-ip>$record->{'source-ip'}</source-ip>" if (exists $record->{"source-ip"});
        print $fh "<dest-ip>$record->{'dest-ip'}</dest-ip>" if (exists $record->{"dest-ip"});
        print $fh "<direction>$direction</direction>" if (exists $record->{"direction"});
        print $fh "<method>$record->{'method'}</method>" if (exists $record->{"method"});
        print $fh "<host>$record->{'host'}</host>" if (exists $record->{"host"});
        print $fh "<request-uri>$request_uri</request-uri>" if (exists $record->{"request-uri"});
        print $fh "<http-version>$record->{'http-version'}</http-version>" if (exists $record->{"http-version"});
        print $fh "<status-code>$record->{'status-code'}</status-code>" if (exists $record->{"status-code"});
        print $fh "<reason-phrase>$record->{'reason-phrase'}</reason-phrase>" if (exists $record->{"reason-phrase"});
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
