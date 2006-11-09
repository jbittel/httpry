#!/usr/bin/perl -w

#
# find_proxies.pm | created: 4/3/2006
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

package find_proxies;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PRUNE_LIMIT = 20;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %proxy_lines = ();

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

        &process_data($record);

        return;
}

sub end {
        &prune_hits();
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
        $prune_limit = $PRUNE_LIMIT unless ($prune_limit > 0);

        return 1;
}

# -----------------------------------------------------------------------------
# Handle each line of data
# -----------------------------------------------------------------------------
sub process_data {
        my $record = shift;
        my $word;
        my $len;
        my $encoded_uri;
        my $decoded_uri = "";
        my $domain;

        return if $record->{"direction"} ne '>';

        # Perform hostname and uri keyword search
        foreach $word (@proxy_keywords) {
                if ($record->{"host"} =~ /$word/i) {
                        $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                        return;
                }

                if ($record->{"request-uri"} =~ /$word/i) {
                        $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                        return;
                }
        }

        # Perform URI embedded request search; this works, but appears
        # to generate too many false positives to be useful as is
        if ($record->{"request-uri"} =~ /(\.pl|\.php|\.asp).*http:\/\/[^\/:]+/) {
                $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                return;
        }

        # Third time's the charm; do a base 64 decode of the URI and
        # search again for an embedded request
        if ($record->{"request-uri"} =~ /(\.pl|\.php|\.asp).*=(.+?)(?:\&|\Z)/) {
                $encoded_uri = $2;
                
                $encoded_uri =~ tr|A-Za-z0-9+=/||cd;
                return if (length($encoded_uri) % 4);

                $encoded_uri =~ s/=+$//;
                $encoded_uri =~ tr|A-Za-z0-9+/| -_|;

                while ($encoded_uri =~ /(.{1,60})/gs) {
                	$len = chr(32 + length($1)*3/4);
                 	$decoded_uri .= unpack("u", $len . $1);
                }

                if ($decoded_uri =~ /http:\/\/[^\/:]+/) {
                        $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                        return;
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Remove hits from results tree that are below our level of interest
# -----------------------------------------------------------------------------
sub prune_hits {
        my $ip;
        my $hostname;

        foreach $ip (keys %proxy_lines) {
                # Delete individual hostnames/counts that are below the limit
                foreach $hostname (keys %{$proxy_lines{$ip}}) {
                        if ($proxy_lines{$ip}->{$hostname} < $prune_limit) {
                                delete $proxy_lines{$ip}->{$hostname};
                        }
                }

                # If all hostnames were deleted, remove the empty IP
                unless (keys %{$proxy_lines{$ip}}) {
                        delete $proxy_lines{$ip};
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub write_output_file {
        my $ip;
        my $hostname;
        my $domain;
        my %counts;
        my %output;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nPOTENTIAL PROXIES\n\n";
        print OUTFILE "Generated: " . localtime() . "\n\n\n";

        # Reformat data hash into a formatted output hash
        if ((keys %proxy_lines) > 0) {
                foreach $ip (keys %proxy_lines) {
                        foreach $hostname (keys %{$proxy_lines{$ip}}) {
                                # Attempt to cluster data by domain
                                if (($hostname =~ /\.([^\.]+?\.[^\.]+?)$/) && !($hostname =~ /\d+\.\d+\.\d+\.\d+/)) {
                                        $domain = $1;
                                } else {
                                        $domain = $hostname;
                                }
 
                                push(@{$output{$domain}->{$hostname}}, $ip);
                                $counts{$hostname} += $proxy_lines{$ip}->{$hostname};
                        }
                }

                # Print output hash data to file
                foreach $domain (sort keys %output) {
                        foreach $hostname (sort keys %{$output{$domain}}) {
                                print OUTFILE "($counts{$hostname}) $hostname\n\t[ ";

                                foreach $ip (@{$output{$domain}->{$hostname}}) {
                                        print OUTFILE "$ip ";
                                }
                                print OUTFILE "]\n";
                        }
                        print OUTFILE "\n\n";
                }
        } else {
                print OUTFILE "*** No potential proxies found\n";
        }

        close(OUTFILE);

        return;
}

1;
